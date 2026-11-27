# ---------------------------------------------------------|
# Queue manager component for the spam-classifier. Read    |
# and writes the queue and calls the wrapper accordingly.  |
# ---------------------------------------------------------|

import json
import mysql.connector
import sys
import subprocess
import datetime
import os
import signal
import logging
import time
from classifier_config import load_or_create_config
from systemd import journal
from contextlib import closing

# ----------------------------------------------------------|
# Database functions.                                       |
# ----------------------------------------------------------|

# Executes a mutation query (INSERT, UPDATE, etc) to the MySQL database server. Requires to be parameterized for SQL injection protection.
def execute_mutation_sql_query(db, q, params):
	with closing(db.cursor()) as cursorObject:
		try:
			cursorObject.execute(q, params)
			db.commit()
			return cursorObject.lastrowid
		except Exception:
			db.rollback()
			raise

# Executes a SELECT query that returns results. Also a parameterized function to safeguard against SQL injection.
def execute_select_sql_query(db, q, params):
	with closing(db.cursor(buffered=True)) as cursorObject:
		cursorObject.execute(q, params)
		rows = cursorObject.fetchall()
		db.commit()
		return rows

# -----------------------------------------------------------

# Prints error message to STDERR.
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# Attempt connection to the MySQL database server.
def connect_mysql_database():
	try:
		database = mysql.connector.connect(host=classifier_config["database_addr"], user=classifier_config["database_user"],
			passwd=classifier_config["database_passwd"], database=classifier_config["database_name"], connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

# ----------------------------------------------------------|
# Signal handling and logging, as we run under systemd.     |
# ----------------------------------------------------------|

# Do initial tasks for starting the analyzer. We initialize a logger that targets systemd.
logger = logging.getLogger("spam-classifier")
journald_handler = journal.JournaldLogHandler()
journald_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
logger.setLevel(logging.INFO)
logger.addHandler(journald_handler)

# Handles SIGTERM and SIGKILL signals which are sent by systemd. While we are at it, let's do SIGINT as well.
class SignalHandler:
	break_loop = False
	def __init__(self):
		signal.signal(signal.SIGINT, self.exit_gracefully)
		signal.signal(signal.SIGTERM, self.exit_gracefully)

	# Sets loop break flag so the main loop can safely exit.
	def exit_gracefully(self, *args):
		logger.info("Received SIGTERM or SIGINT! Setting break flag to true.")
		self.break_loop = True

# ----------------------------------------------------------|
# Main classifier queue manager code                        |
# ----------------------------------------------------------|

# Load configuration from the classifier.
try:
	config_object = load_or_create_config()
	classifier_config = config_object["CLASSIFIER"]
except KeyError:
	logger.error("Could not open config file, one or more required key/value pairs are missing! Review the config file and try again.")
	exit(1)

# Open connection to the database to retrieve and update information.
database = connect_mysql_database()
if database is None:
	logger.error("Failed to connect to MySQL server at: %s!" % classifier_config["database_addr"])
	exit(1)

# -----------------------------------------------------------

# Get classifier timeout value from the configuration.
try:
	classifier_timeout_seconds = int(classifier_config["classifier_timeout_seconds"])
except ValueError:
	logger.error("Expected integer value for 'classifier_timeout_seconds' in the configuration!")
	exit(1)

# Get query block size from the configuration.
try:
	main_query_block_size = int(classifier_config["main_query_block_size"])
except ValueError:
	logger.error("Expected integer value for 'main_query_block_size' in the configuration!")
	exit(1)

# Enter the program loop, staying alive and checking for new entries in the classifier queue.
sigHandler = SignalHandler()
while not sigHandler.break_loop:
	# Query the spam_classifier_queue table to check for new entries. We pick the ones with the lowest ID to process first.
	# To avoid doing too many database queries, we select up to 5 new queue items in one query.
	queue_entries_result = execute_select_sql_query(database, "SELECT id,mail_id FROM spam_classifier_queue ORDER BY id LIMIT %s", (main_query_block_size,))
	for queue_entry in queue_entries_result:
		id = queue_entry[0]
		mail_id = queue_entry[1]

		# Execute the spam-classifier wrapper for the given mail ID and monitor whether the wrapper
		# does not execute longer than allowed. If it does, we will kill it and record an error.
		try:
			command = [ 'python3', '/opt/spam-classifier/wrapper.py', str(mail_id) ]
			p = subprocess.run(command, capture_output=True, text=True, timeout=classifier_timeout_seconds)
			classifier_result = p.stdout.strip()
			exit_code = p.returncode
		except KeyboardInterrupt:
			continue
		except subprocess.TimeoutExpired:
			logger.error("Classifier timed out when processing mail ID: %i!" % mail_id)
			continue

		# If the exit code was 1, an error occurred and we will log the errors put out by the wrapper.
		if exit_code != 0:
			# One or more errors occurred in the wrapper. Obtain them from STDERR and forward them to systemd for troubleshooting.
			logger.error("One or more errors occurred processing mail ID: %i, error messages below" % mail_id)
			classifier_errors = p.stderr
			for error in classifier_errors.split('\n'):
				logger.error(error)
		else:
			# Parse the result from the wrapper on STDOUT. This is a simple indicator string. If the result is unexpected, log an error.
			if classifier_result != "DETECTED" and classifier_result != "CLEAN":
				logger.error("Unknown classifier wrapper output: %s" % classifier_result)
			else:
				# Print informational log entry about the processing of this entry.
				logger.info("Processed entry: %i for mail ID: %i. Result: %s" % (id, mail_id, classifier_result))

		# The wrapper takes care of all database operations regarding the detection.
		# Just delete the row from the spam_classifier_queue table and move on to the next.
		execute_mutation_sql_query(database, "DELETE FROM spam_classifier_queue WHERE id = %s", (id,))

	# Sleep a little bit to avoid hogging the CPU. We run the classifier in blocks so 100ms will be enough of a break.
	time.sleep(1/10)
