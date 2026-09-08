# ---------------------------------------------------------|
# Queue manipulation component, allows one to add and      |
# remove mail IDs from the spam classifier queue. Also     |
# gives functionality to query the queue.                  |
# ---------------------------------------------------------|

import argparse
import mysql.connector
import sys
import datetime
from classifier_config import load_or_create_config

# ----------------------------------------------------------|
# Database functions.                                       |
# ----------------------------------------------------------|

# Executes a mutation query (INSERT, UPDATE, etc) to the MySQL database server.
def execute_mutation_sql_query(db, q, params):
	cursorObject = db.cursor()
	cursorObject.execute(q, params)
	db.commit()
	return cursorObject.lastrowid

# Executes a SELECT query that returns results.
def execute_select_sql_query(db, q):
	cursorObject = db.cursor(buffered=True)
	cursorObject.execute(q)
	db.commit()
	return cursorObject.fetchall()

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
# Main classifier queue controller code.                    |
# ----------------------------------------------------------|

# Parse command line arguments.
parser = argparse.ArgumentParser(description='Spam classifier queue controller')
operations_group = parser.add_mutually_exclusive_group(required=True)
operations_group.add_argument('-a', nargs='+', dest='add_mail_ids', type=int, help='Add one or more mail IDs to the queue')
operations_group.add_argument('-r', nargs='+', dest='remove_mail_ids', type=int, help='Remove one or more mail IDs from the queue')
operations_group.add_argument('-q', action='store_true', dest='query', help='Query statistics on the queue')
operations_group.add_argument('-l', action='store_true', dest='list', help='List all mail IDs currently scheduled')
operations_group.add_argument('-c', action='store_true', dest='clear', help='Purge all mail IDs currently scheduled (empty the queue)')
parser.add_argument('-v', action='store_true', dest='verbose', help='verbose mode, print additional information')
args = parser.parse_args()

# Check whether verbose mode was selected.
verbose = True if args.verbose else False

# Load configuration from the classifier.
try:
	config_object = load_or_create_config()
	classifier_config = config_object["CLASSIFIER"]
except KeyError:
	print("ERROR: Could not open config file, one or more required key/value pairs are missing! Review the config file and try again.")
	exit(1)

# Open connection to the database to retrieve and update information.
database = connect_mysql_database()
if database is None:
	print("ERROR: Failed to connect to MySQL server at: %s!" % classifier_config["database_addr"])
	exit(1)

# -----------------------------------------------------------

# Perform the chosen operation on the queue.
if args.add_mail_ids:
	# Obtain the mail IDs and check whether they are already in the queue or not.
	mail_ids = args.add_mail_ids
	for mail_id in mail_ids:
		queue_entries_result = execute_select_sql_query(database, "SELECT id FROM spam_classifier_queue WHERE mail_id = %i" % mail_id)
		if len(queue_entries_result) > 0:
			if verbose:
				print("INFO: Mail ID: %i already exists in the queue. Skipping." % mail_id)
			continue
		else:
			# Mail ID is not yet in the queue, so append it to the queue.
			query = "INSERT INTO spam_classifier_queue (mail_id,added) VALUES (%s,%s)"
			queue_timestamp = datetime.datetime.now()
			qt_string = queue_timestamp.strftime("%Y-%m-%d %H:%M:%S")
			execute_mutation_sql_query(database, query, (mail_id,qt_string))
			if verbose:
				print("INFO: Added mail ID: %i to the queue." % mail_id)
elif args.remove_mail_ids:
	mail_ids = args.remove_mail_ids
	for mail_id in mail_ids:
		queue_entries_result = execute_select_sql_query(database, "SELECT id FROM spam_classifier_queue WHERE mail_id = %i" % mail_id)
		if len(queue_entries_result) == 0:
			if verbose:
				print("INFO: Mail ID: %i does not exist in the queue. Skipping." % mail_id)
			continue
		else:
			# Mail ID exists in the queue, so remove it from the queue.
			execute_mutation_sql_query(database, "DELETE FROM spam_classifier_queue WHERE mail_id = %s", (mail_id,))
			if verbose:
				print("INFO: Removed all entries for mail ID: %i from the queue." % mail_id)
elif args.query:
	# Obtain the number of mail IDs currently in the queue.
	queue_entries_result = execute_select_sql_query(database, "SELECT COUNT(*) FROM spam_classifier_queue")
	count_row = queue_entries_result[0]
	print("INFO: %i mail IDs in the queue" % count_row[0])
elif args.list:
	# Retrieve a list of mail IDs currently in the queue.
	queue_entries_result = execute_select_sql_query(database, "SELECT id,mail_id,added FROM spam_classifier_queue")
	if len(queue_entries_result) == 0:
		print("INFO: Spam classifier queue is empty.")
	else:
		# Print a CSV-formatted list of mail IDs in the queue.
		print("id,mail_id,added")
		for queue_entry in queue_entries_result:
			print("%i,%i,%s" % (queue_entry[0], queue_entry[1], queue_entry[2]))
elif args.clear:
	# Clear the queue entirely: remove all mail IDs scheduled.
	execute_mutation_sql_query(database, "DELETE FROM spam_classifier_queue", ())
	if args.verbose:
		print("INFO: Cleared the classifier queue.")
else:
	print("ERROR: No operation specified!")
	exit(1)
