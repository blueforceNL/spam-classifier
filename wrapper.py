# ---------------------------------------------------------|
# Spam classifier component, to analyze mail and link a    |
# final detection result to it.                            |
# ---------------------------------------------------------|

import argparse
import json
import mysql.connector
import sys
import subprocess
import datetime
import os
import git
import re
import shutil
import ipaddress
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

# Obtains version number from the number of commits in the local Git repo.
def obtain_version_number():
	try:
		repo = git.Repo(".")
		version = int(repo.git.rev_list('--count', 'HEAD'))
	except git.exc.InvalidGitRepositoryError:
		version = 0
	return version

# Attempt connection to the MySQL database server.
def connect_mysql_database():
	try:
		database = mysql.connector.connect(host=classifier_config["database_addr"], user=classifier_config["database_user"],
			passwd=classifier_config["database_passwd"], database=classifier_config["database_name"], connect_timeout=10)
	except mysql.connector.Error:
		return None

	# Check and print connection info.
	return database if database.is_connected() else None

# Deletes a message file from disk including its attachments, and removes the body and attachments from the database.
def delete_message_from_disk(mail_id, message_file_path, num_attachments, attachments_dir):
	# Delete message file from disk. If the message file does not exist anymore, we just let it slip.
	try:
		os.remove(message_file_path)
	except FileNotFoundError:
		pass

	# If there are any attachments, delete them from disk as well.
	if num_attachments > 0:
		shutil.rmtree(attachments_dir, ignore_errors=True)

	# Before removing attachments, we want to make sure no other mail message in the database links to them. If so, we will just remove the links from the current mail message.
	# Othewise, we will remove the attachment as well. First obtain all attachment links and check the number of references.
	attachments_result = execute_select_sql_query(database, ("SELECT id,attachment_id FROM mail_attachment_link WHERE mail_id = %i" % mail_id))
	for attachment_link in attachments_result:
		# Remove the attachment link from the database.
		execute_mutation_sql_query(database, "DELETE FROM mail_attachment_link WHERE id = %s", (attachment_link[0],))

		# Check whether there are more references to the current attachment than just this mail ID.
		other_attachment_refs = execute_select_sql_query(database, ("SELECT id FROM mail_attachment_link WHERE attachment_id = %i" % (attachment_link[1],)))
		if len(other_attachment_refs) == 0:
			# No other references to this attachment. Delete it from the database.
			execute_mutation_sql_query(database, "DELETE FROM potentially_malicious_attachments WHERE id = %s", (attachment_link[1],))

	# Remove the mail body from the database.
	execute_mutation_sql_query(database, "DELETE FROM mail_message_bodies WHERE mail_id = %s", (mail_id,))

# ----------------------------------------------------------|
# Main classifier wrapper code                              |
# ----------------------------------------------------------|

# Parse command line arguments.
parser = argparse.ArgumentParser(description='Spam mail classifier')
parser.add_argument('mail_id', nargs='?')
parser.add_argument('-v', action='store_true', dest='verbose', help='enable verbose mode, printing JSON input and output objects')
args = parser.parse_args()

# If verbose mode is requested, let the caller know that we took note.
if args.verbose:
	print("Verbose mode enabled! Dry-run will be performed, nothing altered in the database.")

# Check whether the mail ID argument has been specified.
if args.mail_id is None:
	eprint("Mail ID was not specified! Exiting.")
	exit(1)

# Parse the mail ID argument and see whether it is a valid integer.
try:
	mail_id_arg = int(args.mail_id)
except ValueError:
	eprint("Invalid mail ID entered: %s" % args.mail_id)
	exit(1)

# Load configuration from the analyzer.
try:
	config_object = load_or_create_config()
	classifier_config = config_object["CLASSIFIER"]
except KeyError:
	eprint("Could not open config file, one or more required key/value pairs are missing! Review the config file and try again.")
	exit(1)

# Open connection to the database to retrieve and update information.
database = connect_mysql_database()
if database is None:
	eprint("Failed to connect to MySQL server at: %s!" % classifier_config["database_addr"])
	exit(1)

# Create JSON object as input for the classifier application.
json_obj = {}
json_obj["version"] = obtain_version_number()

# Select basic metadata from the analyzed_mail table given the mail ID.
mail_entry_result = execute_select_sql_query(database, ("SELECT * FROM analyzed_mail WHERE id = %i" % mail_id_arg))
if len(mail_entry_result) < 1:
	eprint("Mail ID was not found in analyzed_mail table!")
	exit(1)

# Extract all information from the query result and include it in the JSON object.
mail_entry = mail_entry_result[0]
mail_id = mail_entry[0]
potentially_malicious = True if mail_entry[4] == 1 else False
json_obj["mail"] = {}
json_obj["mail"]["id"] = mail_id
json_obj["mail"]["timestamp"] = mail_entry[1].strftime("%Y-%m-%d %H:%M:%S")
json_obj["mail"]["filename"] = mail_entry[2]
json_obj["mail"]["md5_hash"] = mail_entry[3].hex()
json_obj["mail"]["potentially_malicious"] = potentially_malicious
json_obj["mail"]["sender"] = mail_entry[5]
json_obj["mail"]["subject"] = mail_entry[6]
json_obj["mail"]["bounced_subject"] = mail_entry[7]
json_obj["mail"]["recipient"] = mail_entry[8]
json_obj["mail"]["size"] = mail_entry[10]
json_obj["mail"]["num_attachments"] = mail_entry[11]
json_obj["mail"]["body_length"] = mail_entry[12]
json_obj["mail"]["analysis_time"] = mail_entry[13]
json_obj["mail"]["total_scanned_urls"] = mail_entry[15]

# Get the sender IP address is stored.
sender_ip = mail_entry[16]
if sender_ip:
	sender_ip_str = str(ipaddress.ip_address(sender_ip))
else:
	sender_ip_str = ""
json_obj["mail"]["sender_ip"] = sender_ip_str

# Obtain the sender domain from the mail headers and store it as a separate field.
sender_domain_matches = re.findall(r"@[a-zA-Z0-9.-]+", mail_entry[5])
if len(sender_domain_matches) == 1:
	json_obj["mail"]["sender_domain"] = sender_domain_matches[0].replace("@", "")

# Obtain the recipient domain from the mail headers and store it as a separate field.
receiver_domain_matches = re.findall(r"@[a-zA-Z0-9.-]+", mail_entry[8])
if len(receiver_domain_matches) == 1:
	json_obj["mail"]["recipient_domain"] = receiver_domain_matches[0].replace("@", "")

# Add the timestamp from the mail headers if applicable.
if mail_entry[9] is not None:
	json_obj["mail"]["mail_timestamp"] = mail_entry[9].strftime("%Y-%m-%d %H:%M:%S")

# Construct path to find a mail message on disk if applicable.
mail_message_filename = mail_entry[2]
full_message_path = os.path.join(classifier_config["processing_finished_dir"], mail_message_filename)
if potentially_malicious:
	json_obj["mail"]["message_file_path"] = full_message_path

# Query the mail message body and include it in the JSON object.
mail_body_result = execute_select_sql_query(database, ("SELECT encoded_body FROM mail_message_bodies WHERE mail_id = %i" % mail_id))
if len(mail_body_result) < 1:
	eprint("Mail message body missing from database!")
else:
	mail_body_entry = mail_body_result[0]
	json_obj["mail"]["encoded_body"] = mail_body_entry[0]

# Query the domain associated to the incoming mail message.
domain_entry_result = execute_select_sql_query(database, ("SELECT domain,sinkholed,added,countries.name FROM domains JOIN countries ON domains.country_id = countries.id WHERE domains.id = %i" % mail_entry[14]))
if len(domain_entry_result) < 1:
	eprint("No domain was associated to this mail message!")
else:
	domain_entry = domain_entry_result[0]
	json_obj["domain"] = {}
	json_obj["domain"]["name"] = domain_entry[0]
	json_obj["domain"]["sinkholed"] = True if domain_entry[1] == 1 else False
	json_obj["domain"]["added"] = domain_entry[2].strftime("%Y-%m-%d %H:%M:%S")
	json_obj["domain"]["country"] = domain_entry[3]

# Select all extracted URLs associated to this mail message. If there are no, we omit the object.
extracted_urls_result = execute_select_sql_query(database, ("SELECT url FROM extracted_urls WHERE mail_id = %i" % mail_id))
if len(extracted_urls_result) > 0:
	extracted_urls = []
	for url in extracted_urls_result:
		extracted_urls.append(url[0])
	json_obj["extracted_urls"] = extracted_urls

# Select all extracted BTC addresses associated to this mail message. If there are no, we omit the object.
extracted_btc_result = execute_select_sql_query(database, ("SELECT btc FROM extracted_btc WHERE mail_id = %i" % mail_id))
if len(extracted_btc_result) > 0:
	extracted_btc = []
	for btc in extracted_btc_result:
		extracted_btc.append(btc[0])
	json_obj["extracted_btc"] = extracted_btc

# Select all attachments extracted from the database and add them to the JSON object. If there are not attachments, we omit the object.
attachments_result = execute_select_sql_query(database, ("SELECT sha256_hash,size,filename,filename_on_disk,mime_types.description FROM mail_attachment_link JOIN potentially_malicious_attachments ON potentially_malicious_attachments.id = attachment_id JOIN mime_types ON mime_type_id = mime_types.id WHERE mail_id = %i" % mail_id))
num_attachments = len(attachments_result)
attachments_dir = os.path.join(classifier_config["attachments_dir"], mail_message_filename)
if num_attachments > 0:
	attachments = []
	counter = 1
	for a in attachments_result:
		# Store metadata on the attachment from the database in a JSON object.
		json_attachment = {}
		json_attachment["sha256_hash"] = a[0].hex()
		json_attachment["size"] = a[1]
		json_attachment["filename"] = a[2]
		json_attachment["mime_type"] = a[4]

		# Construct and store the path to the binary file on disk.
		json_attachment["path"] = os.path.join(attachments_dir, a[3])
		attachments.append(json_attachment)

		# Increment counter for this attachment.
		counter += 1
	json_obj["attachments"] = attachments

# Convert dictionary with mail analysis information to JSON and output it.
json_text = json.dumps(json_obj, indent=4)

# If verbose mode was requested, print the JSON data.
if args.verbose:
	print("Input: %s" % json_text)

# Open a subprocess to the spam-classifier, providing the JSON object to STDIN.
command = [ './bin/spam-classifier' ]
p = subprocess.run(command, input=json_text, capture_output=True, text=True)
classifier_result = p.stdout.strip()

# Parse the classifier output as JSON and look at the detection(s).
classifier_json = json.loads(classifier_result)
classifier_version = classifier_json["version"]

# If verbose mode was requested, print the JSON output, and consider it a dry-run. We don't enter anything in the database.
if args.verbose:
	print("Output: %s" % json.dumps(classifier_json, indent=4))
	exit(0)

# ---------------------------------------------------------|
# From here on, the database will be altered.              |
# ---------------------------------------------------------|

# Now find out whether there is already a detection linked to this mail message.
# If so, we must remove it: new detection logic may or may not induce a new classification.
# Suppose there were too much false positives with a previous detection, then we will have loose ends if we don't remove the old crap.
detection_link_result = execute_select_sql_query(database, ("SELECT id FROM mail_classifications_link WHERE mail_id = %i" % mail_id))
for entry in detection_link_result:
	# Select all indicators linked to this detection. We want to check if any of those have more than one reference.
	classification_indicators_result = execute_select_sql_query(database, ("SELECT indicator_id FROM indicator_classification_link WHERE classifications_link_id = %i" % entry[0]))

	# Remove the link to the indicator from the given mail ID. Then, only other links will appear below and we should not touch them.
	execute_mutation_sql_query(database, "DELETE FROM indicator_classification_link WHERE classifications_link_id = %s", (entry[0],))

	# Iterate over the linked indicators to see if there are any other links remaining.
	for linked_indicator in classification_indicators_result:
		# Select all indicator links with the same ID as this one, having a different classification ID.
		other_indicator_links_result = execute_select_sql_query(database, ("SELECT id FROM indicator_classification_link WHERE indicator_id = %i" % (linked_indicator[0],)))
		if len(other_indicator_links_result) == 0:
			# No other links to this indicator exist, and therefore, we can remove the indicator from the database as well.
			execute_mutation_sql_query(database, "DELETE FROM indicators WHERE id = %s", (linked_indicator[0],))

	# Delete attributes if any are linked to this detection.
	execute_mutation_sql_query(database, "DELETE FROM linked_attributes WHERE classifications_link_id = %s", (entry[0],))

	# Finally, remove the classification from the database.
	execute_mutation_sql_query(database, "DELETE FROM mail_classifications_link WHERE id = %s", (entry[0],))

# If there are detections, parse them. This is logic for the production mode (non-verbose).
if "detections" in classifier_json:
	# Keep track of whether at least one detection for this message requires the message file and attachments to be retained.
	retain_message = False

	# Read the detections from the classifier result and process them.
	detections = classifier_json["detections"]
	for detection in detections:
		# Select detection from the database.
		detection_result = execute_select_sql_query(database, ("SELECT id,store_message_file FROM mail_classifications WHERE name = '%s'" % detection["name"]))
		if len(detection_result) != 1:
			eprint("Detection: %s was not found in the database! Must be added manually.." % detection["name"])
			exit(1)

		# Get the ID of the detection to link to.
		detection_entry = detection_result[0]
		detection_id = detection_entry[0]
		if detection_entry[1] != 0:
			retain_message = True

		# Query the most recent system API state, we will insert that value with the new classification.
		system_api_state_result = execute_select_sql_query(database, "SELECT MAX(state) FROM api_state");
		if len(system_api_state_result) == 0:
			eprint("System API state table is empty! No state was obtained, so execution aborted.")
			exit(1)

		# Get the API state to insert with the new classification.
		system_api_state_entry = system_api_state_result[0]
		system_api_state = system_api_state_entry[0]

		# Old detections deleted, we can insert the new one. Start with the detection itself.
		# We insert the state value itself in the mail_classifications_link table because it saves us a JOIN and space-wise it doesn't matter.
		# However, if normalized correctly, we would have inserted a reference to api_state.id instead.
		classification_link_id = execute_mutation_sql_query(database, "INSERT INTO mail_classifications_link (mail_id,classification_id,confidence,version,added_state) VALUES (%s,%s,%s,%s,%s)", (mail_id,detection_id,detection["confidence"], json_obj["version"], system_api_state))

		# Now we process the indicators associated with the detection.
		for indicator in detection["indicators"]:
			# Get the correct indicator ID from the text representation in the JSON output.
			indicator_type_id_result = execute_select_sql_query(database, ("SELECT id FROM indicator_types WHERE type = '%s'" % indicator["type"]))
			if len(indicator_type_id_result) == 0:
				eprint("Could not find indicator type: %s in the database! Skipping indicator." % indicator["type"])
				continue

			# Query the indicators table to check whether this indicator already exists. If so, we only need to insert a link to the new classification.
			indicator_type_entry = indicator_type_id_result[0]
			indicator_type_id = indicator_type_entry[0]
			indicator_result = execute_select_sql_query(database, ("SELECT id FROM indicators WHERE indicator_type_id = %s AND value = '%s'" % (indicator_type_id, indicator["value"])))
			if len(indicator_result) == 0:
				# Indicator does not exist in the database yet, so insert it here.
				indicator_id = execute_mutation_sql_query(database, "INSERT INTO indicators(indicator_type_id,value) VALUES (%s,%s)", (indicator_type_id, indicator["value"]))
			else:
				indicator_entry = indicator_result[0]
				indicator_id = indicator_entry[0]

			# Finally, insert the link between the indicator and the classification.
			execute_mutation_sql_query(database, "INSERT INTO indicator_classification_link (classifications_link_id,indicator_id,confidence) VALUES (%s,%s,%s)", (classification_link_id, indicator_id, indicator["confidence"]))

		# Process the attributes linked to the detection.
		if detection.get("attributes"):
			# Insert the attributes JSON into the database.
			execute_mutation_sql_query(database, "INSERT INTO linked_attributes (classifications_link_id,attributes) VALUES (%s,%s)", (classification_link_id, json.dumps(detection["attributes"])))

	# If the message must be retained to future reference, move it to the retained messages directory. Otherwise, we delete the message and attachments from disk and its body from the database.
	if retain_message:
		# Move the message file to the retained messages directory.
		shutil.move(full_message_path, os.path.join(classifier_config["retained_messages_dir"], mail_message_filename))
	else:
		# Message file does not need to be retained, so we delete everything from disk and the database.
		delete_message_from_disk(mail_id, full_message_path, num_attachments, attachments_dir)

	# Processed all detections, we let the queue manager know there was at least one detection.
	print("DETECTED")
else:
	# No detections on this mail message. Let the queue manager know it is clean.
	print("CLEAN")

	# Result is clean, and therefore, message file does not need to be retained. Delete everything from disk and the database.
	# FIXME: not yet, because we want to implement more detections first!
#	delete_message_from_disk(mail_id, full_message_path, num_attachments, attachments_dir)
