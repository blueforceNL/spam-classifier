# ----------------------------------------------------------|
# Configuration file logic for spam classifier              |
# ----------------------------------------------------------|

from configparser import ConfigParser
import os

CONFIG_PATH = "/etc/spam-classifier"
DEFAULT_DB_ADDR = "localhost"
DEFAULT_DB_NAME = "spam_analyzer"
DEFAULT_DB_USER = "spam-analyzer"
DEFAULT_DB_PWD = "ChangeMe"
DEFAULT_CLASSIFIER_TIMEOUT_SECONDS = "60"
PROCESSING_FINISHED_DIR = "/sinkhole/processing_finished"
ATTACHMENTS_DIR = "/sinkhole/attachments"
RETAINED_MESSAGES_DIR = "/sinkhole/retained_messages"

# Reads configuration file from the config directory.
def load_configuration_file(path):
	config_object = ConfigParser()
	config_object.read(path)
	return config_object

# Creates a new default configuration.
def create_default_configuration(path):
	# Create default configuration.
	config_object = ConfigParser()
	config_object["CLASSIFIER"] = {
		"database_addr" : DEFAULT_DB_ADDR,
		"database_name" : DEFAULT_DB_NAME,
		"database_user" : DEFAULT_DB_USER,
		"database_passwd" : DEFAULT_DB_PWD,
		"processing_finished_dir" : PROCESSING_FINISHED_DIR,
		"attachments_dir" : ATTACHMENTS_DIR,
		"retained_messages_dir" : RETAINED_MESSAGES_DIR,
		"classifier_timeout_seconds" : DEFAULT_CLASSIFIER_TIMEOUT_SECONDS,
	}

	# Write default configuration to the config directory.
	with open(path, 'w') as config_file:
		config_object.write(config_file)

	return config_object

# Gets the configuration, newly created default or loaded from disk.
def load_or_create_config():
	# Create subdirectory for the configuration if it doesn't exist.
	os.makedirs(CONFIG_PATH, exist_ok=True)

	# Load configuration file from /etc/spam-analyzer/analyzer.comf. If it doesn't exist, create a new default one.
	conf_path = os.path.join(CONFIG_PATH, "classifier.conf")
	if os.path.exists(conf_path):
		config_object = load_configuration_file(conf_path)
	else:
		# Create default configuration.
		config_object = create_default_configuration(conf_path)

	# Obtain classifier config object.
	classifier_config = config_object["CLASSIFIER"]

	# Check whether the processing finished directory exists, and create if it does not.
	os.makedirs(classifier_config["processing_finished_dir"], exist_ok=True)

	# Check whether the attachments directory exists, and create if it does not.
	os.makedirs(classifier_config["attachments_dir"], exist_ok=True)

	# Check whether the retained messages directory exists, and create if it does not.
	os.makedirs(classifier_config["retained_messages_dir"], exist_ok=True)

	# Finally, return the config object to the caller.
	return config_object
