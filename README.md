# Spam Classifier

This repository contains the spam-classifier. This component is responsible for deciding whether a potentially malicious mail message is actually malicious or not. The classifier decision will determine whether a mail message body and its attachments will be retained or discarded. The spam-classifier will read from the spam-analyzer database and also write its results there, in its own tables.

## Installing

Follow the installation of the spam-analyzer first. After that, we clone the spam-classifier Git repository and move the directory into /opt/. The spam-classifier will be called from there by the queue manager.

```
cd /opt/
git clone git@github.com:blueforceNL/spam-classifier.git
```

Copy the wrapper script for the `spam-queue-ctl` tool to `/usr/local/bin` so it is accessible in `$PATH`.

```
cp /opt/spam-classifier/spam-queue-ctl.sh /usr/local/bin/spam-queue-ctl
```

Install the spam-classifier in systemd and make sure it is enabled.

```
cp /opt/spam-classifier/etc/spam-classifier.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now spam-classifier
```

## Building

The spam-classifier consists of two primary componentns: a Python wrapper script that collects input data from the database, and
the spam-classifier application. The latter is written in C++ and supports self-written detection modules. First, compile the source
code of the spam-classifier.

```
apt-get install make g++
cd /opt/spam-classifier/
make
```

The compilation will create `/opt/spam-classifier/bin/` and the `spam-classifier` binary. The classifier will read from STDIN, and therefore,
it must be called from the wrapper script.

## Configuring

Install the classifier configuration file from its sample in `/etc/spam-classifier`.

```
mkdir /etc/spam-classifier
cp /opt/spam-classifier/etc/classifier.conf.sample /etc/spam-classifier/classifier.conf
```

Configure the database parameters and directories for the classifier to move failed and completed messages to.
The database user and password are probably the only things you need to change.

| **Parameter**           | **Description**                                                                                            |
|-------------------------|------------------------------------------------------------------------------------------------------------|
| database_addr           | Address of database server, localhost by default.                                                          |
| database_name           | Database name, `spam_analyzer` by default. It needs to match what is configured for the spam-analyzer.     |
| database_user           | Username to authenticate to database server. Recommended to use the same account as for the spam-analyzer. |
| database_passwd         | Password to authenticate to the database server.                                                           |
| processing_finished_dir | This directory contains message files stored by the spam-analyzer as input for the classifier.             |
| attachments_dir         | This directory contains the attachments referenced by email messages.                                      |
| retained_messages_dir   | Raw message files are retained in this directory if the spam-classifier returns a positive result.         |

## Running

The spam-classifier is called automatically from the queue manager, which polls the spam classifier queue in the database. When an entry
is found in the queue, it calls `wrapper.py` with the mail ID as argument. The wrapper will pull all information from the database
using the mail ID and execute the classifier.

The classifier can be run manually as follows.

```
python3 /opt/spam-classifier/wrapper.py <mail_id>
```

By specifying the `-v` argument, the wrapper runs in verbose mode, and implicitly also dry-run mode. This means that the wrapper will
only return the classifier result but it will not write it to the database.

## Queue Management

The spam-classifier interacts with the spam-analyzer via a queue of mail IDs. This queue can be managed using the command line
tool `spam-queue-ctl` we have just placed in /usr/local/bin. This tool can list, query, add and remove mail IDs from the queue.
Very useful to debug or enter a series of mail IDs into the spam-classifier manually.

```
usage: queue_ctl.py [-h] (-a ADD_MAIL_IDS [ADD_MAIL_IDS ...] | -r REMOVE_MAIL_IDS [REMOVE_MAIL_IDS ...] | -q | -l | -c) [-v]

Spam classifier queue controller

optional arguments:
  -h, --help            show this help message and exit
  -a ADD_MAIL_IDS [ADD_MAIL_IDS ...]
                        Add one or more mail IDs to the queue
  -r REMOVE_MAIL_IDS [REMOVE_MAIL_IDS ...]
                        Remove one or more mail IDs from the queue
  -q                    Query statistics on the queue
  -l                    List all mail IDs currently scheduled
  -c                    Purge all mail IDs currently scheduled (empty the queue)
  -v                    verbose mode, print additional information
```

For example, querying the queue would return the number of elements currently queued.

```
# spam-queue-ctl -q
INFO: 5301 mail IDs in the queue
```

## Result object

The result object contains the version number of the spam-classifier that produced the output. If there is at least one detection, it is listed in
the `detections` sub-object. A detection contains a name, confidence level between 0 and 100, and a list of indicators and attributes. Indicators
can be email addresses, IP addresss, BTC addresses, URLs, etc. extracted from the message. Attributes can be freely filled in from a detection module
and could indicate a campaign ID for example.

```
{
    "detections": [
        {
            "attributes": {},
            "confidence": 30,
            "indicators": [],
            "name": "scam_generic"
        }
    ],
    "version": 53
}
```
