#!/bin/sh

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#   WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
#
#  By using variables passed in from clamsmtpd in file 
#  manipulation commands without escaping their contents 
#  you are opening yourself up to REMOTE COMPROMISE. You 
#  have been warned. Do NOT do the following unless you 
#  want to be screwed big time:
#
#  mv $EMAIL "$SENDER.eml"
#
#  An attacker can use the above command to compromise your
#  computer. The only variable that is guaranteed safe in
#  this regard is $EMAIL. 
# 
#  The following script does not escape its variables 
#  because it only uses them in safe ways. 
# 
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# A sample script for virus actions. When testing make sure
# everything can run as the clamav (or relevant) user.

file="/path/to/virus.log"
dir="/path/to/quarantine/"

exec 1>>$file
exec 2>>$file


# Add some fun log lines to the log file

echo "-------------------------------------------------------"
echo Sender  $SENDER
echo Recipients  $RECIPIENTS
echo Virus  $VIRUS
echo "-------------------------------------------------------"


# Move the virus file to another directory
# This only works if Quarantine is enabled

if [ -n "$EMAIL" ]; then
	mv "$EMAIL" "$dir"
fi

