#!/bin/sh
#
# convert.sh 0.2
# Lance Spitzner <lance@honeynet.org>
# November 27, 2002
# Last Modified: 10 December, 2002
#
# PURPOSE: The purpose of this script is to take an existing 
# Snort 1.9 rules set and convert it for use with a Honeynet 
# using Snort-Inline.  A Honeynet is  a type of honeypot, it 
# is a network designed to be compromised.  You can learn 
# more at
#
#    http://www.honeynet.org/papers/honeynet/
#
# WARNING!  You do not want to use this script to to create 
# rules for regular environments.  This script will create 
# an ass-backwards rule set.  It will allow any inbound 
# attacks, but block any outbound attacks once your network 
# has been hacked.  Sounds odd, but for a Honeynet, this is 
# exactly what we want.
#
# To execute this script, simply copy it in the same
# directory as the Snort rule set you want to convert.
# No need to run this as root.  You will most likely have
# to manually modify the new rule set, as this global 
# approach can break things.
#
# For Honeynets, you should carefully select which rules 
# you will use to drop attacks.  If you Drop everything,
# you will be blocking alot of valid traffic (such as
# ICMP queries).  If you don't drop certain outbound
# attacks, the bad guys can hack into other systems.
# So, which rules do you use?  That is for you to figure
# out.  This script takes the brute force approach and
# converts ALL rules to Drop packets.

###  Basics
PATH=/bin:/usr/bin

### Variables
TMP=/tmp/.rule_$$

#### Execution  ######
## Uncomment this line (and comment the for statement beneath it) if you 
# want to convert only specific rules files listed in rules.txt
#for x in `cat rules.txt`

for x in `ls *.rules`
do
  echo "Converting rule $p in $x to use the DROP command for Honeynets"
  cat $x | sed -e "s/EXTERNAL_NET/HONEYNET/g"  -e "s/HOME_NET/EXTERNAL_NET/g" \
               -e "s/SMTP_SERVERS/EXTERNAL_NET/g"  -e "s/HTTP_SERVERS/EXTERNAL_NET/g" \
               -e "s/SQL_SERVERS/EXTERNAL_NET/g"   -e "s/DNS_SERVERS/EXTERNAL_NET/g" \
               -e "s/TELNET_SERVERS/EXTERNAL_NET/g" -e "s/alert /drop /g" > $TMP
  cat $TMP > $x
done

rm $TMP
