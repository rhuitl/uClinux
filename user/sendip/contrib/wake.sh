#! /bin/sh

# Usage: wake <host> [<MAC address>]
#
# <host> can be a host name or a dotted-quad IP address.
# If the <MAC address> is not given, it is taken from ethers(5).
# For this to work, if you give a host name as first argument, ethers
# has to contain host names (as opposed to IP addresses).
#
# Unless you have it already, you can build your ethers file like this:
#
# nmap -sP -PI 192.168.1.0/24	# prepare ARP cache with a ping-sweep
# arp -a | awk '$5 == "[ether]" { printf("%s\t%s\n", $4, $1); }' \
#        | sort >>/etc/ethers
#
# The 'magic packet' consists of 6 times 0xFF followed by 16 times
# the hardware address of the NIC. This sequence can be encapsulated
# in any kind of packet; I chose UDP to the discard port (9).

if [ $# = 1 ]; then
  ETHER=`awk "/$1/"' { gsub(":", "", $1); print $1; exit; }' /etc/ethers`
  if [ -z $ETHER ]; then
    echo "$0: host $1 is not in /etc/ethers" >&2
    exit 1
  fi
  ETHER=`echo $ETHER | sed 's/://g'`
else
  ETHER=$2
fi

ETHER="${ETHER}${ETHER}${ETHER}${ETHER}"		# 4 x MAC
ETHER="FFFFFFFFFFFF${ETHER}${ETHER}${ETHER}${ETHER}"	# Preamble + 16 x MAC

sendip $1 -p ipv4 -p udp.so -ud 9 -d 0x"$ETHER"
