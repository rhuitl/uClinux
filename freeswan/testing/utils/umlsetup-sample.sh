#!/bin/sh 

#
# this is the configuration file that helps setup for
# a kernel pool for UML compilation w/FreeSWAN.
# 
# Copy this file to the top of your FreeSWAN source directory as
# umlsetup.sh, and edit that copy.
#

# set this to someplace with at least 100Mb free.
POOLSPACE=/c2/freeswan/umlbuild

# set this to original kernel source
# could be native build:
#KERNPOOL=/usr/src/linux
#
# or something you downloaded.
KERNPOOL=/c2/kernel/linux-2.4.9/linux

# set this to the UML tar file, gotten from, e.g.
#     http://ftp.nl.linux.org/uml/uml-patch-2.4.9-7.bz2
#
UMLPATCH=/c2/user-mode-linux/download/uml-patch-2.4.9-7.bz2

# set BASICROOT this to an unpacked copy of the root file system you
# want to use.
#
# a small-ish one is at:
#     http://www.sandelman.ottawa.on.ca/freeswan/uml/
#
# umlfreeroot-5.1.tar.gz  is 17Mb, unpacks to around 50Mb.
#
# umlfreesharemini.tar.gz is 3Mb, unpacks to around 8Mb.
# umlfreeshareall.tar.gz is 6Mb, unpacks to around 26Mb.
#
# I did 
#   mkdir -p /c2/user-mode-linux/basic-root
#   cd /c2/user-mode-linux/basic-root
#   nftp -o - http://www.sandelman.ottawa.on.ca/freeswan/uml/umlfreeroot-5.1.tar.gz | tar xzvf - 
#  (or ncftp, or whatever your favorite program is)
#
# There is an advantage to having this on the same partition as
# $POOLSPACE, as hard links can be used.
#
BASICROOT=/c2/user-mode-linux/basic-root/root

# the mini /usr/share has Canada zoneinfo and "en" locale only.
# the all one has everything from the original UML debian root.
# I run debian, so I can just use my native /usr/share!
SHAREDIR=/usr/share

REGULARHOSTS='sunrise sunset nic'
FREESWANHOSTS='east west japan'

# comment this out
echo 



