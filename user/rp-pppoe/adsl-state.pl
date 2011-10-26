#!/usr/bin/perl
#**********************************************************************
#
# adsl-state.pl
#
# Perl script which examines log files and summarizes state of ADSL link.
#
# Copyright (C) 2000 Roaring Penguin Software Inc.
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
# $Id: adsl-state.pl,v 1.1.1.1 2000-11-17 05:28:41 davidm Exp $
#
#**********************************************************************

# This script analyzes your log files and summarizes the availability
# of your ADSL link.
# ASSUMPTIONS:
# 1) You are using the adsl-connect script supplied with rp-pppoe to maintain
#    your connection.
# 2) You are logging events of level "info" or above, and that "daemon"
#    facility messages are logged to /var/log/messages.
#
# To use:  perl adsl-state.pl < /var/log/messages

$state = "??";
$prevtime = "??";

sub up {
    return if ($state eq "UP  ");

    my($line) = @_;
    $line =~ /^(\S+)\s+(\S+)\s+(\S+).*/;
    $month = $1;
    $day = $2;
    $time = $3;
    $now = "$day $month $time";
    if ($state ne "??") {
	print "DOWN from $prevtime to $now\n";
    }
    $state = "UP  ";
    $prevtime = $now;
}

sub down {
    return if ($state eq "DOWN");

    my($line) = @_;
    $line =~ /^(\S+)\s+(\S+)\s+(\S+).*/;
    $month = $1;
    $day = $2;
    $time = $3;
    $now = "$day $month $time";
    if ($state ne "??") {
	print "UP   from $prevtime to $now\n";
    }
    $state = "DOWN";
    $prevtime = $now;
}

while(<>) {
    chomp;
    if (/remote IP address/) {
	up($_);
    } elsif (/connection lost; attempting/) {
	down($_);
    }
    $lastline = $_;
}

$lastline =~ /^(\S+)\s+(\S+)\s+(\S+).*/;
$month = $1;
$day = $2;
$time = $3;
$now = "$day $month $time";
print "$state from $prevtime to $now (end of log.)\n";
