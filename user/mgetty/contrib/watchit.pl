#!/usr/local/bin/perl5
#
# watchit.pl
#
# watch mgetty log file (the "auth.log" syslog file) for repeated failure
# messages, alarming system administrator after repeated failures
#
# RCS: $Id: watchit.pl,v 1.2 1998/10/07 13:54:06 gert Exp $
#
# $Log: watchit.pl,v $
# Revision 1.2  1998/10/07 13:54:06  gert
# add RCS keywords
#
#
require 'getopts.pl';

# configuration section
#
# which file to monitor
$logfile="/var/log/auth.log";

# send mail after <n> "failed" mgetty startups
$max_fail=3;

# who you gonna call? This user gets the mail
$faxadmin="knarf";

# mail program
$mailprg="/usr/lib/sendmail";


# options
#
# -d: debug = show what's going on (silent operation otherwise)

$opt_d = 0;
&Getopts('d') || do { print STDERR "$0: usage: watchit [-d]\n"; die; };


$cmd="tail -f $logfile |";
$skipped=0;

open( TAILF, $cmd ) ||
	die "Can't fork command '$cmd': $!\n";

while( <TAILF> )
{
# skip "old junk"
    $skipped++;
    next if ( $skipped<10 );

    chomp;

# skip non-mgetty messages
    next unless /mgetty/;

    print "DBUG: $_\n" if $opt_d;

# skip lines with no device name given
    next unless / dev=([^\s,]+)[, ]/;

    $dev=$1;

# set up status
    if ( /failed/ )
    {
	if ( $status{$dev} ne "FAIL" )
	    { $status{$dev}="FAIL"; $failures{$dev}=1; $failmsg{$dev}=$_; }
	else
	    { $failures{$dev}++;
	      $failmsg{$dev} .= "\n" . $_;
	      if ( $failures{$dev} >= $max_fail ) { &make_noise; };
	    }
    }
    else
    { $status{$dev}="GOOD" };

    print "DBUG: status\{$dev\} now ". $status{$dev}. 
			"(" . $failures{$dev} . ")\n" if $opt_d;
}

close TAILF;

sub make_noise
{
    open( PIPE, "|$mailprg $faxadmin" ) ||
		    die "can't open pipe to mail program: $!\n";

    print PIPE <<PEOF;
To: $faxadmin
From: root (Modem Watching Servant)
Subject: sick modem on $dev
Priority: urgent

Hello $faxadmin,

one of your modems ($dev) created $max_fail failure messages
in the logfile '$logfile'. You might want to investigate!!!

The offending lines in the log file are:

----------------- snip - snap - ouch --------------------------
PEOF
    print PIPE $failmsg{$dev};

    print PIPE <<PEOF2;

----------------- snip - snap - ouch --------------------------

Kind regards,

your ever happily watching modem servant.

PEOF2

    close PIPE;

    print "sent mail to $faxadmin\n" if $opt_d;

    $failures{$dev}=-57;	# complain again in 60 mgetty cycles
}
