#!/usr/bin/perl -w
#
# Non-terminating program that checks for jobs from the pcs.
#
# This program certainly isn't suited to show how to program in
# perl. It was only a quick hack to test the feasibility of faxing
# word documents from pcs.
#
# This program is (C) 1996 by Klaus Lichtenwalder, Lichtenwalder@ACM.org
# Permission to use and modify as appropriate. Please retain the copyright
# notice if redistributing.
#

$MAILER="/usr/lib/sendmail";
$DIR="/usr/spool/fax/winword";

open(LOG, ">>/usr/adm/errors");
select LOG; $| = 1;select STDOUT;
# Just keep some infos 'bout problems.

$lfnd = 1;

while (1) {
    chdir($DIR);
    opendir(DIR, $DIR);
    foreach $lck (readdir(DIR)) {

# Some words about the structure of the files:
#  The lock file, 'lck.###' This file names in the extension the number
#  of the pc the job's coming from. The first line contains the fax number.
#  The second line names the recipients name.
#  According to the number from the lck-file we check for a PostScript-
#  Document temp###.fax. Because of some write latency (??) we check
#  for the completeness of the file by grep-ing for %%EOF

	next unless ($lck =~ /^lck\.\d/); # No file present

	$lck =~ /lck.(\d+)/;
	$pcnummer = $1;

	next if (! -s "temp$pcnummer.fax");

	printf LOG "%s: LCK ist %s\n", join('.', localtime(time)), $lck;
	# Some comment for our log.

	$cnt = `grep -c %%EOF temp$pcnummer.fax`;
	next if ($cnt == 0);
	# Not yet completely written.

	$user = "pc$pcnummer";
	# The naming scheme is pc1, pc2, ...

	open(LCK, $lck);
	chop($phone = <LCK>);
	chop($verbose_to = <LCK>);
	chop($verbose_to);	# Because of Ctrl-M Ctrl-J
	close(LCK);

	chop($phone);
	print  LOG "PC $pcnummer to $phone/$verbose_to\n";

	$ok = `file temp$pcnummer.fax`;

	# Did we get a Postscript File?
	if ($ok !~ /[pP]ost[sS]cript/) {
	    # No, complain bitterly
	    open(MAILERR, "|$MAILER $user ");
	    print MAILERR "To: $user
Subject: Problems trying to send your fax
From: Fax Subsystem

The pages are not in the correct format, please try again!!\n";
	    close(MAILERR);
	    system("rm -f temp$pcnummer.fax $lck");
	    next;
	}

	# Now take it out of the way, for slower systems,
	# so the user can schedule the next fax
	$fn = sprintf("/tmp/fax%04d", $lfnd++);
	`mv $DIR/temp$pcnummer.fax $fn`;
	`rm -f temp$pcnummer.fax $lck`;

	# Send it off to the fax system.
	# We use a slightly hacked fax-script: the first argument
	# is the verbose_to, the second the faxnumber, the third (and rest)
	# are the faxpages
	$err = `USER=PC$pcnummer; export USER; sh /usr/bin/fax $verbose_to $phone $fn </dev/null >/dev/null`;
	`rm -f $fn`;

	# Error occured?
	if ($err =~ /Error spool/ ) {
	    open(MAILERR, "|$MAILER $user ");
	    print MAILERR "To: $user
Subject: Problems trying to send your fax
From: Fax Subsystem

Can't hand off the fax to to fax system:
$err\n";
	    close(MAILERR);
	    next;
	}
    }
    sleep 10;			# Just keep an eye at the system load
    closedir(DIR);
}				# And on and on ...
