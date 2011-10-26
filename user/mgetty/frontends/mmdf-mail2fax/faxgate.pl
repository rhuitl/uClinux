#!/usr/local/bin/perl
#
# faxgate 1.0.0
# By Nigel Whitfield
#
# Takes files from mail spool directories and injects them
# into the fax system for transmission
#
#

# initialise variables; make sure these are set correctly
# for your system
#
$queuedir='/usr/spool/mmdf/lock/home/q.fax' ;
$msgdir='/usr/spool/mmdf/lock/home/msg' ;
$addrdir='/usr/spool/mmdf/lock/home/addr' ;

# faxsender must take the same options as the mgetty faxspool program
#
$faxsender='/usr/local/bin/faxspool' ;
$faxadmin='faxadmin@stonewall.demon.co.uk' ;
$mailprog='/bin/mail' ;

$tmpdir='/usr/tmp' ;

chdir( $queuedir ) || die("Cannot change to mail queue directory!\n" ) ;

@files=`/bin/ls` ;

# This is the main loop, done for each file in the queue dir
#
$faxes = 0 ;


while($qfile=shift(@files)){

	open( NOTIFY, "| $mailprog -s'Fax gateway report' $faxadmin" ) || die("Cannot open log message\n") ;

	$faxes++ ;
	chop $qfile ;
	printf( NOTIFY "Message queued in file %s\n", $qfile ) ;

	# Open the queue file and extract destination & return info
	#
	open(Q, $qfile) || die("Cannot open queue file\n" ) ;
	$c= 0 ;
	while(<Q>) {
		chop $_ ;
		$qinfo[$c] = $_  ;
		$c++ ;
	}
	close Q ;
	$retaddr = $qinfo[1] ;
	($x1,$x2,$x3,$x4,$x5)= split(/ /, $qinfo[2]) ;
	($x1,$fnumber,$x2) = split( /\"|@/, $x5 ) ;

	printf( NOTIFY "Fax from %s queued to %s\n" , $retaddr, $fnumber ) ;
	
	# Now open the message file and extract info for
	# the cover page, and the message body
	#
	open(MSG, $msgdir . "/" . $qfile ) || die("Cannot open message file\n");
	
	$msgstart = 0 ; 
	$msgcount = 0 ;
	$subject = "" ;
	$fromaddr = "" ;
	$dateline = "" ;

	while(<MSG>) {
		if ($msgstart == 0) {
			($_ =~ /^$/ ) && ($msgstart = 1);
			($_ =~ /^Date:[ 	]/) && ($dateline = $_) ;
			($_ =~ /^From:[ 	]/) && ($fromaddr = $_) ;
			($_ =~ /^Subject:[ 	]/) && ($subject = $_) ;
		}
		else {
			$msg[$msgcount] = $_ ;
			$msgcount++ ;
		}
	}
	close MSG ;

	chop $dateline ;
	chop $fromaddr ;
	chop $subject ;

	# Now we have all the information needed to create a fax
	# Start with the cover page information
	#
	$cvrname = "" ;
	$cvrname .= $tmpdir . "/" . "faxgate-cover" . $$ . "." . $faxes ;
	open(CVR, "> $cvrname" ) || die("Cannot create cover page file") ;
	
	print CVR "The following fax message was automatically converted\n" ;
	printf( CVR "from internet e-mail by %s\n\n", $faxadmin) ; 
	print CVR "The originator of the fax, the subject of their message\n" ;
	print CVR "and the time at which it was posted via e-mail are below.\n" ;
	printf( CVR "\n%s\n%s\n%s\n", $fromaddr, $subject, $dateline ) ;

	close CVR ;

	# and now the message text
	#
	$msgname = "" ;
	$msgname .= $tmpdir . "/" . "faxgate-msg" . $$ . "." . $faxes ;
	open(FAX, "> $msgname" ) || die("Cannot create message file") ;

	print FAX @msg ;

	close FAX ;
	
	# and now we can actually queue the fax
	#
	$faxcmd = $faxsender ;

	$faxcmd . = " -F 'Mail to fax gateway' -C '/usr/local/lib/fax/make.coverpg -m " . $cvrname . "' -f " . $retaddr . " -q " . $fnumber . " " . $msgname ;

	printf( NOTIFY "Fax command: %s\n", $faxcmd ) ;
	
	$success=system($faxcmd) ;
	
	# and finally notify people of the result, and clean up
	#	
	open(SENDER, "| $mailprog -s'Your fax transmission' '$retaddr'" ) || die("Can't report to originator\n" ) ;

	if ($success == 0 ) {
		print NOTIFY "Fax command completed\n\n" ;
		unlink $qfile ;
		unlink $msgdir . "/" . $qfile ; 
		unlink $addrdir . "/" . $qfile ;

		printf( SENDER "Your fax to %s has been queued for sending\nand will be despatched when the fax queue is next processed.\n" , $fnumber ) ;

	}
	else {
		printf( NOTIFY "Unable to send fax for message %s\n\n", $qfile ) ;
		printf( SENDER "Your fax to %s cannot be queued because\nan error occurred during processing.\n\nPlease contact %s for more details\n\n", $fnumber, $faxadmin ) ;
	}

	unlink $cvrname ; 
	unlink $msgname ;
	close SENDER ;
	
}

exit ;

