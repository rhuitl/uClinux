#!/usr/bin/perl -w
# This script will convert the on disk cache from frox version 0.6.x to one 
# for frox version 0.7.x.
#

$USER="";
$OLD_DIR="";
$NEW_DIR="";
$DELETE=1;

# Read Command line args.
while(scalar @ARGV>0) {
    if($ARGV[0] =~ /^--help$/) {
	print "Usage $0 [--olddir DIR] [--newdir DIR] [--user USER] [--keep]\n";
	print "\nUse this script to convert a version 0.6.x frox cache to 0.7.x.\n";
	print "Unless you give --keep the old cache files will be deleted.\n";
	exit;
    }
    if($ARGV[0] =~ /^--olddir$/) {
	shift @ARGV;
	$OLD_DIR=$ARGV[0];
    }
    elsif($ARGV[0] =~ /^--newdir$/) {
	shift @ARGV;
	$NEW_DIR=$ARGV[0];
    }
    elsif($ARGV[0] =~ /^--user$/) {
	shift @ARGV;
	$USER=$ARGV[0];
    }
    elsif($ARGV[0] =~ /^--keep$/) {
	$DELETE=0;
    }
    else {
	die "Unknown argument $ARGV[0]\n";
    }
    shift @ARGV;
}

if ($USER =~ /^$/) {
    print "What user does frox run as? ";
    $USER = <>;
    chomp($USER);
}
if ($OLD_DIR =~ /^$/) {
    print "What directory contains the frox cache to convert? ";
    $OLD_DIR = <>;
    chomp($OLD_DIR);
}

if ( ! -d $OLD_DIR . "/01" ) {
    die "$OLD_DIR doesn't appear to be a valid frox cache\n";
}

if ($NEW_DIR =~ /^$/) {
    print "What directory will frox 0.7.0 use[$OLD_DIR]?  ";
    $NEW_DIR = <>;
    chomp($NEW_DIR);
    if($NEW_DIR =~ /^$/) {$NEW_DIR=$OLD_DIR;}
}

$login=""; # Shut up warnings.
$pass=""; # Shut up warnings.
($login,$pass,$uid,$gid) = getpwnam($USER) or die "$USER not in passwd file\n";

chdir "$OLD_DIR" or die "Can't chdir to $OLD_DIR\n";

# Make new cache dirs.
$mode = 0755;
$filename = $NEW_DIR . "/cache/";
mkdir $filename or die "Can't make $filename\n";
chown $uid, $gid, $filename 
    or die "Can't change ownership. Please run as root\n";
chmod $mode, $filename;
foreach $i ("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f") {
    $filename = $NEW_DIR . "/cache/0" . $i;
    mkdir $filename;
    chown $uid, $gid, $filename;
    chmod $mode, $filename;
}

$mode = 0644;
# Find and convert files.
for $f  (`find ??/ -type f`) {
    chomp($f);
    @stats=stat($f);

    $nf=$NEW_DIR . "/cache/" . $f;
    open OLDFILE, "$f" or die "Unable to open $f\n";
    open NEWFILE, ">$nf" or die "Can't open $nf\n";

    $_=<OLDFILE>;
    @header=split;    # HEADER_BYTES MDTM SIZE MODE URL

    # sprintf line copied from cachemgr.c
    $new_header=sprintf("%.3d  %s %.12d %.1d %s %.12lu\n",
			length($header[1]) + length($header[4]) + 30,
			$header[1], $header[2], 1, $header[4], $stats[8]);
    print NEWFILE "$new_header";

    binmode OLDFILE;
    binmode NEWFILE;
    while(read OLDFILE, $BUFFER, 4096) {print NEWFILE $BUFFER}
    
    close OLDFILE;
    close NEWFILE;

    chmod $mode, $nf;
    chown $uid, $gid, $nf;

    if ($DELETE == 1) {unlink $f;}
}

print "Cache converted successfully\n";
