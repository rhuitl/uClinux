#!/usr/local/bin/perl

# The purpose of this script is to match each database entry with
# its "closest" tw.config entry.  Discrepencies appear when database
# entries are added, and currently, Tripwire does not remap existing
# entries to newly added entries.
# 
# This script is an interim measure to correct this database divergence.

##
## From tripwire.h
##
## /* database record format */
## /* filename: (entrynumber, ignorevec, st_mode, st_ino, st_nlink,
## *              st_uid, st_gid, st_size,
## *              ltob64(statbuf->st_atime, vec64_a),
## *              ltob64(statbuf->st_mtime, vec64_m),
## *              ltob64(statbuf->st_ctime, vec64_c), sig0, sig1, ..., sig9
## */

$usage = "usage: $0 <tw.db_hostname> <tw.config>";

$#ARGV != 1 && die $usage;		# only one argument allowed
($Database = $ARGV[0]) || die $usage;	# get name of db file
$Back = $Database . ".BAK";
die "Will not clobber existing $Back (saved backup version).\n" 
	if -e $Back;

#  Now, we create the backup file.  We do this in stages.  The first
#  stage involves linking the current file to the backup.  We then
#  create a temp file to hold the output.  Finally, when we are all
#  done, we unlink the original name and move the temporary to the
#  old name.

$Database =~ m#^(.+)/[^/]+$#;
$Temp = ($1 ? $1 : "./") . "tw.db_TEMP";
umask(077);
link ($Database, $Back) 
	|| die "Failed to link $Database to $Back: $!";
open (TMPFD, ">$Temp") 
	|| die "Failed to open temporary file $Temp: $!";

($Configfile = $ARGV[1]) || die $usage;	

# First we read in the configuration file, and remember the name of
# each entry.
#	$entry[$i++] = ...
#

open(CONFIG, $Configfile) || die "Failed to open config file $Configfile\n";

while (<CONFIG>) {
    s/^ *//;
    if (m/^#/) { next; }
    chop;
    ($entry, $flags) = split;
    eval "\$eentry = qq#$entry#";       # expands \ddd form

    $entry = $eentry;
    #print "Found entry $entry\n";

    $entry[$numentries] = $entry;
    $entrynums{$entry} = $numentries++;
}

# foreach dbentry {
#	foreach configentry {
#		assign score based on how maximal match
#	}
#	make sure entry(maximal match) is the entry(dbaseentry)
#	if not, correct
# }
#

open(DBASE, $ARGV[0]);
while (<DBASE>) {
    m/^@@dbaseversion\s+(\d+)/ && do {
	next if $1 == 4;
	unlink($Temp, $Back);
	die "$Database is version $1, and I only know how to update version 4!";
    };
    next if (/^(#|@@)/);
    next if (/^@@/);

    @line = split(' ', $_, 6);

    $line[0] =~ s/#/\\#/g;
    $junk = $line[0];
    eval "\$file = qq#$junk#";       # expands \ddd form
    $entrynum = ($line)[1];

    # find longest substring match
    $longest = 0;
    for ($i = 0; $i < $numentries; $i++) {
        if ($file =~ m/$entry[$i]/) {
	    if (length($entry[$i] > $longest)) {
	        $longest = length($entry[$i]);
		$lentrymatch = $entry[$i];
	    }
	}
    }

    #print "entry=$longest: $file\n";
    $realentrynum = $entrynums{$lentrymatch};
    #print "entry=$realentrynum ($line[1]): $file\n";

    if ($realentrynum != $line[1]) {
        #print "^^^^ Wow, it was wrong!!\n";
        $_ = join(' ', (@line[0], $realentrynum, @line[2..5]));
    }
    else {
        $_ = join(' ', (@line[0..5]));
    }

    #if ($st_ino) {
        #$_ = join(' ', (@line[0..3], $st_ino, @line[5]));
    #} else {
        #warn "$file: lstat() failed: $!  skipping...\n";
    #}
} continue {
    print TMPFD $_;
}

close TMPFD;

unlink($Database) 
	|| warn "Failed to unlink old database file $Database: $!";
rename($Temp, $Database)
	|| die "Failed to rename temporary file $Temp to $Database: $!";

