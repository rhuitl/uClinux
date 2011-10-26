#!/usr/bin/perl

# This script is used to clean up the /btmp dir of previous nights runs.
# It expects the following things to be in the environment:
#
#    $BTMP
#    $USER
#    $BRANCH
#    $TODAY

if(!defined($ENV{'BTMP'})   || length($ENV{'BTMP'})==0 ||
   !defined($ENV{'USER'})   || length($ENV{'USER'})==0 ||
   !defined($ENV{'BRANCH'}) || length($ENV{'BRANCH'})==0 ||
   !defined($ENV{'TODAY'})  || length($ENV{'TODAY'})==0 )
  {
    print STDERR "You must define \$BTMP, \$USER, \$BRANCH and \$TODAY for the cleanup to function."; 
    print STDERR "Values are: BTMP=\"".$ENV{'BTMP'}."\"\n";
    print STDERR "\tUSER=\"".$ENV{'USER'}."\"\n";
    print STDERR "\tBRANCH=\"".$ENV{'BRANCH'}."\"\n";
    print STDERR "\tTODAY=\"".$ENV{'TODAY'}."\"\n";
    die "Thank you.";
  }

$BTMP=$ENV{'BTMP'};
$USER=$ENV{'USER'};
$BRANCH=$ENV{'BRANCH'};
$TODAY=$ENV{'TODAY'};

$cleandir="$BTMP/$USER/$BRANCH";

# by default we'd like to have 700Mb to play with. UMLs take lots of space, alas.
$desiredspace=700*1024*1024;

# but, if there is a file in $cleandir called "free", then we take that as
# being the amount to keep free. It would make more sense to put a maximum
# usage instead, but that requires that we walk the file system multiple times.

if(-f "$cleandir/free") {
  $success = open(FREE, "$cleandir/free");
  if($success) {
    chop($desiredspace=<FREE>);
    close(FREE);
  } else {
    warn "Can not open $cleandir/free: $!\n";
  }
}

sub getdiskspace {
# bash-2.05$ df -P /btmp
# Filesystem         1024-blocks      Used Available Capacity Mounted on
# /dev/hda7             33855264   2954140  29181368      10% /abigail
#

  open(DF, "df -P $cleandir |") || die "Can not invoke df: $!\n";
  $header=<DF>;
  $_=<DF>;
  ($filesystem, $blocks, $used, $avail, $percent, $mount)=split;
  return $avail*1024;
}

sub cmpdir {
  # $a and $b contain things to compare.

  local($ay,$am,$ad) = split(/_/, $a, 3);
  local($by,$bm,$bd) = split(/_/, $b, 3);

  if($ay != $by) {
    return $ay <=> $by;
  } elsif ($am != $bm) {
    return $am <=> $bm;
  } elsif ($ad != $bm) {
    return $ad <=> $bd;
  } else {
    return 0;
  }
}

chdir($cleandir) || die "Can not chdir to $cleandir\n";

opendir(TOPDIR, $cleandir) || die "can not opendir($cleandir): $!\n";
@dirs=readdir(TOPDIR);
closedir(TOPDIR);

# filter it looking for date format dirs, excepting $TODAY.
@candidatedirs=();
for $dir (@dirs) {
  if($dir =~ m,\d\d\d\d_\d\d_\d\d, &&
     $dir != $TODAY) {
    push(@candidatedirs, $dir);
  }
}

@candiatedirs = sort cmpdir @candidatedirs;

while($#candiatedirs > 0 &&
      &getdiskspace < $desiredspace) {

  $dir=unpush(@candiatedirs);

 
  print "Removing $dir\n";
  #system("rm -rf $dir");
}

if(&getdiskspace < $desiredspace) {
  print STDERR "Failed to free enough disk space";
  exit 1;
}

exit 0;  

# $Id: regress-cleanup.pl,v 1.2 2002/01/11 20:43:02 mcr Exp $
#
# $Log: regress-cleanup.pl,v $
# Revision 1.2  2002/01/11 20:43:02  mcr
# 	perl uses "elsif" - if was missing completely.
#
# Revision 1.1  2002/01/11 04:26:48  mcr
# 	revision 1 of nightly regress scripts.
#
#
