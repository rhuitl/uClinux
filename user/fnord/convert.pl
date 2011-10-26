#!/usr/bin/perl

use Compress::Zlib;

$PWD=`pwd`;
chomp $PWD;
push @dirs,$PWD;

while ($#dirs>=0) {
  my $x=shift @dirs;
  opendir DIR,$x || die "can't chdir to $x\n";
  foreach $i (readdir DIR) {
    next if (substr($i,0,1) eq ".");
    if (-d "$x/$i") {
      push @dirs,"$x/$i";
    } elsif (-f "$x/$i") {
      next if ($i =~ m/\.gz$/);
      my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$x/$i");
      my $gzmtime=(stat("$x/$i.gz"))[9];
      if (not defined $gzmtime or $gzmtime<$mtime) {
	print "gzipping $x/$i...\n";
	if ($#ARGV<0) {
	  open FILE,"$x/$i" || die "can't open $x/$i\n";
	  my $gz = gzopen("$x/$i.gz","wb")
	    or die "can't open $x/$i.gz: $gzerrno\n";
	  while (<FILE>) {
	    $gz->gzwrite($_)
	      or die "error writing: $gzerrno\n";
	  }
	  $gz->gzclose;
	  close FILE;
	  utime $atime, $mtime, "$x/$i.gz" or die "can't utime $x/$i.gz\n";
	  my $gzsize=(stat("$x/$i.gz"))[7];
	  unlink "$x/$i.gz" if ($gzsize>=$size);
	}
      }
    }
  }
  closedir DIR;
}
