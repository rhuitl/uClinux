#!/usr/bin/perl

use strict;

open(INP, '<', $ARGV[0]) or die "Can't open input file $ARGV[0]: $!\n";

my $i = 0;
while(1)
{
	my $nread = sysread(INP, my $page, 4096);

	if($nread == 0)
	{
		last;
	}

	if($nread < 4096)
	{
		$page .= "\000" x (4096 - length($page));
	}

	my $file = 'page' . sprintf("%04x", $i) . '.bin';
	open(PAGE, '>', $file) or die "Can't create output file $file: $!\n";
	print PAGE $page;
	close(PAGE);

	$i++;
}

close(INP);
