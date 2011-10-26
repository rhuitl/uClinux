#!/usr/bin/perl -w
#
# $Id: callme.pl,v 1.1 1998/09/09 21:48:54 gert Exp $
#
# This script dials a given number and then re-plays the message.
# Use "vm shell -S /usr/bin/perl callme.pl number message.rmd"
# for calling the "number" and playing the "message.rmd".
#
# Copyright (c) 1998 Jan "Yenya" Kasprzak <kas@fi.muni.cz>. All rights
# reserved. This package is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
use Modem::Vgetty;

my $v = new Modem::Vgetty;

die "Usage: callme.pl number message.rmd" if $#ARGV != 1;
$v->device('DIALUP_LINE')
$v->add_handler('BUSY_TONE', 'finish',
        sub { $v->stop; exit 0; });
$v->enable_events;
$v->dial($ARGV[0]);
$v->waitfor('READY');
$v->play_and_wait($ARGV[1]);
1;

