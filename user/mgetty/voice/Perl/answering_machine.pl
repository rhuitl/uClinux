#!/usr/bin/perl -w
#
# $Id: answering_machine.pl,v 1.1 1998/09/09 21:48:52 gert Exp $
#
# A simple answering machine. See the Modem::Vgetty man page for the
# discussion of this source code.
#
# Copyright (c) 1998 Jan "Yenya" Kasprzak <kas@fi.muni.cz>. All rights
# reserved. This package is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# To run it: set the $voicemaster and $voicedir variables below to something
# usable. Create the $voicedir directory. Edit the vgetty's configuration
# file (voice.conf) so that it contains the following options:
#
#      voice_shell /usr/bin/perl
#      call_program /some/path/answering_machine.pl
#
# (optional: create the welcome message using something like
#      autopvf <message.au |pvfspeed -s <speed>|pvftormd <modem_type> \
#             > $voicedir/welcome.rmd
# where the speed and modem_type depends on your modem type - see the
# pvftormd(1) documentation.)
# Configure the vgetty on your modem line (in voice.conf), run it
# (maybe from /etc/inittab) an call your modem. It should play a welcome
# message (if you have created one), beep and record the message you
# say to the phone.
#
use Modem::Vgetty;

my $voicemaster = 'root@localhost';
my $voicedir = '/var/spool/voice';
my $tmout = 30;
my $finish = 0;
my $v = new Modem::Vgetty;
$v->add_handler('BUSY_TONE', 'finish',
	sub { $v->stop; $finish=1; });
$v->add_handler('SILENCE_DETECTED', 'finish',
	sub { $v->stop; $finish=1; });
local $SIG{ALRM} = sub { $v->stop; };
$v->enable_events;
$v->play_and_wait($voicedir.'/welcome.rmd');
$v->beep(100,10);
$v->waitfor('READY');
if ($finish == 0) {
	my $num = 0;
	$num++ while(-r "$voicedir/$num.rmd");
	$v->record("$voicedir/$num.rmd");
	alarm $tmout;
	$v->waitfor('READY');
}
system "echo 'Play with rmdtopvf $voicedir/$num.rmd|pvftoau >/dev/audio'" .
	 " | mail -s 'New voice message' $voicemaster";
exit 0;
