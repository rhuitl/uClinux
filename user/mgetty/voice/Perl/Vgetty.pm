# 
# $Id: Vgetty.pm,v 1.4 2002/02/20 17:34:35 gert Exp $
#
# Copyright (c) 1998 Jan "Yenya" Kasprzak <kas@fi.muni.cz>. All rights
# reserved. This package is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package Modem::Vgetty;

use FileHandle;
use POSIX;
use strict;

use Carp;

use vars qw($testing $log_file $VERSION);

$VERSION='0.03';
$testing = 0;
$log_file = '/var/log/voicelog';

my @event_names = qw(BONG_TONE BUSY_TONE CALL_WAITING DIAL_TONE
	DATA_CALLING_TONE DATA_OR_FAX_DETECTED FAX_CALLING_TONE
	HANDSET_ON_HOOK LOOP_BREAK LOOP_POLARITY_CHANGE NO_ANSWER
        NO_CARRIER
	NO_DIAL_TONE NO_VOICE_ENERGY RING_DETECTED RINGBACK_DETECTED
	RECEIVED_DTMF SILENCE_DETECTED SIT_TONE TDD_DETECTED
	VOICE_DETECTED UNKNOWN_EVENT);



sub new {
	my ($class, $infd, $outfd, $pid) = @_;
	my $self = bless {}, $class;

        $infd  ||= $ENV{'VOICE_INPUT'};
        $outfd ||= $ENV{'VOICE_OUTPUT'};
        $pid   ||= $ENV{'VOICE_PID'};


	$self->{'IN'} = FileHandle->new_from_fd( $infd, "r" )
		|| return;
	$self->{'OUT'} = FileHandle->new_from_fd( $outfd, "w" )
		|| return;
	$self->{'IN'}->autoflush;
	$self->{'OUT'}->autoflush;

        $self->{'PIPE_BUF_LEN'} = POSIX::_POSIX_PIPE_BUF ;

	$self->{'PID'} = $pid;
	$self->{'LOG'} = FileHandle->new();

	if ($testing > 0) {
		$self->{'LOG'}->open(">>$log_file") || return undef;
		$self->{'LOG'}->autoflush;
		$self->{'LOG'}->print("-----------\n### Pid $$ opening log\n----------\n");
	}
        $self->{'EVENTS'} = { map { $_ => {} } @event_names };

	$self->init();

        return $self;

}


# The basic two functions (a low-level interface);
sub receive {
	my $self = shift;
	my $input;
	while(1) {
		$input = $self->{IN}->getline;
		chomp $input;
		$self->{LOG}->print("received: $input\n") if $testing > 0;
		last unless defined $self->{EVENTS}->{$input};
		# Handle the event:
		my $dtmf = '';
		if ($input eq 'RECEIVED_DTMF') {
			$dtmf = $self->{IN}->getline;
			chomp $dtmf;
			$self->{LOG}->print("DTMF $dtmf\n") if $testing > 0;
		}
		for (keys %{$self->{EVENTS}->{$input}}) {
			$self->{LOG}->print("Running handler $_ for event $input\n") if $testing > 0;
			&{$self->{EVENTS}->{$input}->{$_}}($self, $input, $dtmf);
			$self->{LOG}->print("Handler $_ for event $input finished.\n") if $testing > 0;
		}
	}
	$input;
}

sub send {
	my $self = shift;
	my $output = shift;
	$self->{OUT}->print("$output\n");
	kill PIPE => $self->{PID};
	$self->{LOG}->print("sent: $output\n") if $testing > 0;
}

sub expect {
	my $self = shift;
        $self->{LOG}->print("expecting: ", (join '|', @_), "\n")
	    if $testing > 0;
	my $received = $self->receive || return undef;
	for my $expected (@_) {
		return $received if $received eq $expected;
	}
	return undef;
}

sub waitfor {
	my $self = shift;
	my $string = shift;
        while (($self->expect($string) || "") ne $string) { }
}

sub chat {
	my $self = shift;
	my @chatscript = @_;
	my $received = 0;
	for my $cmd (@chatscript) {
		$received = 1 ^ $received;
		next if $cmd eq '';
		if ($received == 1) {
			return undef unless $self->expect($cmd);

		} else {
			$self->send($cmd);
		}
	}
	return 1;
}

# Initial chat
sub init {
	my $self = shift;
	$self->chat ('HELLO SHELL', 'HELLO VOICE PROGRAM', 'READY');
#	$self->chat ('HELLO SHELL', 'HELLO VOICE PROGRAM');

        return $self;
}

# Setting the voice device
sub device {
	my $self = shift;
	my $dev = shift;
        $self->{LOG}->print("attempting to set device $dev") if $testing;
	$self->chat ('', "DEVICE $dev", 'READY') || return undef;
	$self->{DEVICE}=$dev;
        $self->{LOG}->print("sucessfully set device $dev") if $testing;
}

sub shutdown {
	my $self = shift;
	$self->chat ('', 'GOODBYE', 'GOODBYE SHELL');
	$self->{IN}->close;
	$self->{OUT}->close;
	$self->{LOG}->close if $testing > 0;
}

sub DESTROY {
	my $self = shift;
	$self->shutdown;
}

sub enable_events {
	my $self = shift;
	$self->chat ('', 'ENABLE EVENTS', 'READY');
}

sub disable_events {
	my $self = shift;
	$self->chat ('', 'DISABLE EVENTS', 'READY');
}

sub beep {
	my $self = shift;
	my $freq = shift;
	my $len = shift;
	$self->chat ('', "BEEP $freq $len", 'BEEPING');
}

sub dial {
	my $self = shift;
	my $num = shift;
	$self->chat ('', "DIAL $num", 'DIALING');
}

sub getty {
	my $self = shift;
	$self->chat ('', 'GET TTY') || return undef;
	my $id = $self->receive;
	$self->expect ('READY') || return undef;
	return $id;
}

sub modem_type {
#	To be implemented in vgetty first.
	return undef;
}

sub autostop {
	my $self = shift;
	my $arg = shift;
	$self->chat ('', "AUTOSTOP $arg", 'READY');
}

sub play {
	my $self = shift;
	my $file = shift;
	$self->chat ('', "PLAY $file", 'PLAYING');
}

sub record {
	my $self = shift;
	my $file = shift;
	$self->chat ('', "RECORD $file", 'RECORDING');
}

sub wait {
	my $self = shift;
	my $sec = shift;
	$self->chat ('', "WAIT $sec", 'WAITING');
}

sub stop {
	my $self = shift;
	$self->send ('STOP'); # Nechceme READY.
}

sub add_handler {
	my $self = shift;
	my $event = shift;
	my $name = shift;
	my $func = shift;
	if (!defined($self->{EVENTS}->{$event})) {
		$self->{LOG}->print("add_handler: unknown event $event\n")
			if $testing > 0;
		return undef;
	}
	$self->{EVENTS}->{$event}->{$name} = $func;
}

sub del_handler {
	my $self = shift;
	my $event = shift;
	my $name = shift;
	if (!defined($self->{EVENTS}->{$event})) {
		$self->{LOG}->print("del_handler: unknown event $event\n")
			if $testing > 0;
		return undef;
	}
	if (!defined($self->{EVENTS}->{$event}->{$name})) {
		$self->{LOG}->print("del_handler: trying to delete nonexistent handler $name\n")
			if $testing > 0;
	} else {
		delete $self->{EVENTS}->{$event}->{$name};
	}
}

sub play_and_wait {
	my $self = shift;
	my $file = shift;
	$self->play($file);
	$self->waitfor('READY');
}

#####################################################################
# The readnum routine, its private variables and the event handler. #
#####################################################################

my $_readnum_number = ''; # The number itself. Filled in by the event handler.
my $_readnum_timeout = 10; # The value of the timeout. Fileld in by readnum.
my $_readnum_in_timeout = 1; # 'READY' from timeout or from the '#' key?

# Event handler. Just adds key to the $_readnum_number.
sub _readnum_event {
	my $self = shift;
	my $input = shift; # Unused. Should be 'RECEIVED_DTMF'.
	my $dtmf = shift;

	if ($dtmf eq '#') { # Stop the reading now.
		$_readnum_in_timeout = 0;
		$self->stop;
		$self->{LOG}->print("_readnum_event(): Got #; stopping\n");
		return;
	}
	$_readnum_number .= $dtmf;
	$self->stop;
	$self->expect('READY');
	# Restart the wait again.
	$_readnum_in_timeout = 1;
	$self->wait($_readnum_timeout);
}

sub readnum {
	my $self = shift;
	my $message = shift;
	my $timeout = shift;
	my $times = shift;
	$_readnum_number = '';
	$_readnum_in_timeout = 1;
	$_readnum_timeout = $timeout if $timeout != 0;
	$times = 3 if $times == 0;

	# Install the handler.
	$self->add_handler('RECEIVED_DTMF', 'readnum', \&_readnum_event);
	while($_readnum_in_timeout != 0 && $_readnum_number eq ''
		&& $times-- > 0) {
		$self->play_and_wait($message);
		last if $_readnum_in_timeout == 0;
		while ($_readnum_in_timeout != 0) {
			$self->wait($_readnum_timeout);
			$self->expect('READY');
		}
	}
	return undef if $times < 0;
	$self->del_handler('RECEIVED_DTMF', 'readnum');
	$self->stop;
	$self->expect('READY');
	$_readnum_number;
}

1;

__END__

=head1 NAME

Modem::Vgetty - interface to vgetty(8)

=head1 SYNOPSIS

	use Modem::Vgetty;
	$v = new Modem::Vgetty;

	$string = $v->receive;
	$v->send($string);
	$string = $v->expect($str1, $str2, ...);
	$v->waitfor($string);
	$rv = $v->chat($expect1, $send1, $expect2, $send2, ...);

	$ttyname = $v->getty;
	$rv = $v->device($dev_type);
	$rv = $v->autostop($bool);
	$rv = $v->modem_type; # !!! see the docs below.

	$rv = $v->beep($freq, $len);
	$rv = $v->dial($number);
	$rv = $v->play($filename);
	$rv = $v->record($filename);
	$rv = $v->wait($seconds);
	$rv = $v->play_and_wait($filename);
	$v->stop;

	$v->add_handler($event, $handler_name, $handler);
	$v->del_handler($event, $handler_name);
	$v->enable_events;
	$v->disable_events;

	$number = $v->readnum($message, $tmout, $repeat);

	$v->shutdown;

=head1 DESCRIPTION

C<Modem::Vgetty> is an encapsulation object for writing applications
for voice modems using the B<vgetty(8)> or B<vm(8)> package. The answering
machines and sofisticated voice applications can be written using this
module.

=head1 OVERVIEW

I<Voice modem> is a special kind of modem, which (besides the normal
data and/or fax mode) can communicate also in voice mode. It means
it can record sounds it hears from the phone line to the file,
Play-back recorded files, it can beep to the line, and it can detect
various standard sounds coming from the line (busy tone, silence,
dual tone modulation frequency (DTMF) keypad tones, etc).
An example of the voice modem can be the ZyXEL U1496, US Robotics
Sportster (not Courier), etc.

To use this software with the voice modem you need to have the
B<vgetty(8)> package installed. B<Vgetty> is distributed as a part of
B<mgetty> package. In fact, B<vgetty> is a B<mgetty(8)> with the voice
extensions. Vgetty has some support for scripting - when it receives
an incoming call, it runs a voice shell (it is program specified in
the B<voice.conf> file) as its child process, establishes the read
and write pipes to it, and tells it the number of the appropriate
descriptors in the environment variables. Voice shell can now
communicate with B<vgetty>. It can tell B<vgetty> "Play this file",
or "Record anything you hear to that file", or "Notify me when
user hangs up", etc. Sophisticated voice systems and answering
machines can be build on top of B<vgetty>.

B<mgetty> (including the B<vgetty>) is available at
the following URL:

	ftp://alpha.greenie.net/pub/mgetty/

Originally there was a (Bourne) shell interface to B<vgetty> only.
The B<Modem::Vgetty> module allows user to write the voice shell in Perl.
The typical use is to write a script and point the B<vgetty> to it
(in B<voice.conf> file). The script will be run when somebody calls in.
Another use is running voice shell from the B<vm(8)> program, which
can for example dial somewhere and say something.

=head1 QUICK START

	#!/usr/bin/perl
	use Modem::Vgetty;
	my $v = new Modem::Vgetty;
	$v->add_handler('BUSY_TONE', 'endh', sub { $v->stop; exit(0); });
	local $SIG{ALRM} = sub { $v->stop; };
	$v->enable_events;
	$v->record('/tmp/hello.rmd');
	alarm(20);
	$v->waitfor('READY');
	$v->shutdown;

The above example installs the simple `exit now'-style handler for the
B<BUSY_TONE> event (which is sent by B<vgetty> when user hangs up)
and then records the B<hello.rmd> file. Put this text into a file
and then point B<vgetty> to it in the B<voice.conf>. After you dial into
your voice modem, you can record a 20-seconds of some message.
Verify that B</tmp/hello.rmd> exists. Now delete the line contaning
the word "record" and two subsequent lines and insert to the file
the following line instead of them:

	$v->play_and_wait('/tmp/hello.rmd');

Now call the voice modem and listen to the sounds you have just recorded.


=head1 METHODS

=head2 Begin and end of communication

The B<Modem::Vgetty> object will initialize the communication pipes to
the B<vgetty> at the creation time - in the constructor. The closing
of the communication is done via the B<shutdown> method:

	$v->shutdown;

The module will call this method itself from the destructor, if you do
not call it explicitly.

=head2 Low-level communication

Users probably don't want to use these methods directly. Use the higher-level
functions instead.

=over 4

=item receive

This method returns a string received from the B<vgetty>. It parses
the string for the event types and runs appropriate event handlers.
If event handler is run it waits for another string.

=item send($string)

This method sends the string B<$string> to the B<vgetty> process.

=item expect($string1, $string2, ...)

Receives a string from B<vgetty> (using the B<receive> method described
above) and returns it iff it is equal to one of the strings in the argument
list. When something different is received, this method returns B<undef>.

=item waitfor($string)

Waits until the string B<$sring> is received from B<vgetty> (using the
B<receive> method described above).
=item chat($expect1, $sent1, $expect2, $sent2, ...)

A chat-script with B<vgetty>. Arguments are interpreted as the received-sent
string pairs. A received string equals to the empty string means that no
B<receive> method will be called at that place. This can be used for
constructing chat scripts beginning with the sent string instead of the
received one.

=back

=head2 Vgetty control methods

There are miscellaneous methods for controllig B<vgetty> and querying its
status. 


=over 4

=item getty

Returns the name of the modem special file (e.g. B</dev/ttyC4>).

=item device($name)

Sets the port of the voice modem input and output is done to.
Possible values are qw(NO_DEVICE DIALUP_LINE EXTERNAL_MICROPHONE
INTERNAL_SPEAKER LOCAL_HANDSET).

=item autostop($bool)

With autostop on, the voicelib will automatically abort a
play in progress and return READY. This is useful for faster
reaction times for voice menus. Possible arguments are qw(ON OFF).
B<Note:> The interface should probably be changed to accept the
Perl boolean arguments (undef, something else). Returns defined
value on success, undef on failure.

=item modem_type

B<vgetty> currently has no way of telling voice shell
the type of the current modem. This method is a proposed interface
for determining this type. Currently returns B<undef>. The appropriate
low-level interface has to be implemented in B<vgetty> first.

=back

=head2 Voice commands

=over 4

=item beep($freq, $len)

Sends a beep through the chosen device using given frequency (HZ) and length
(in miliseconds).
Returns a defined value on success or undef on failure.
The state of the vgetty changes to "BEEPING" and B<vgetty>
returns "READY" after a beep is finshed. Example:

	$v->beep(50,10);
	# Possibly do something else
	$v->waitfor('READY');

=item dial($number)

Modem tries to dial a given number. The B<vgetty> changes its state
to "DIALING" and returns "READY" after the dialing is finished.

=item play($filename)

The B<vgetty> tries to play the given file as a raw modem data.
See the "Voice data" section for details on creating the raw modem data
file. It changes the state to "PLAYING" and returns "READY" after
playing the whole file.

=item record($filename)

The B<vgetty> records the voice it can hear on the line to the given file.
It uses the raw modem data format (which can be re-played using the
B<play> subroutine). B<vgetty> changes its state to "RECORDING" and
you need to manually stop the recording using the B<stop> method
after some time (or, you can set B<autostop> and wait for any event
- silence, busy tone, etc).

=item wait($seconds)

The modem waits for a given number of seconds. Changes its state to
"WAITING" and returns "READY" after the wait is finished. Example:

	$v->wait(5);
	$v->waitfor('READY');

=item stop

The B<vgetty> stops anything it is currently doing and returns to the
command state. You must use B<stop> when you want to call another
B<beep>, B<dial>, B<play>, B<record> or B<wait> before the previous
one is finished. The B<vgetty> returns "READY" after the B<stop>
is called. So it is possible to interrupt a main routine waiting
for "READY" from the event handler:

	my $dtmf;
	$v->add_handler('RECEIVED_DTMF', 'readnum',
		sub { my $self=shift; $self->stop; $dtmf = $_[2]; });
	$v->enable_events;
	$v->wait(10); 
	$v->waitfor('READY');

In the previous example the B<waitfor> method can be finished either by
the 10-second timeout expired, or by the 'READY' generated by the
B<stop> in the event handler. See also the B<Events> section.

=item play_and_wait($file)

It is an abbreviation for the following:

	$v->play($file);
	$v->waitfor('READY');

It is repeated so much time in the voice applications so I have decided
to make a special routine for it. I may add the similar routines
for B<dial>, B<record>, B<beep> and even B<wait> in the future releases.

=back

=head2 Event handler methods

=over 4

=item add_handler($event, $handler_name, $handler)

Installs a call-back routine $handler for the event type $event.
The call-back routine is called with three arguments. The first
one is the Modem::Vgetty object itself, the second one is the
event name and the third one is optional event argument.
The B<$handler_name> argument can be anything. It is used when you
want to delete this handler for identificating it.

=item del_handler($event, $handler_name)

This method deletes the handler $handler_name for the $event event.
The result of unregistering the handler from the
event handler of the same event is unspecified. It may or may not be
called.

=item enable_events

Tells the B<vgetty> that the voice shell is willing to dispatch events.
No events are sent by B<vgetty> until this method is called.

=item disable_events

Tells the B<vgetty> that the voice shell doesn't want to receive
any events anymore.

=back

=head2 The B<readnum> method

=over 4

=item readnum($message, $tmout, $repeat)

The applications often need to read the multi-digit
number via the DTMF tones.  This routine plays the B<$message> to the
voice object and then waits for the
sequence of the DTMF keys finished by the `#' key. If no key is pressed
for B<$tmout> of seconds, it re-plays the message again. It returns
failure if no key is pressed after the message is played B<$repeat>-th
time. It returns a string (a sequence of DTMF tones 0-9,A-D and `*')
without the final `#'. When some DTMF tones are received and no terminating
`#' or other tone is received for B<$tmout> seconds, the routine returns
the string it currently has without waiting for the final '#'.
DTMF tones are accepted even at the time the B<$message> is played.
When the DTMF tone is received, the playing of the B<$message> is
(with some latency, of course) stopped.

B<NOTE:> The interface of this routine can be changed in future releases,
because I am not (yet) decided whether the current interface is the best one.
See also the B<EXAMPLES> section where the source code of this routine
(and its co-routine) is discussed.

=back

=head1 EVENTS

=head2 Introduction

Events are asynchronous messages sent by B<vgetty> to the voice shell.
The B<Modem::Vgetty> module dispatches events itself in the B<receive>
method. User can register any number of handlers for each event.
When an event arrives, all handlers for that event are called (in no
specified order).

=head2 Event types

At this time, the B<Modem::Vgetty> module recognizes the following
event types (description is mostly re-typed from the B<vgetty>
documentation):

=over 4

=item BONG_TONE

The modem detected a bong tone on the line.

=item BUSY_TONE

The modem detected busy tone on the line (when dialing to the busy
number or when caller finished the call).

=item CALL_WAITING

Defined in IS-101 (I think it is when the line receives another call-in
when some call is already in progress. -Yenya).

=item DIAL_TONE

The modem detected dial tone on the line.

=item DATA_CALLING_TONE

The modem detected data calling tone on the line.

=item DATA_OR_FAX_DETECTED

The modem detected data or fax calling tones on the line.

=item FAX_CALLING_TONE

The modem detected fax calling tone on the line.

=item HANDSET_ON_HOOK

Locally connected handset went on hook.

=item HANDSET_OFF_HOOK

Locally connected handset went off hook.

=item LOOP_BREAK

Defined in IS-101.

=item LOOP_POLARITY_CHANGE

Defined in IS-101.

=item NO_ANSWER

After dialing the modem didn't detect answer for the time
give in dial_timeout in voice.conf.

=item NO_CARRIER

The caller has hung up. This event is detected only by the ISDN4Linux
driver.

=item NO_DIAL_TONE

The modem didn't detect dial tone (make sure your modem is
connected properly to your telephone company's line, or check
the ATX command if dial tone in your system differs from
the standard).

=item NO_VOICE_ENERGY

It means that the modem detected voice energy at the
beginning of the session, but after that there was a
period of some time of silence (the actual time can be set using
the B<rec_silence_len> and B<rec_silence_treshold> parameters
in B<voice.conf>).

=item RING_DETECTED

The modem detected an incoming ring.

=item RINGBACK_DETECTED

The modem detected a ringback condition on the line.

=item RECEIVE_DTMF

The modem detected a dtmf code. The actual code value
(one of 0-9, *, #, A-D) is given to the event handler as the
third argument.

=item SILENCE_DETECTED

The modem detected that there was no voice energy at the
beginning of the session and after some time of silence
(the actual time can be set using
the B<rec_silence_len> and B<rec_silence_treshold> parameters
in B<voice.conf>).

=item SIT_TONE

Defined in IS-101.

=item TDD_DETECTED

Defined in IS-101.

=item VOICE_DETECTED

The modem detected a voice signal on the line. IS-101 does
not define, how the modem makes this decision, so be careful.

=item UNKNOWN_EVENT

None of the above :)

=back

=head1 VOICE DATA

Voice shell can send the voice data to the modem using the B<play>
method and record them using the B<record> method. The ".rmd" extension
(Raw Modem Data) is usually used for these files. The ".rmd" is not
a single format - every modem has its own format (sampling frequency,
data bit depth, etc). There is a B<pvftools> package for converting
the sound files (it is a set of filters similar to the B<netpbm> for image
files). The B<pvftormd(1)> filter can be used to create the RMD files
for all known types of modems.

=head1 EXAMPLES

=head2 Answering machine

A simple answering machine can look like this:

        #!/usr/bin/perl
        use Modem::Vgetty;
	my $voicemaster = 'root@localhost';
	my $tmout = 30;
	my $finish = 0;
        my $v = new Modem::Vgetty;
        $v->add_handler('BUSY_TONE', 'finish',
		sub { $v->stop; $finish=1; });
        $v->add_handler('SILENCE_DETECTED', 'finish',
		sub { $v->stop; $finish=1; });
	local $SIG{ALRM} = sub { $v->stop; };
        $v->enable_events;
        $v->play_and_wait('/path/welcome.rmd');
        $v->beep(100,10);
	$v->waitfor('READY');
	if ($finish == 0) {
		my $num = 0;
		$num++ while(-r "/path/$num.rmd");
		$v->record("/path/$num.rmd");
		alarm $tmout;
		$v->waitfor('READY');
	}
	system "echo 'Play with rmdtopvf /path/$num.rmd|pvftoau >/dev/audio'" .
		 " | mail -s 'New voice message' $voicemaster";
        exit 0;

See the B<examples/answering_machine.pl> in the source distribution,
which contains a more configurable version of the above text.
It first sets the event handlers for the case of busy tone (the caller
hangs up) or silence (the caller doesn't speak at all). The handler
stops B<vgetty> from anything it is currently doing and sets the $finish
variable to 1. Then the reception of the events is enabled and 
the welcome message is played. Then the answering machine beeps
and starts to record the message. Note that we need to check the
$finish variable before we start recording to determine if user
hanged up the phone. Now we find the first filename <number>.rmd
such that this file does not exist and we start to record the message
to this file. We record until user hangs up the phone or until
the timeout occurs.

=head2 Readnum routine

An interesting application of the low-level routines is the
B<Voice::Modem::readnum> method. The calling sequence of this method
has been discussed above. The source code for this routine and its
co-routine will be discussed here, so that you can write your own
variants of B<readnum> (which in fact does not have too general
interface). See also the source code of B<Vgetty.pm> for the B<readnum>
source.

The B<readnum> routine needs to have its own event handler for the
B<RECEIVED_DTMF> event and the way the handler can communicate with
this routine. In our solution we use "static" variables:

	my $_readnum_number = '';
	my $_readnum_timeout = 10;
	my $_readnum_in_timeout = 1;

The event handler will add the new character to the end of the 
B<$_readnum_number> variable. The B<$_readnum_timeout> is the number
of seconds both B<readnum> and the event handler should wait for the
next keypress, and the B<$_readnum_in_timeout> is a flag used by the
event handler for notifying the main B<readnum> routine that it forced
the B<vgetty> to emit the `READY' message because of the final `#'
has been received.

	sub _readnum_event {
		my $self = shift;
		my $input = shift; # Unused. Should be 'RECEIVED_DTMF'.
		my $dtmf = shift;

		if ($dtmf eq '#') { # Stop the reading now.
			$_readnum_in_timeout = 0;
			$self->stop;
			$self->{LOG}->print("_readnum_event(): Got #; stopping\n");
			return;
		}
		$_readnum_number .= $dtmf;
		$self->stop;
		$self->expect('READY');
		# Restart the wait again.
		$_readnum_in_timeout = 1;
		$self->wait($_readnum_timeout);
	}

The event handler is installed for the `RECEIVED_DTMF' event only, so it
doesn't need to check for the B<$input> value. The actual DTMF key is in
the third parameter, B<$dtmf>. Note that the handler will be called
when B<vgetty> is PLAYING or WAITING and the B<readnum> routine will
be waiting for the `READY' message. This allows us to immediately
interrupt waiting by the B<$self->stop> (which emits the `READY' message).
So when the `#' DTMF tone is received, we send a B<stop> to B<vgetty>.
If something else is received, we B<stop> the B<vgetty> too but we
enter a new wait using B<$self->wait>.

	sub readnum {
		my $self = shift;
		my $message = shift;
		my $timeout = shift;
		my $times = shift;
		$_readnum_number = '';
		$_readnum_in_timeout = 1;
		$_readnum_timeout = $timeout if $timeout != 0;
		$times = 3 if $times == 0;

		# Install the handler.
		$self->add_handler('RECEIVED_DTMF', 'readnum', \&_readnum_event);
		while($_readnum_in_timeout != 0 && $_readnum_number eq ''
			&& $times-- > 0) {
			$self->play_and_wait($message);
			last if $_readnum_in_timeout == 0;
			while ($_readnum_in_timeout != 0) {
				$self->wait($_readnum_timeout);
				$self->expect('READY');
			}
		}
		return undef if $times < 0;
		$self->del_handler('RECEIVED_DTMF', 'readnum');
		$self->stop;
		$self->expect('READY');
		$_readnum_number;
	}

The B<readnum> routine just sets up the event handler, then plays
the B<$message> and waits for the input (possibly several times).
The main work is done in the event handler. At the end the handler
is unregistered and the final value is returned.

=head2 Callme script

In the B<examples> subdirectory of the source distribution there is
a B<callme.pl> script. This dials the given number and plays the
given message. Use the following command to run it:

	vm shell -S /usr/bin/perl callme.pl <number> <message>.rmd

=head1 BUGS

There may be some, but it will more likely be in the B<vgetty> itself.
On the other hand, there can be typos in this manual (English is not my
native language) or some parts of the interface that should be
redesigned. Feel free to mail any comments on this module to me.

=head1 TODO

=over 4

=item Modem type recognition

The B<vgetty> should be able to tell the voice shell the name of the
current modem type.

=item The _wait() routines

I need to implement the routines similar to B<play_and_wait> for other
B<vgetty> states as well.

=item Debugging information

The module has currently some support for writing a debug logs
(use the $Modem::Vgetty::testing = 1 and watch the /var/log/voicelog
file). This needs to be re-done using (I think) Sys::Syslog.
I need to implement some kind of log-levels, etc.

=item Mgetty/Vgetty 1.1.17

Need to figure out what is new in 1.1.17 (I use 1.1.14 now). I think
new B<vgetty> can play more than one file in the single `PLAY' command,
it (I think) have some support for sending voice data from/to the voice
shell via the pipe, etc.

=back

=head1 AUTHOR

The B<Modem::Vgetty> package was written by Jan "Yenya" Kasprzak
<kas@fi.muni.cz>. Feel free to mail me any suggestions etc.
on this module. Module itself is available from CPAN, but be sure
to check the following address, where the development versions can
be found:

	http://www.fi.muni.cz/~kas/vgetty/

=head1 COPYRIGHT

Copyright (c) 1998 Jan "Yenya" Kasprzak <kas@fi.muni.cz>. All rights
reserved. This package is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut

