#! /usr/local/bin/vm shell
exec /usr/local/bin/perl -x $0
#! /usr/local/bin/perl

#
# This is a demo script for the new interface between shell scripts and
# the voice library
#
# WARNING: you MUST use the "#!" lines as shown, otherwise perl/vm get into
#          a recursive loop until your system runs out of file descriptors
#
# $Id: demo.pl,v 1.1 1998/04/18 17:49:14 gert Exp $
#

require 5.004;
use IO::Handle;

# debugging?
$opt_d = 1;

#
# Define the function to receive an answer from the voice library
#
sub voice_receive
{
    my $line = <$voice_rfd>;
    chomp $line;
    print "VR: <$line>\n"  if $opt_d;
    return $line;
}

#
# Define the function to send a command to the voice library
#

sub voice_send
{
    print "VS: <$_[0]>\n"  if $opt_d;
    print $voice_wfd $_[0] . "\n";
    $voice_wfd->flush();
    kill PIPE => $voice_pid;
}

#
# Define the function to initialize the file descriptors and 
# check whether the voice library is talking to us.
#

sub voice_init
{
    if ( ! defined( $ENV{VOICE_INPUT} ) )
	{ die "$0: environment variable 'VOICE_INPUT' not set!\n"; }
    if ( ! defined( $ENV{VOICE_OUTPUT} ) )
	{ die "$0: environment variable 'VOICE_OUTPUT' not set!\n"; }
    if ( ! defined( $ENV{VOICE_PID} ) )
	{ die "$0: environment variable 'VOICE_PID' not set!\n"; }

    print "VI: input:  " . $ENV{VOICE_INPUT} . "\n";
    print "VI: output: " . $ENV{VOICE_OUTPUT} . "\n";

    $voice_rfd = new IO::Handle;
    unless( $voice_rfd->fdopen( $ENV{VOICE_INPUT}, "r" ) )
	{ die "$0: can't reopen VOICE_INPUT for reading"; }

    $voice_wfd = new IO::Handle;
    unless( $voice_wfd->fdopen( $ENV{VOICE_OUTPUT}, "w" ) )
	{ die "$0: can't reopen VOICE_OUTPUT for writing"; }

    $voice_pid = $ENV{VOICE_PID};

    my $text = &voice_receive;
    if ( $text ne 'HELLO SHELL' )
	{ die "$0: voice library not answering ($text)"; }
}

#
# Let's see if the voice library is talking to us
#
&voice_init;

#
# Let's answer the message
#

&voice_send("HELLO VOICE PROGRAM");

#
# Let's see if it worked
#

$answer=&voice_receive;
if ( $answer ne 'READY' )
{
    die "$0: initialization failed ($answer)\n";
}

#
# Set the device
#

if ( $ARGV[0] eq 'dialup' )
     { &voice_send('DEVICE DIALUP_LINE'); }
else
     { &voice_send('DEVICE INTERNAL_SPEAKER'); }

#
# Let's see if it worked
#

$answer=&voice_receive;
if ( $answer ne 'READY' )
{
    die "$0: could not set output device ($answer)\n";
}

#
# Let's send demo.rmd if it exists
#

if ( -f 'demo.rmd' )
{
     &voice_send('PLAY demo.rmd');

     #
     # Let's see if it works
     #

     $answer=&voice_receive;
     if ( $answer ne 'PLAYING' )
     {
          die "$0: could not start playing ($answer)";
     }

     $answer=&voice_receive;
     if ( $answer ne 'READY' )
     {
          die "$0: something went wrong on playing ($answer)";
     }
}

#
# Let's record a new demo.rmd if we are connected to the dialup
# line
#

if ( $ARGV[0] eq 'dialup' )
{
    #
    # Let's send a beep
    #

    &voice_send('BEEP');

    #
    # Let's see if it works
    #

    $answer=&voice_receive;
    if ( $answer ne 'BEEPING' )
    {
	die "$0: could not send a beep ($answer)";
    }

    $answer=&voice_receive;
    if ( $answer ne 'READY' )
    {
        die "$0: could not send a beep ($answer)";
    }

    #
    # Let's start the recording
    #

    &voice_send('RECORD demo.rmd');

    #
    # Let's see if it works
    #

    $answer=&voice_receive;
    if ( $answer ne 'RECORDING' )
    {
        die "$0: could not start recording ($answer)" >&2
    }

    $answer=&voice_receive;
    if ( $answer ne 'READY' )
    {
        die "$0: something went wrong on recording ($answer)" >&2
    }

    #
    # Let's send a final beep
    #
    &voice_send('BEEP');

    #
    # Let's see if it works
    #

    $answer=&voice_receive;
    if ( $answer ne 'BEEPING' )
    {
	die "$0: could not send a beep ($answer)";
    }

    $answer=&voice_receive;
    if ( $answer ne 'READY' )
    {
        die "$0: could not send a beep ($answer)";
    }
}
#
# Let's say goodbye
#

&voice_send('GOODBYE');

#
# Let's see if the voice library got it
#

$answer=&voice_receive;
if ( $answer ne 'GOODBYE SHELL' )
{
     die "$0: could not say goodbye to the voice library ($answer)";
}

exit 0;
