#! /bin/sh

# This script is responsible for speaking out a date stamp.
# It should be installed in your voice directory once you got
# it working correctly.
#
# Input:  $1 - filename for which the date information should be spoken out
#         $2 - sample speed
#         $3 - modem type
#         $4 - compression type
#
# Output: rmd voice file on stdout
#
# This implementation uses GNU find and the rsynth synthesizer.

AMP=3.5
MSG=`find $1 -printf 'This message was recorded on %TA, %TB %Td, at %Tk %TM.\n'`
SPEED=$2
MODEM_TYPE=$3
COMPRESSION=$4

#
# This if for my old rsynth version...
#

say "$MSG" -r $SPEED -L -l - 2>/dev/null | lintopvf -s $SPEED | \
 pvfcut -H -0.5 | pvfamp -A $AMP | pvftormd $MODEM_TYPE $COMPRESSION

#
# This is for rsynth 2.0
#

# say "$MSG" -a -r $SPEED -l - 2>/dev/null | autopvf | \
#  pvftormd $MODEM_TYPE $COMPRESSION
