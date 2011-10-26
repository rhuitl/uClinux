#! /bin/sh
# Convert from WAV to RMD format, including stereo.
# $Id: convert_wav_to_rmd.sh,v 1.2 2000/07/22 09:57:46 marcs Exp $

# NOTES
#    - This is no longer required since vgetty 0.9.11. Now vgetty
#      supports correct WAV conversion.

if [ $# != 1 ]; then
   echo "$0: bad args."
   exit 2
fi

SOX=~/ported/sox10p11/sox
PVFTOOLS=/usr/lib/mgetty/pvftools/
SPEED=11025
MODEM_BRAND=ZyXEL_2864
MODEM_BRAND_RESOLUTION=4

FNAME=$1
TMP_FNAME=/tmp/convert_$$

# Merge into one channel (maybe that could be done merged)
$SOX -t wav $FNAME -t wav -c 1 $TMP_FNAME

$PVFTOOLS/wavtopvf < $TMP_FNAME | $PVFTOOLS/pvfspeed -s $SPEED | $PVFTOOLS/pvftormd $MODEM_BRAND $MODEM_BRAND_RESOLUTION > $FNAME.rmd

rm -f $TMP_FNAME
