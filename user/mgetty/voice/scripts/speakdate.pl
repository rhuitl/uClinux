#!/usr/bin/perl

# This script is responsible for creating a date stamp.
# It should be installed in your voice directory as `speakdate'
# if you have perl and the rsynth synthesizer installed.
#
# Input: a filename, passed as $1
#
# Output: a voice file on STDOUT, e.g. adpcm3

$amp = 2.5;

@wdays = ('Sunday','Monday','Tuesday','Wednesday',
       'Thursday','Friday','Saturday');

@months = ('January','February','March','April','May','June','July',
        'August','September','October','November','December');

@ordnum = ('zeroth','first','second','third','fourth','fifth',
        'sixth','seventh','eighth','ninth','tenth',
        'eleventh','twelfth','thirteenth','fourteenth','fifteenth',
        'sixteenth','seventeenth','eighteenth','nineteenth','twentieth');

sub ordinal {
# this routine only works for n=0..39.
    local($n)=@_[0];
    if ($n <= 20) {
     $ordnum[$n];
    } elsif ($n < 30) {
     "twenty " . $ordnum[$n-20];
    } elsif ($n == 30) {
     "thirtieth";
    } else {
     "thirty " . $ordnum[$n-30];
    }
}

sub etime {
    local($h, $m) = (@_[0], @_[1]);
    local($hr, $min, $exactly);

    if ($h==0) {
     $hr="12";
    } elsif ($h <= 12) {
     $hr=$h;
    } else {
     $hr=($h-12);
    }

    if ($m==0) {
     $min="";
     $exactly=" exactly";
    } elsif ($m < 10) {
     $min="oh " . $m;
    } else {
     $min=$m;
    }

    $hr . " " . $min . " " . ($h<12 ? "A M" : "P M") . $exactly;
}

($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
     $atime,$mtime,$ctime,$blksize,$blocks) = stat($ARGV[0]);

($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($mtime);

$msg = $wdays[$wday]. ", ". $months[$mon]. " ". &ordinal($mday) .
     " at ". &etime($hour,$min);

$cmd = "say \"$msg\" -r 9600 -L -l - "
     . "| lintopvf | pvfcut -0.5 0 | pvfamp $amp | pvftozyxel3";

#print STDERR $cmd, "\n";
exec $cmd;
