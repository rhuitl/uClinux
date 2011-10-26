#!/usr/bin/perl

#
# this program processes a bunch of directories routed at
# $REGRESSRESULTS. Each one is examined for a file "status"
# the result is an HTML table with the directory name as 
# left columns (it is the implied test name), and the status 
# on the right.
#
# if the test status is negative, then the results are a hotlink
# to that directory's output.
#
# The test names are links to the file "description.txt" if it
# exists.
#

require 'ctime.pl';

# colours are RRGGBB
$failedcolour="#990000";
$succeedcolour="#009900";
$missingcolour="#000099";

$failed=0;
$passed=0;
$missed=0;
$total=0;

@faillist=();

sub htmlize_test {
  local($testname)=@_;

  if(-f "$testname/description.txt") {
    print HTMLFILE "<TR><TD><A HREF=\"$testname/description.txt\">$testname</A></TD>\n";
  } else {
    print HTMLFILE "<TR><TD>$testname</TD>\n";
  }

  if(open(STATUS,"$testname/status")) {
    $total++;
    chop($result=<STATUS>);
    if($result =~ /(Yes|True|1|Succeed|Passed)/i) {
      $result=1;
      $link="<FONT COLOR=\"$succeedcolour\">passed</FONT>";
      $passed++;
    } else {
      $result=0;
      $link="<FONT COLOR=\"$failedcolour\">FAILED</FONT>";
      if(-d "$testname/OUTPUT") {
	$output="$testname/OUTPUT";
	$link="<A HREF=\"$output\">$link</A>";
      }
      push(@faillist, $testname);
      $failed++;
    }
    close(STATUS);
  } else {
    $link="<FONT COLOR=\"$missingcolour\">missing</FONT>";
    if(-d "$testname/OUTPUT") {
      $output="$testname/OUTPUT";
      $link="<A HREF=\"$output\">$link</A>";
    }
    $missed++;
  }

  print HTMLFILE "<TD>$link</TD>";

  if(-f "$testname/regress.txt") {
    open(PROBREPORT, "$testname/regress.txt") || die "$testname/regress.txt: $!\n";
    chop($prnum=<PROBREPORT>);
    close(PROBREPORT);
    print "<TD><A HREF=\"http://gnats.freeswan.org/bugs/gnatsweb.pl?database=freeswan&cmd=view+audit-trail&pr=$prnum\">PR#$prnum</A></TD>";

  } elsif(-f "$testname/goal.txt") {
    open(GOALREQ, "$testname/goal.txt") || die "$testname/regress.txt: $!\n";
    chop($goalnum=<GOALREQ>);
    close(GOALREQ);

    $goalnum=sprintf("%03d", $goalnum);
    print "<TD><A HREF=\"http://www.freeswan.org/freeswan_snaps/CURRENT-SNAP/klips/doc/klipsNGreq/requirements/$goalnum\">Requirement $goalnum</A></TD>";

  } elsif(-f "$testname/exploit.txt") {
    open(EXPLOIT, "$testname/exploit.txt") || die "$testname/exploit.txt: $!\n";
    chop($url=<EXPLOIT>);
    close(EXPLOIT);

  } else {
    # test not categorized, output nothing.
  }

  print HTMLFILE "</TR>\n";
}

# the test names are sorted.

$REGRESSRESULTS=$ENV{'REGRESSRESULTS'};

if(defined($ARGV[0])) {
  $REGRESSRESULTS=$ARGV[0];
}

if( ! -d $REGRESSRESULTS ) {
  die "No such directory $REGRESSRESULTS.";
}

chdir($REGRESSRESULTS);

opendir(TESTS,".") || die "opendir $REGRESSRESULTS: $!\n";
@tests=readdir(TESTS);
closedir(TESTS);

@testnames=sort @tests;

#
# make pass through the tests, categorizing them.
#
@regresstests=();
@goaltests=();
@exploittests=();
foreach $testname (@testnames) {
  if(-f "$testname/regress.txt") {
    push(@regresstests,$testname);
  } elsif(-f "$testname/goal.txt") {
    push(@goaltests, $testname);
  } elsif(-f "$testname/exploit.txt") {
    push(@exploittests, $testname);
  } else {
    push(@regresstests,$testname);
  }
}

if(open(DATE, "datestamp")) {
  chop($timestamp=<DATE>);
  close(DATE);
  $runtime=&ctime($timestamp);
} else {
  $runtime="an unknown time";
}
$hostname=`uname -n`;

open(HTMLFILE, ">testresults.html") || die "Can not open testresults.html: $!\n";

print HTMLFILE "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n";
print HTMLFILE "<HTML>  <HEAD>\n";
print HTMLFILE "<TITLE>FreeSWAN nightly testing results for $runtime</TITLE>\n";
print HTMLFILE "</HEAD>  <BODY>\n";
print HTMLFILE "<H1>FreeSWAN nightly testing results for $runtime on $hostname</H1>\n";
print HTMLFILE "<TABLE>\n";

print HTMLFILE "<TR COLSPAN=3>Regression tests</TR>\n";
print HTMLFILE "<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n";

foreach $testname (@regresstests) {
  next if($testname =~ /^\./);
  next unless(-d $testname);

  &htmlize_test($testname);
}

print HTMLFILE "<TR COLSPAN=3>Goal tests</TR>\n";
print HTMLFILE "<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n";

foreach $testname (@goaltests) {
  next if($testname =~ /^\./);
  next unless(-d $testname);

  &htmlize_test($testname);
}

print HTMLFILE "<TR COLSPAN=3>Exploits</TR>\n";
print HTMLFILE "<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n";

foreach $testname (@exploittests) {
  next if($testname =~ /^\./);
  next unless(-d $testname);

  &htmlize_test($testname);
}

print HTMLFILE "</TABLE>  \n";
print HTMLFILE "\n<BR><PRE>TOTAL tests: $total   PASSED: $passed   FAILED: $failed   MISSED: $missed  SUCCESS RATE: %".sprintf("%2.1d",(($passed*100)/$total))."</PRE><BR>\n";
print HTMLFILE "<A HREF=\"stdout.txt\">stdout</A><BR>\n";
print HTMLFILE "<A HREF=\"stderr.txt\">stderr</A><BR>\n";
print HTMLFILE "</BODY></HTML>\n";
close(HTMLFILE);

open(FAILLIST, ">faillist.txt") || die "failed to write to faillist.txt: $!\n";
print FAILLIST join('\n', @faillist)."\n";
close(FAILLIST);




