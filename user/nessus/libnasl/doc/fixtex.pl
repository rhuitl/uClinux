#!/usr/bin/perl -w

$f = 1;
while (<>) {
  print;
  if ($f && /^\\documentclass/) {
    print '\ifx\pdfoutput\undefined\else\usepackage{times}[12pt]\fi';
    print "\n";
    $f = 0;
  }
}
