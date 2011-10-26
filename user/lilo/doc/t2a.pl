#!/usr/bin/perl
#
# Copyright 1994-1996 Werner Almesberger.
# All rights reserved.
#
# See file COPYING for details.
#
#-----------------------------------------------------------------------------
#
# Known bugs:
#
#   Usually doesn't check for prepended backslashes, e.g. things like
#   \\begin{verbatim} would be processed incorrectly.
#
#   Tokenization should be done once at the beginning, not on the fly
#   with cleanup and check procedures at the end of each step.
#
#-----------------------------------------------------------------------------
#
$w = 75;
#
# default macros
#
$m{"\\\\ldots"} = "...";
#
# read the file
#
print STDERR "[".length($t)."] Reading the file\n";
$/ = "\000";
$t = "\n".<>."\n";
#
# universal markers
#
$N = "\000";	# non-character
$X = "\007";	# generic marker
$Y = "\010";	# another generic marker
$Z = "\011";	# yet another generic marker
$B = "\001";	# begin
$E = "\002";	# end
$BS = "\013";	# second begin
$ES = "\014";	# second end
$CO = "\003";	# curly open
$CC = "\004";	# curly close
#
# commands to the output formatter
#
$SI = "\020";	# increase indentation by one
$SO = "\021";	# decrease indentation by one
$B1 = "\022";	# one blank line
$B2 = "\023";	# two blank lines

sub xlat
{
    local ($l) = @_;

    $l =~ tr/~/ /;
    $l =~ s/\\([_~&%^\$\#\[\]|\-])/\1/g;# unescape special characters
    $l =~ s/\\,//g;			# remove small spaces
    $l =~ s/\\backslash */$X/g;		# \backslash ->\
    if ($l =~ /\\([A-Za-z]+|.)/) {
	warn "unrecognized command $& ($l)";
	$l = $`."\n!!! UNRECOGNIZED COMMAND: $&\n$'";
    }
    $l =~ s/$X/\\/g;
    $l =~ tr/{}//d;			# delete stray curly braces
    $l =~ s/$CO/{/g;			# put escaped braces back
    $l =~ s/$CC/}/g;
    return $l;
}


#
# load macros
#
print STDERR "[".length($t)."] Loading macros\n";
while ($t =~ /\n%%(def|cmd)([^\n]*)\n/) {
    $t = $`."\n".$';
    $a = $1;
    $2 =~ /([^\\])=/ || die "= missing in $2";
    if ($a eq "def") {
	$m{$`.$1} = $';
	$c{$`.$1} = "";
    }
    else {
	$m{$`.$1} = "";
	$c{$`.$1} = $';
    }
}
#
# remove %%beginskip ... %%endskip pairs
#
print STDERR "[".length($t)."] Removing %%beginskip ... %%endskip pairs\n";
while ($t =~ /\n%%beginskip\s*\n/) { $t = $`.$B.$'; }
while ($t =~ /\n%%endskip\s*\n/) { $t = $`.$E.$'; }
while ($t =~ /$B[^$B$E]*$E/) { $t = $`."\n".$'; }
$t !~ /[$B$E]/ || die "%%beginskip/%%endskip mismatch";
#
#  process macros
#
print STDERR "[".length($t)."] Processing macros (may take a while)\n";
while (1) {
    $none = 1;
    for (keys %m) {
	while ($t =~ /$_/) {
	    $none = 0;
	    if ($c{$_} eq "") {
		eval "\$t = \$`.\"$m{$_}\".\$';";
	    }
	    else {
		eval "\$t = \$`.$c{$_}.\$';";
	    }
	    die "syntax error: $@" if $@;
	}
    }
    last if $none;
    print STDERR "[".length($t)."] "."  next pass\n";
# perfectionist's approach:
#    $l = 0;
#    for (keys %m) {
#	if ($t =~ /$_/) {
#	    if (length($&) > $l) {
#		$i = $_;
#		$l = length($&);
#	    }
#	}
#    }
#    last if !$l;
#    $t =~ /$i/ || die "internal error";
#    eval "\$t = \$`.\"$m{$i}\".\$'";
#    die "syntax error: $@" if $@;
#    print STDERR "[".length($t)."] "."$i\n";
}
#
# handle verbatim sections (we're not trying to be perfect here)
#
print STDERR "[".length($t)."] Handling verbatim sections\n";
while ($t =~ /\\begin{verbatim}([ \t]*\n)?/) { $t = $`."\n\n".$B.$'; }
while ($t =~ /\\end{verbatim}([ \t]*\n)?/) { $t = $`.$E."\n\n".$'; }
while ($t =~ /\\verb([^a-zA-Z \t\n])/ && $t =~ /\\verb$1([^$1]*)$1/) {
    $t = $`.$B.$1.$E.$';
}
while ($t =~ /$B([^$B$E]*)$E/) {
    ($a,$b,$c) = ($`,$1,$');
    die "no support for \\t yet, sorry" if $b =~ /\t/;
    $b =~ s/\\/\\backslash /g;
    $b =~ s/[~^_%#&{}\$\-]/\\$&/g;
    $b =~ s/[`']/\\$&~/g;
    $b =~ s/ /~/g;
    $b =~ s/\n\n\n/$B2/g;
    $b =~ s/\n\n/$B1/g;
    $b =~ s/\n/\\\\/g;
    $t = $a.$b.$c;
}
if ($t =~ /[$B$E]/) {
    if ($t =~ /..........[$B$E]........../) { print STDERR "$&\n"; }
    die "verbatim conflict";
}
#
# hide escaped curly braces
#
print STDERR "[".length($t)."] Hiding escaped curly braces\n";
$t =~ s/\\{/$CO/g;
$t =~ s/\\}/$CC/g;
#
# discard comments and italic corrections
#
print STDERR "[".length($t)."] Discarding comments and italic corrections\n";
while ($t =~ s/([^\\])%[^\n]*\n/$1/g) {};
$t =~ s|\\/||g;
#
# no math mode
#
print STDERR "[".length($t)."] No math mode\n";
while ($t =~ s/([^\\])\$/$1/g) {};
#
# remove tabs and massage blanks
#
print STDERR "[".length($t)."] Removing tabs and massaging blanks\n";
$t =~ s/\\ / /g;	# \cmd\ blah
$t =~ tr/ \t/ /s;
#
# various minor issues
#
print STDERR "[".length($t)."] Dealing with various minor issues\n";
$t =~ s/\\rightarrow\s*/->/g;
$t =~ s/\\quad\s*/~/g;
$t =~ s/\\qquad\s*/~~/g;
$t =~ s/\\vert/|/g;
$t =~ s/\\TeX/TeX/g;
$t =~ s/\\LaTeX/LaTeX/g;
$t =~ s/\\rm\s*//g;
$t =~ s/\\hbox{/{/g;
$t =~ s/\\protect//g;
$t =~ s/\\newpage\s*//g;
$t =~ tr/-/-/s;
$t =~ s/\n\n+/$B1/g;
while ($t =~ /\\cite{([^}]+)}/) {
    $t = $`."[";
    $after = $';
    for (split(",",$1)) {
	if (defined $cite{$_}) { $t .= "$cite{$_},"; }
	else {
	    $cite{$_} = ++$citation;
	    $bibref[$citation] = $_;
	    $t .= "$citation,";
	    die "unmatched ref $_" unless $after =~ /\\bibitem{$_}/;
	    $after = $`."\\item[\[$citation\]] ".$';
	}
    }
    $t =~ s/,$//;
    $t .= "]$after";
}
$t =~
  s/\\begin{thebibliography}{[^}]*}/\\section{References}\\begin{description}/;
$t =~ s/\\end{thebibliography/\\end{description}/;
#
# handle footnotes
#
print STDERR "[".length($t)."] Handling footnotes\n";
$t =~ s/\\footnote{/\\footnotemark\\footnotetext{/g;
$t =~ s/\\footnotemark/$X/g;
$t =~ s/\\footnotetext{/$Y/g;
while ($t =~ /$X([^$Y]*)$Y/) {
    ($a,$b,$c) = ($`,$',$1);
    $t =~ /^[^$Y]*$Y$B1/;
    $d = $';
    for ($s = "*"; $d =~ /$Z/; $d = $`.$Y.$') { $s .= "*"; }
    $a = $a.$s.$c;
    while ($b =~ /^([^}]*){([^{}]*)}/) { $b = $`.$1.$B.$2.$E.$'; }
    $b =~ /^([^{}]*)}/ || die "{ } confusion";
    ($b,$t) = ($1,$');
    $b =~ s/$B/{/g;
    $b =~ s/$E/}/g;
    $d = "$B1$Z\\begin{description}\\item[$s] $b\\end{description}$B1";
    if ($t =~ /$B1([^$Z][^$N]*)$/) { $t = $`.$d.$1; }
    else { $t = $t.$d; }
    $t = $a.$t;
}
$t =~ s/$Z//g;
if ($t =~ /[$X$Y$Z$B$E]/) {
    if ($t =~ /..............[$X$Y$Z$B$E]/) { print STDERR "HEY $&\n"; }
    die "footnote confusion";
}
#
# process simple tables ...
#
print STDERR "[".length($t)."] Processing simple tables\n";
while ($t =~ /\\begin{tabular}/) { $t = $`.$B.$'; }
while ($t =~ /\\end{tabular}/) { $t = $`.$E.$'; }
while ($t =~ /$B\{([rlc|]+)\}([^$B$E]*)$E/) {
    ($a,$b,$c,$d) = ($`,$',$2,$1);
    $c =~ s/\\\\/&/g;
    $c =~ s/[\s\n]*\\hline[\s\n]*/$X&/g;
    ($e = $d) =~ tr/|//cd;
    @d = ();
    while ($d =~ /^(\|*)[a-z](\|*)/) {
	push(@d,$&);
	$d = $';
    }
    @f = ();
    while ($c =~ /([^\\])&/) {
	push(@f,$`.$1);
	$c = $';
    }
    @w = ();
    $d =~ tr/|//d;
    $i = 0;
    for (@f) {
	next if $_ eq $X;
	$f = $i % @d;
	$_ = &xlat($_);
	$_ =~ s/^[\s\n]*//g;
	$_ =~ s/[\s\n]*$//g;
	if ($w[$f] < length($_)) { $w[$f] = length($_); }
	$i++;
    }
    $l = @d+2*length($e)-1;
    for (@w) { $l += $_; }
    $a .= "$B1";
    $i = 0;
    for (@f) {
	if ($_ eq $X) { $a .= ("-" x $l)."\\\\"; }
	else {
	    $f = $i % @d;
	    if ($d[$f] =~ /^\|/) { $a .= "| "; }
	    $g = $w[$f]-length($_);
	    if ($d[$f] =~ /l/) { $a .= $_.("~" x $g); }
	    if ($d[$f] =~ /c/) {
		$a .= ("~" x int($g/2)).$_.("~" x ($g-int($g/2)));
	    }
	    if ($d[$f] =~ /r/) { $a .= ("~" x $g).$_; }
	    $a .= " ";
	    if ($d[$f] =~ /\|$/) { $a .= "| "; }
	    if ($f == $#d) { $a .= "\\\\"; }
	    $i++;
	}
    }
    $t = $a.$b.$B1;
}
if ($t =~ /[$B$E$X]/) {
    if ($t =~ /(.|\n)(.|\n)(.|\n)(.|\n)(.|\n)(.|\n)[$B$E$X](.|\n)(.|\n)(.|\n)(.|\n)(.|\n)(.|\n)/) { print STDERR "$&\n"; }
    die "\\begin/end{tabular} mismatch";
}
#
# process lists
#
print STDERR "[".length($t)."] Formatting lists\n";
while ($t =~ /\\begin{itemize}\s*/) { $t = $`.$B.$'; }
while ($t =~ /\\end{itemize}\s*/) { $t = $`.$E.$'; }
while ($t =~ /$B[^$B$E]*$E/) {
    ($a,$b,$c) = ($`,$&,$');
    while ($b =~ /\\item\s*/) { $b = $`.$X.$'; }
    while ($b =~ /$X([^$X]*)([$X$E])/) {
	$b = $`."- ".$SI.$SI.$1.$SO.$SO."\\\\"."$2".$';
    }
    $b =~ /$B([^$B$E]*)$E/;
    $t = $a.$SI.$SI.$B1.$1.$SO.$SO."$B1".$c;
}
$t !~ /[$B$E]/ || die "\\begin/\\end{itemize} mismatch";
while ($t =~ /\\begin{description}\s*/) { $t = $`.$B.$'; }
while ($t =~ /\\end{description}\s*/) { $t = $`.$E.$'; }
while ($t =~ /$B[^$B$E]*$E/) {
    ($a,$b,$c) = ($`,$&,$');
    while ($b =~ /\\item\[/) { $b = $`.$X."[".$'; }
    while ($b =~ /$X\[/) {
	($d,$e) = ($`,$');
	while ($e =~ s/\[([^\[\]]*)\]/$BS$1$ES/g) {};
	$e =~ /^([^\[\]]*)]\s*([^$X]*)([$X$E])/ || die "\item problem (1)";
	$b = $d.$1."~~".$SI.$SI.$2.$SO.$SO."\\\\".$3.$';
	$b =~ s/$BS/[/g;
	$b =~ s/$ES/]/g;
    }
    $b =~ /$B([^$B$E]*)$E/;
    $t = $a.$SI.$SI.$B1.$1.$SO.$SO.$B1.$c;
}
$t !~ /[$X]/ || die "\item problem (2)";
$t !~ /[$B$E]/ || die "\\begin/\\end{description} mismatch";
#
# process figures
#
print STDERR "[".length($t)."] Removing figures\n";
while ($t =~ /\\begin{figure}\s*/) { $t = $`.$B.$'; }
while ($t =~ /\\end{figure}\s*/) { $t = $`.$E.$'; }
while ($t =~ /$B[^$B$E]*$E/) {
    ($a,$b,$c) = ($`,$&,$');
    $t = $a."[ Figure";
    if ($b =~ /\\label{([^}]*)}/) {
	$l{$1} = ++$figref;
	$t .= " $figref";
    }
    if ($b =~ /\\caption{([^}]*)}/) {
	$t .= ": $1";
    }
    $t .= " ]".$c;
}

#
# process sections and labels
#
print STDERR "[".length($t)."] Processing sections and labels\n";
$t =~ s/\\begin{abstract}/\\section{Abstract}/g;
$t =~ s/\\end{abstract}//g;
$LB = "\005";	# they don't necessarily have to be unique
$SC = "\006";
while ($t =~ /\\label{/) { $t = $`.$LB."{".$'; }
while ($t =~ /\\((sub)*)section\*?{/) { $t = $`.$SC.$1."{".$'; }
$l = "";
while (1) {
    if ($t =~ /^([^$LB$SC]*)$LB\{([^{}]*)\}/) {
	$l{$2} = '"'.$l.'"';
	$t = $1.$';
    }
    if ($t =~ /$SC((sub)*){/) {
	($a,$b,$c) = ($`,$',$1);
	while ($b =~ /^([^}]*){([^{}]*)}/) { $b = $`.$1.$B.$2.$E.$'; }
	$b =~ /^([^{}]*)}\s*/ || die "{ } confusion";
	($b,$d) = ($1,$');
	$b =~ s/$B/{/g;
	$b =~ s/$E/}/g;
	$l = $b;
	$b = &xlat($b);
	if (($u = ("=","-","- ","")[length($c)/3]) ne "") {
	    $u = "\\\\".substr($u x length($b),0,length($b));
	}
        $t = $a.$B2.$b.$u.$B1.$d;
    }
    else {
	last;
    }
}
#
# handle references
#
print STDERR "[".length($t)."] Handling references\n";
$t =~ s/[Pp]age \\pageref({[^{}]*})/\\ref$1/g;
$t =~ s/\\pageref{[^{}]*}/???/g;
while ($t =~ /\\ref{([^{}]*)}/) {
    $t = $`.(defined($l{$1}) ? $l{$1} : "???").$';
}
#
# collapse whitespace
#
print STDERR "[".length($t)."] Collapsing whitespace\n";
$t =~ s/\\par\s*/\n\n/g;
$t =~ s/ *(\n+) */$1/g;
$t =~ tr/\n/ /;
$t =~ tr/ \t/ /s;	# again
#
# handle line breaks
#
print STDERR "[".length($t)."] Handling line breaks\n";
$t =~ tr/\n//d;
$t =~ s/\\\\/\n/g;
$t =~ s/\\par\s*/$B1/g;
#
# handle accents, umlauts, and double quotes
#
print STDERR "[".length($t)."] Handling accents, umlauts, double quotes ".
  "and hyphens\n";
$t =~ s/\\[`']([AEOUaeou])/$1/g;
$t =~ s/\\([`'])~/$1/g;
$t =~ s/\\"([AOUaou])/$1e/g;
$t =~ s/``/"/g;
$t =~ s/''/"/g;
#
# apply ultimate set of fixes to newlines
#
print STDERR "[".length($t)."] Applying ultimate set of fixes to newlines\n";
while ($t =~ s/([\n$B1$B2]+)([$SI$SO])/$2$1/g) {};
$t =~ s/([\n$B1$B2]*)\s+([\n$B1$B2]+)/$1$2/g;
$t =~ s/\n+/\n/g;
$t =~ s/\n?($B1)[\n$B1]*/\n\n/g;
$t =~ s/\n*($B2)[\n$B2]*/\n\n\n/g;
#
# translate what's left
#
print STDERR "[".length($t)."] Final translation\n";
$t = &xlat($t);
$t =~ s/^\s*//;
$t =~ s/\s*$//;
$t .= "\n";
#
# okay, now format and print it
#
print STDERR "[".length($t)."] "."Formatting (may take a while)\n";
$l = "";
$m = 0;
while ($t =~ /([$SI$SO\n]| +)/) {
    if ($` ne "" || substr($1,0,1) eq " ") {
	if (length($l)+length($`) > $w && $l ne "") {
	    print $l."\n";
	    $l = "";
	}
	if ($l eq "") { $l = " " x $m; }
	$l = $l.$`.(substr($1,0,1) eq " " ? $1 : "");
    }
    $t = $';
    if ($1 eq $SI) { $m++; }
    if ($1 eq $SO) { $m--; }
    if ($1 eq "\n") {
	print $l."\n";
	$l = "";
#	$t = s/^ *(\S.*)/\1/;
    }
}
print "$l\n" if $l ne "";
print STDERR "Done\n";
