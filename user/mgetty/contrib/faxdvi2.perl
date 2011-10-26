#!/usr/local/bin/perl
#
# faxdvi2 -- pass a DVI file to the FAX subsystem.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Ralph Schleicher
# 241:10000/1513@PNoF
# rs@purple.PNoF.sub.org


$config_file = '/usr/local/lib/mgetty+sendfax/faxdvi.config';
$user_file = "$ENV{'HOME'}/.faxdvirc";

$dvips = 'dvips -t letter -P fax';
$gs = 'gs -sPAPERSIZE=letter -sDEVICE=dfaxhigh';


$version_string = 'FAXDVI2 Version 1.0 (Perl)';

sub usage
{
  print <<STOP

Usage:  faxdvi2 [-C <file-name>] [-V] [-?] [- <stuff>]
		<phone-number> <dvi-file>

	-C, --config-file
		Use <file-name> as the configuration file instead of the
		default `$config_file'.
	-V, --version
		Displays the version number.
	-?, --help
		Prints this small help.
	-, --
		Pass <stuff> verbatim to DVIPS.
	<phone-number>
		A real phone number or a FAX alias.
	<dvi-file>
		You name it.

STOP
}

{}

# Get the command line options.
#
while (($_ = $ARGV[0]) =~ /^-/)
  {
    shift;

    if ($_ eq '-C' || $_ eq '--config-file')
      {
	$config_file = shift @ARGV;

	die "$0: Missing option argument for `$_'\n"
	  if $config_file =~ /^-/;
      }
    elsif ($_ eq '-V' || $_ eq '--version')
      {
	$version = 1;
	$exit = 0;
      }
    elsif ($_ eq '-?' || $_ eq '--help')
      {
	$help = 1;
	$exit = 0;
      }
    elsif (/^--?$/)
      {
	push (@DVIPS, shift @ARGV)
	  while @ARGV > 2;

	last;
      }
    else
      {
	die "$0: Unknown option `$_', try `--help'\n";
      }
  }

if (@ARGV == 2)
  {
    $phone_number = $ARGV[0];
    $dvi_file = $ARGV[1];
  }
elsif ($exit eq '')
  {
    $help = 1;
    $exit = 1;
  }

print "\nThis is $version_string\n\n"
  if $version;
&usage
  if $help;
exit $exit
  if $exit ne '';

# Read the configuration files.
#
sub configure
{
  local ($config) = @_;
  local (*CONF);

  open (CONF, $config)
    || die "$0:$config: $!\n";

  foreach (<CONF>)
    {
      next if /^\s*#/;
      next if /^\s*$/;

      chop;

      $comment{$1} = $3, $alias{$1} = $4, next
	if /^alias\s+(\S+)\s+(\((.*)\)\s+)?(.+)/;

      push (@dialtrans, $1), next
	if /^dialtrans\s+(.+)/;

      die "$0:$config:$.: Bad line\n";
    }

  close (CONF);
}

&configure ($config_file)
  if $config_file ne '';

&configure ($user_file)
  if -f $user_file;

# Do alias substitution and phone number translation.
#
foreach (grep ($alias{$_} =~ /^\|/, keys %alias))
  {
    ($command = $alias{$_}) =~ s/^\|//;
    $command =~ s/@/$comment{$_}/
      if $comment{$_} ne '';
    $alias{$_} = `$command`;
    chop $alias{$_};

    die "$0: Command alias for `$_' evaluates to null\n"
      if $alias{$_} =~ /^\s*$/;
  }

for (@work = ($phone_number); @work > 0; ++$done{shift @work})
  {
    unshift (@work, split (',', $alias{shift @work}))
      while $alias{$work[0]} ne '';
  }

foreach $num (keys %done)
  {
    foreach $rule (@dialtrans)
      {
	if ($num =~ (split (substr ($rule, 0, 1), $rule))[1])
	  {
	    eval "\$num =~ s$rule";
	    die "$0: $@\n"
	      if $@ ne '';

	    last;
	  }
      }

    push (@number, $num);
  }

# Convert the DVI file into G3 format.
#
$temp_dir = "/tmp/faxdvi2.$$";

mkdir ($temp_dir, 0755)
  || die "$0:$temp_dir: $!\n";

sub cleanup
{
  local ($sig) = @_;
  local (*DIR);

  opendir (DIR, $temp_dir);
  unlink grep ($_ = "$temp_dir/$_", grep (! /^\.\.?$/, readdir (DIR)));
  closedir (DIR);

  rmdir ($temp_dir);

  exit ($sig eq '') ? 0 : 1;
}

$SIG{'HUP'} = 'cleanup';
$SIG{'INT'} = 'cleanup';
$SIG{'QUIT'} = 'cleanup';
$SIG{'PIPE'} = 'cleanup';
$SIG{'TERM'} = 'cleanup';

open (NULL, ">/dev/null")
  || die "$0:/dev/null: $!\n";
open (SAVOUT, ">&STDOUT")
  || die "$0:(stdout): $!\n";
open (STDOUT, ">&NULL")
  || die "$0:(stdout): $!\n";
open (SAVERR, ">&STDERR")
  || die "$0:(stderr): $!\n";
open (STDERR, ">&NULL")
  || die "$0:(stderr): $!\n";

sub bye
{
  open (STDOUT, ">&SAVOUT");
  open (STDERR, ">&SAVERR");

  warn @_;
  &cleanup;
}

$output = join ('/', ($temp_dir, 'f'));

system ("$dvips @DVIPS -o $output $dvi_file")
  && &bye ("$0: DVIPS failed on `$dvi_file'\n");

system ("$gs -dNOPAUSE -sOUTPUTFILE=$output%07d.g3 $output quit.ps")
  && &bye ("$0: Ghostscript failed for some reason\n");

opendir (DIR, $temp_dir)
  || &bye ("$0:$temp_dir: $!\n");
@pages = grep ($_ = "$temp_dir/$_", grep (/\.g3$/, readdir (DIR)));
closedir (DIR);

foreach (@number)
  {
    system ("faxspool $_ @pages\n")
      && &bye ("$0: Sending `$dvi_file' to `$_' failed\n");
  }

&cleanup;
