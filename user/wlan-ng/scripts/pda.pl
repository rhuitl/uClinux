#!/usr/bin/perl

use Getopt::Long;
GetOptions(qw(pda! diff! repl! xdiff=s));

sub usage {
  print(q{
Usage:
pda.pl pdafile 
or
pda.pl --pda --diff --xdiff=0x0104,0x0007 pda1 pda2 > diff-pda1-pda2.pda

--diff     takes 2 filenams and prints a diff (2nd file will override the first on
           records that are present in both
--pda      saves output suitable for loading via prism2dl (mainly for --diff)
--repl     generates merged PDA, that could be used as a replacement (prism2dl -p)
--xdiff    exclude given PDR's from beeing overridden by dst PDA => those will be
           generated from src pdafile (comma separated hexlist)
});
  exit(0);
} 

$pdr_codes = {
	0x0001 => 'PCB_PARTNUM', 0x0002 => 'PCB_TRACENUM', 0x0003 => 'NIC_SERIAL',
	0x0004 => 'MKK_MEASUREMENTS', 0x0005 => 'NIC_RAMSIZE', 0x0006 => 'MFISUPRANGE',
	0x0007 => 'CFISUPRANGE', 0x0008 => 'NICID', 0x0010 => 'REFDAC_MEASUREMENTS',
	0x0020 => 'VGDAC_MEASUREMENTS', 0x0030 => 'LEVEL_COMP_MEASUREMENTS',
	0x0040 => 'MODEM_TRIMDAC_MEASUREMENTS', 0x0101 => 'MAC_ADDRESS', 0x0102 => 'MKK_CALLNAME',
	0x0103 => 'REGDOMAIN', 0x0104 => 'ALLOWED_CHANNEL', 0x0105 => 'DEFAULT_CHANNEL',
	0x0106 => 'PRIVACY_OPTION', 0x0107 => 'TEMPTYPE', 0x0110 => 'REFDAC_SETUP',
	0x0120 => 'VGDAC_SETUP', 0x0130 => 'LEVEL_COMP_SETUP', 0x0140 => 'TRIMDAC_SETUP',
	0x0200 => 'IFR_SETTING', 0x0201 => 'RFR_SETTING', 0x0202 => 'HFA3861_BASELINE',
	0x0203 => 'HFA3861_SHADOW', 0x0204 => 'HFA3861_IFRF', 0x0300 => 'HFA3861_CHCALSP',
	0x0301 => 'HFA3861_CHCALI', 0x0900 => 'HFA3861_MANF_TESTSP', 0x0901 => 'HFA3861_MANF_TESTI',
	0x0000 => 'END_OF_PDA',
};

$pdr_fmt = {
   0x0001 => \&x2ascii_list, 0x0002 => \&x2ascii_list, 0x0003 => \&x2ascii_list,
   0x0101 => \&x2hex_list,   0x0103 => \&x2dec_list,   0x0104 => \&x2bit_list,
   0x0001 => \&x2ascii_list,
};

$srcfile=$ARGV[0];
$dstfile=$ARGV[1];

if (defined $opt_xdiff) {
  @xdiff = map {hex} split /\s*,\s*/, $opt_xdiff;
  print "@@ xdiff: $opt_xdiff\n";
}

if (!defined $srcfile) {
  usage();
}
$src=read_pda($srcfile);

if ($opt_diff) {
  if (!defined $dstfile) {
    usage();
  }
  $dst=read_pda($dstfile);

  map { $join{$_->{code}} = 1; $src{$_->{code}} = $_; } @$src;
  map { $join{$_->{code}} = 1; $dst{$_->{code}} = $_; } @$dst;

  for $code (sort {($a || $a+0x1000) <=> ($b || $b+0x1000)} keys %join) {
    if (!defined $dst{$code}) {
       push @{$diff{src}}, $src{$code};
    } elsif (!defined $src{$code}) {
       push @{$diff{dst}}, $dst{$code};
    } elsif ($src{$code}{data} ne $dst{$code}{data}) {
       push @{$diff{diff}}, [$src{$code}, $dst{$code}];
    } else {
       push @{$diff{same}}, [$src{$code}, $dst{$code}];
    }
  }
  print "@@ Only in $srcfile:\n";
  for my $pdr (@{$diff{src}}) {
    print_pdr($pdr, {prefix=>$opt_pda && !$opt_repl ? "#- " : ""});
  }
  print "@@ Only in $dstfile:\n";
  for my $pdr (@{$diff{dst}}) {
    print_pdr($pdr);
  }
  print "@@ Different:\n";
  for my $pdr (@{$diff{diff}}) {
    if (grep {$_ == $pdr->[0]{code}} @xdiff) {
      print_pdr($pdr->[0]);
    } else {
      if ($opt_pda && !$opt_repl && $pdr->[0]{len} != $pdr->[1]{len}) {
	  printf "0x%04x, 0x%04x,\n", 1, $pdr->[0]{code};
      }
      print_pdr($pdr->[0], {prefix=>($opt_pda ? "#" : "").'- '});
      print_pdr($pdr->[1], {prefix=>($opt_pda ? "" : "+ ")});
    }
  }
  print "@@ Same:\n";
  for my $pdr (@{$diff{same}}) {
    print_pdr($pdr->[0], {header=>!$opt_pda});
  }
} else {
  for $pdr (sort {($a->{code} || $a->{code}+0x1000) <=> ($b->{code} || $b->{code}+0x1000)} @$src) {
    print_pdr($pdr);
  }
}
sub x2ascii_list {
  my ($pdr) = @_;
  my ($data) =  $pdr->{data};
  $data =~ s/[\x0-\x1f\x80-\x9f]/sprintf "\\x%02x", $&/eg;
  return $data;
}

sub x2hex_list {
  my ($pdr) = @_;

  return join(':', map { sprintf "%02x", ord($_) } split //, $pdr->{data});
}
sub x2dec_list {
  my ($pdr) = @_;

  return join(',', unpack('C*', $pdr->{data}));
}
sub x2bit_list {
  my ($pdr) = @_;
  my ($start) = 1;

  return join(',', map { $_ ? $start++ : scalar($start++, undef) } 
                       split //, unpack("b*", $pdr->{data}));
}

sub print_pdr {
  my ($pdr, $opts) = @_;
  my $data;

  if (exists($pdr_fmt->{$pdr->{code}})) {
     $data = &{$pdr_fmt->{$pdr->{code}}}($pdr);
  }
  printf "%s# %s (0x%04x/0x%04x) %s\n", $opts->{prefix},
	 $pdr_codes->{$pdr->{code}}, $pdr->{code}, $pdr->{len}, $data && "= $data"; 
  print $opts->{prefix}.join('', map {sprintf "0x%04x, ", $_} $pdr->{len}, $pdr->{code}, @{$pdr->{nums}})."\n"
    unless $opts->{header};
}

sub read_pda {
  my ($file) = @_;
  my (@pda, $pdrs);

  open PDA, "$file" or die "$file: $!\n";
  while (<PDA>) {
    s/[^\s\da-fx,].*//;
    push @pda, grep { /^0x[\da-z]+$/i } split /[^x\da-z]+/i;
  }
  close PDA;

  my ($len, $op, @data);

  for (my $i=0; $i < @pda; $i+=$len+1) {
    $len   = hex($pda[$i]);
    $code  = hex($pda[$i+1]);
    next unless $code;
    $nums  = [ map { hex } @pda[$i+2 .. $i+$len] ];
    $data  = pack("v*", @$nums);

    push @$pdrs, {len=>$len, code=>$code, data=>$data, nums=>$nums};
  }
  return $pdrs;
}
