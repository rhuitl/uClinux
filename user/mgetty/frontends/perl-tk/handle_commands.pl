#!/usr/bin/perl5
#
# (C) 1995 Klaus Lichtenwalder <Lichtenwalder@ACM.org>
#
# First shot 

#
# Configurable Commands for printing and viewing INCOMING faxes.
#     Print and View command can have and need exactly one parameter:
#     the complete pathname of the fax.
#

# We go to the /tmp for converting, this is for PostScript output
$MULTIPAGE_PRINT= 'cd /tmp; for i in %s; do /usr/local/bin/fax2tiff -o fax$$.tif `dirname %s`/$i; /usr/local/bin/fax2ps fax$$.tif | lpr; done; rm fax$$.tif';
#
$MULTIPAGE_VIEW = 'cd `dirname %s`;/usr/local/bin/viewfax %s';

my $HiResPosPrint   = 1;
my $NormResPosPrint = 0;
my $HiResPosView    = 0;
my $NormResPosView  = 0;

my $MAX_LINES = 5;

# The Array of print commands
my @print_command = ('cd /tmp; /usr/local/bin/fax2tiff -so fax$$.tif %s; /usr/local/bin/fax2ps fax$$.tif | lpr; rm fax$$.tif', 'cd /tmp; /usr/local/bin/fax2tiff -o fax$$.tif %s; /usr/local/bin/fax2ps fax$$.tif | lpr; rm fax$$.tif');

# The Array of view commands
my @view_command = ('/usr/local/bin/viewfax %s');


sub get_res {
  my $f = pop(@_);

  return 1 if ($f =~ m,/ff([^/]+)$,); # If fine resolution
  return 0;
}

sub get_print_command {
  my($res, $fname) = (@_);
  my $str;

  if ($res) {
    $str = $print_command[$HiResPosPrint];
  } else {
    $str = $print_command[$NormResPosPrint];
  }
  return sprintf($str, $fname);
}

sub get_view_command {
  my($res, $fname) = (@_);
  my $str;

  if ($res) {
    $str = $view_command[$HiResPosView];
  } else {
    $str = $view_command[$NormResPosView];
  }
  return sprintf($str, $fname);
}

sub execute {
  my $cmd = pop(@_);

  if ($opt_f == 1) {
    exec($cmd) unless fork;
  } else {
    $v = system($cmd);
    if ($v) {
      &tel_error($cmd);
      return;
    }
  }
}

sub print_the_fax {
  my($faxname) = pop(@_);
  my $res = get_res($faxname);
  my $command = get_print_command($res, $faxname);

  execute($command);
}

sub view_the_fax {
  my($faxname) = pop(@_);
  my $res = get_res($faxname);
  my $command = get_view_command($res, $faxname);

  execute($command);
}

sub multi_print {
  my($dirs, $pags) = (@_);
}

sub multi_view {
  my($dirs, $pags) = (@_);
}


#
# ************************************************************************
#

sub config_printer {
  my ($path, $tit) = @ARG;
  my ($top, $w, $rb_fein, $rb_norm);
  my ($i);
  my(@pl) = (-side => 'top', -fill => 'x');      # packing list

  $top = $path->Toplevel();
  $top->title($tit);

  $w = $top->Frame;
  $w->pack(-side => "top", -expand => "yes", -fill => "both");

  my $frm = $w->Frame();
  $frm->pack(-side => 'left');
  my $lab = $frm->Label(-text => 'HiRes');
  $lab->pack(-side => 'top');

  my $b1_frame = $frm->Frame(-bd => '1m');
  $b1_frame->pack(-side => 'top', -fill => 'x');

  $i = 0;
  while ($i <= $MAX_LINES) {
    my $e = $b1_frame->Radiobutton(-value => $i, -variable => \$HiResPosPrint);
    $e->pack(-side => 'top');
    $i++;
  }

  $frm = $w->Frame();
  $frm->pack(-side => 'left');
  $lab = $frm->Label(-text => 'LoRes');
  $lab->pack(-side => 'top');

  $b1_frame = $frm->Frame(-bd => '1m');
  $b1_frame->pack(-side => 'left', -fill => 'x');
  $i = 0;
  while ($i <= $MAX_LINES) {
    my $e = $b1_frame->Radiobutton(-value => $i,
				   -variable => \$NormResPosPrint);
    $e->pack(-side => 'top');
    $i++;
  }

  $frm = $w->Frame();
  $frm->pack(-side => 'left');
  $lab = $frm->Label(-text => 'Command');
  $lab->pack(-side => 'top');

  my $f1 = $frm->Frame(-bd => '1m');
  $f1->pack(-side => 'left', -fill => 'x');
  $i = 0;
  while ($i <= $MAX_LINES) {
    my $f = $f1->Frame;
    my $e = $f->Entry(-relief => 'sunken', -width => '50',
		     -textvariable => \$print_command[$i]);
    $e->bind('<Return>', ['destroy', $top]);
    $f->pack(@pl);
    $e->pack(-side => 'right');
    $i++;
  }
  $f = $top->Frame;
  $f->pack(-side => 'bottom', -fill => 'x');
  $e = $f->Button(-text => "OK", -command => ['destroy', $top]);
  $e->pack(-side => 'top');
}

sub config_viewer {
  my ($path, $tit) = @ARG;
  my ($top, $w, $rb_fein, $rb_norm);
  my ($i);
  my(@pl) = (-side => 'top', -fill => 'x');      # packing list

  $top = $path->Toplevel();
  $top->title($tit);

  $w = $top->Frame;
  $w->pack(-side => "top", -expand => "yes", -fill => "both");

  my $frm = $w->Frame();
  $frm->pack(-side => 'left');
  my $lab = $frm->Label(-text => 'HiRes');
  $lab->pack(-side => 'top');

  my $b1_frame = $frm->Frame(-bd => '1m');
  $b1_frame->pack(-side => 'top', -fill => 'x');

  $i = 0;
  while ($i <= $MAX_LINES) {
    my $e = $b1_frame->Radiobutton(-value => $i, -variable => \$HiResPosView);
    $e->pack(-side => 'top');
    $i++;
  }

  $frm = $w->Frame();
  $frm->pack(-side => 'left');
  $lab = $frm->Label(-text => 'LoRes');
  $lab->pack(-side => 'top');

  $b1_frame = $frm->Frame(-bd => '1m');
  $b1_frame->pack(-side => 'left', -fill => 'x');
  $i = 0;
  while ($i <= $MAX_LINES) {
    my $e = $b1_frame->Radiobutton(-value => $i,
				   -variable => \$NormResPosView);
    $e->pack(-side => 'top');
    $i++;
  }

  $frm = $w->Frame();
  $frm->pack(-side => 'left');
  $lab = $frm->Label(-text => 'Command');
  $lab->pack(-side => 'top');

  my $f1 = $frm->Frame(-bd => '1m');
  $f1->pack(-side => 'left', -fill => 'x');
  $i = 0;
  while ($i <= $MAX_LINES) {
    my $f = $f1->Frame;
    my $e = $f->Entry(-relief => 'sunken', -width => '50',
		     -textvariable => \$view_command[$i]);
    $e->bind('<Return>', ['destroy', $top]);
    $f->pack(@pl);
    $e->pack(-side => 'right');
    $i++;
  }
  $f = $top->Frame;
  $f->pack(-side => 'bottom', -fill => 'x');
  $e = $f->Button(-text => "OK", -command => ['destroy', $top]);
  $e->pack(-side => 'top');
}

sub read_print_commands {
  my ($fil) = @_;

  my $i;

  $MAX_LINES = <$fil> + 0;		# Force to int

  for ($i = 0; $i < $MAX_LINES; $i++) {
    my $lin = <$fil>;

    $print_command[$i] = $lin unless ($lin =~ /^$/);
    chomp($print_command[$i]);
  }
  $HiResPosPrint   = <$fil> + 0;
  $NormResPosPrint = <$fil> + 0;
}

sub read_view_commands {
  my ($fil) = @_;

  my $i;

  for ($i = 0; $i < $MAX_LINES; $i++) {
    my $lin = <$fil>;

    $view_command[$i] = $lin unless ($lin =~ /^$/);
    chomp($view_command[$i]);
  }
  $HiResPosView   = <$fil> + 0;
  $NormResPosView = <$fil> + 0;
}


sub save_view_commands {
  my ($fil) = @_;

  my $i;

  for ($i = 0; $i < $MAX_LINES; $i++) {
    print $fil "$view_command[$i]\n";
  }
  print $fil "$HiResPosView\n$NormResPosView\n";
}

sub save_print_commands {
  my ($fil) = @_;

  my $i;

  print $fil "$MAX_LINES\n";

  for ($i = 0; $i < $MAX_LINES; $i++) {
    print $fil "$print_command[$i]\n";
  }
  print $fil "$HiResPosPrint\n$NormResPosPrint\n";
}

1;
