#!/usr/local/bin/tkperl
# 
# $Header: faxman.pl[2.5] Thu Apr  6 16:41:01 1995 klaus@gaston.m.ISAR.de saved $
#
# (C) Klaus Lichtenwalder, Munich, Germany, 1995, 
#     klaus@gaston.m.isar.de, Lichtenwalder@ACM.org
#
#
# ************************************************************************
# This script is freely copyable as long as my name is not removed.
# You are allowed to charge for media costs if distributing. You are
# not allowed to charge for the package itself.
# If you make changes or bug fixes, please state clearly and please let
# me know!
# ************************************************************************
#
#
# Friendly People with good ideas and other help (in alphabetical order
#   [ if I didn't make any mistake while sorting :-]
#
#  Gert Doering <gert@greenie.muc.de>
#  Stephan Gilbert <stephan@gaston.m.isar.de>
#
# ************************************************************************
#
# Configuration
$FAXINDIR       = "/usr/spool/fax/incoming";
$FAXOUTDIR      = "/usr/spool/fax/outgoing";
$LIBDIR         = "/usr/local/lib";
#
$BOLDFONT	= "-Adobe-Courier-Bold-R-Normal-*-18-*-*-*-*-*-*";
$BIGFONT        = "-Adobe-Times-Bold-I-Normal-*-18-*-*-*-*-*-*";
# ************************************************************************
#
# Constants
$refreshdelay   = 60000;	# check incoming every minute
$LOOPS_TO_WAIT  =     5;	# this times $refreshdelay reread outgoing dir
$stat_dir_time  =     0;	# Last Modification date of incoming
$mv_or_cp       =     1;	# mv == 1, cp == 0 for save
$MULTIPAGE_PRINT= 'cd /tmp; for i in %s; do /usr/local/bin/fax2tiff -o fax$$.tif `dirname %s`/$i; /usr/local/bin/fax2ps fax$$.tif | lpr; done; rm fax$$.tif';
#
$MULTIPAGE_VIEW = 'cd `dirname %s`;/usr/local/bin/viewfax %s';

if (defined $ENV{'FAXMAN_LANGUAGE'}) {
  $FAXLANG = $ENV{'FAXMAN_LANGUAGE'};
} else {
  $FAXLANG = 'deutsch';
  # $FAXLANG = 'english';		# You might prefer this one...
}

# Language Constants
my $name = "$ENV{'HOME'}/.faxman-$FAXLANG";
if (open(LANGIN, $name)) {
  my ($key, $val);
  while (<LANGIN>) {
    chomp;
    ($key, $val) = split('=');
    $LANG{$key} = "$val";
  }
  close(LANGIN);
} else {
  my ($key, $val);
  $name = "$LIBDIR/faxman-$FAXLANG";
  if (open(LANGIN, $name)) {
    while (<LANGIN>) {
      chomp;
      ($key, $val) = split('=');
      $LANG{$key} = "$val";
    }
    close(LANGIN);
  } else {
    $LANG{'PRINT_TXT'}    = " Drucken ";
    $LANG{'VIEW_TXT'}     = " Ansehen ";
    $LANG{'REREAD_TXT'}   = " Neu Einlesen ";
    $LANG{'SAVE_TXT'}     = " Sichern ";
    $LANG{'FORW_TXT'}     = " Weiterversenden ";
    $LANG{'SHORTEN_TXT'}  = " Kurz ";
    $LANG{'EXPAND_TXT'}   = " Lang ";
    $LANG{'QUIT_TXT'}     = " Ende ";
    $LANG{'RECFAX_TXT'}   = " Empfangene Faxe ";
    $LANG{'SEND_TXT'}     = " Zu sendende Faxe ";
    $LANG{'CHNGNUM_TXT'}  = " Nummer ändern ";
    $LANG{'SNDTIM_TXT'}   = " Sendezeit (hh:mm)";
    $LANG{'CHNGSTAT_TXT'} = " Status ändern ";
    $LANG{'CLR_TXT'}      = " Löschen ";
    $LANG{'JOB_TITLE'}    = " *** Faxmanager *** ";
    $LANG{'CNCL_TXT'}     = " Abbruch ";
    $LANG{'DOCHNG_TXT'}   = " Ändern ";
    $LANG{'CHNGTIM_TXT'}  = " Sendezeit ändern ";
    $LANG{'CONFBTN_TXT'}  = " Ja, löschen ";
    $LANG{'CNCBTN_TXT'}   = " Nein, nicht löschen ";
    $LANG{'FAXALERT_TXT'} = "    Fax angekommen   ";
    $LANG{'SZ_TXT'}       = "Größe:";
    $LANG{'SND_NAM'}      = "Absender:";
    $LANG{'PG_NAM'}       = "Seite:";
    $LANG{'PGS_NAM'}      = "Seiten:";
    $LANG{'TO_TXT'}       = "An:";
    $LANG{'FRM_TXT'}      = "Von:";
    $LANG{'PGS_TXT'}      = "Seiten:";
    $LANG{'TIM_TXT'}      = "Zeit:";
    $LANG{'FINE_TXT'}     = "fein";
    $LANG{'NORM_TXT'}     = "normal";
    $LANG{'DETAIL_TXT'}   = " Details ";
    $LANG{'DETAILHEAD'}   = "Details des Fax-JOB";
    $LANG{'FILE_TXT'}     = "Datei";
    $LANG{'SHOW_TXT'}     = "Ansicht";
    $LANG{'OPT_TXT'}      = "Optionen";
    $LANG{'CHNG_TXT'}     = "Manipulationen";
    $LANG{'LS_TXT'}       = "Format empf. Faxe";
    $LANG{'MVORCP'}       = "Kopieren oder Umbenennen";
    $LANG{'COPY_TXT'}     = "Kopieren";
    $LANG{'RENAME_TXT'}   = "Umbenennen";
    $LANG{'MISCERR_TXT'}  = " Fehler in der Ausführung des Kommandos ";
    $LANG{'GAB_ERR'}      = " ergab einen Fehler ";
    $LANG{'PRINTCONF'}    = "Druckkommando";
    $LANG{'VIEWCONF'}     = "Darstellen";
    $LANG{'USAGE'}        = "Aufruf:
faxman [-A]
        -A: keine Warnung bei neuem Fax
        -l: erzwinge langes Listing (default)
        -s: erzwinge kurzes Listing
        -E: Selektierte Einträge *nicht* exportieren
";
    $LANG{'CONFDEL_TXT'} = "
Sollen die markierten Faxe
gelöscht werden ?";
  }
}

# get required things
BEGIN { push @INC, qw(/usr/home/klaus/faxman /u/gert/mgetty/frontends/tkperl);}
require 'getopts.pl';
use English;
use Tk;
use Tk::FileSelect;
use Tk::Dialog;
use POSIX qw(getenv stat);

require 'handle_commands.pl';	# Needs Tk Package

&read_opts;			# Get the Options

my $short_display = 1;
my $exp_sel = "y";
# Options Processing
# define option switches for -w Flag
$opt_A = 0;
$opt_l = 0;
$opt_s = 0;
$opt_f = 0;
$opt_E = 0;
&Getopts('AlsfE') || do { printf "%s", $LANG{'USAGE'}; die; };

$short_display = 0 if ($opt_l == 1);
$short_display = 1 if ($opt_s == 1);
$exp_sel = "n"     if ($opt_E == 1);

# Initialize Aliases
&init_aliases;

# Initialize Toplevel 
my $faxmgrtop = MainWindow->new();
my $cursor = ($faxmgrtop->configure("-cursor"))[3];

#
my $topframe = $faxmgrtop->Frame();

# create a fileselector for later perusal
my $TheFileSelector = $faxmgrtop->FileSelect($ENV{'HOME'});

# same for a confirmation dialog
my $ConfirmDel = $faxmgrtop->Dialog(-title          => 'Delete Fax?',
				    -text           => $LANG{'CONFDEL_TXT'},
				    -bitmap         => 'questhead',
				    -default_button => $LANG{'CLR_TXT'},
				    -buttons        => [$LANG{'CLR_TXT'},
							$LANG{'CNCL_TXT'}]);

# ... and the error popup
my $ErrorDialog = $faxmgrtop->Dialog(-title          => $LANG{'MISCERR_TXT'},
				     -text           => 'Hi there', # Defined
				     -bitmap         => 'error',    # at popup time
				     -default_button => 'OK',
				     -buttons        => ['OK']);
#
# Create menu
my $menu = $faxmgrtop->Frame(-relief => "raised", -borderwidth => 1);
$menu->pack(-side => "top", -expand => "yes", -fill => "x");

# File Commands
my $f_mb_l = $menu->Menubutton(-text => $LANG{'FILE_TXT'});
$f_mb_l->command(-label   => $LANG{'REREAD_TXT'},
		 -command => \&force_refresh);
$f_mb_l->separator;
$f_mb_l->command(-label => $LANG{'PRINT_TXT'},  -command => \&printit);
$f_mb_l->command(-label => $LANG{'VIEW_TXT'},   -command => \&viewit);
$f_mb_l->separator;
$f_mb_l->command(-label => $LANG{'DETAIL_TXT'}, -command => \&show_details);
$f_mb_l->separator;
$f_mb_l->command(-label => $LANG{'FORW_TXT'}, -command => \&forward_fax);
$f_mb_l->command(-label => $LANG{'SAVE_TXT'}, -command => \&saveit);
$f_mb_l->command(-label => $LANG{'CLR_TXT'},  -command => \&del_fax);
$f_mb_l->separator;
$f_mb_l->command(-label => $LANG{'QUIT_TXT'}, -command => \&ende);
$f_mb_l->pack(-side => "left");
($f_mb_l->cget(-menu))->configure(-tearoff => 'no');

# Changes
my $c_mb_l = $menu->Menubutton(-text => $LANG{'CHNG_TXT'});
$c_mb_l->command(-label => $LANG{'CHNGNUM_TXT'},  -command => \&change_number);
$c_mb_l->command(-label => $LANG{'SNDTIM_TXT'},   -command => \&change_time);
$c_mb_l->command(-label => $LANG{'CHNGSTAT_TXT'}, -command => \&change_state);
$c_mb_l->pack(-side => "left");
($c_mb_l->cget(-menu))->configure(-tearoff => 'no');

# Options
my $o_mb_l = $menu->Menubutton(-text => $LANG{'OPT_TXT'});
$o_mb_l->pack(-side => 'left');
$o_mb_l->cascade(-label => $LANG{'LS_TXT'}, -underline => 0);
my $ls_ctrl = $o_mb_l->cget(-menu);
my $menu_ls = $ls_ctrl->Menu(-tearoff => 'no');
$ls_ctrl->entryconfigure($LANG{'LS_TXT'}, -menu => $menu_ls);
$menu_ls->radiobutton(-label    => $LANG{'SHORTEN_TXT'},
		       -value    => 1,
		       -variable => \$short_display,
		       -command  => \&toggle_style);
$menu_ls->radiobutton(-label    => $LANG{'EXPAND_TXT'},
		      -value    => 0,
		      -variable => \$short_display,
		      -command  => \&toggle_style);
$o_mb_l->cascade(-label => $LANG{'MVORCP'}, -underline => 0);
($o_mb_l->cget(-menu))->configure(-tearoff => 'no');

my $mv_ctrl = $o_mb_l->cget(-menu);
my $menu_mv = $mv_ctrl->Menu(-tearoff => 'no');
$mv_ctrl->entryconfigure($LANG{'MVORCP'}, -menu => $menu_mv);
$menu_mv->radiobutton(-label    => $LANG{'COPY_TXT'},
		       -value    => 0,
		       -variable => \$mv_or_cp);
$menu_mv->radiobutton(-label    => $LANG{'RENAME_TXT'},
		      -value    => 1,
		      -variable => \$mv_or_cp);
$o_mb_l->command(-label => $LANG{'PRINTCONF'}, -command => sub {
  &config_printer($o_mb_l, $LANG{'PRINTCONF'});
 });
$o_mb_l->command(-label => $LANG{'VIEWCONF'}, -command => sub {
 &config_viewer($o_mb_l, $LANG{'VIEWCONF'});
});
$o_mb_l->separator;
$o_mb_l->command(-label => $LANG{'SAVE_TXT'}, -command => \&save_opts);
# Quit
my $q_mb_l = $menu->Menubutton(-text => $LANG{'QUIT_TXT'});
$q_mb_l->command(-label => $LANG{'QUIT_TXT'}, -command => \&ende);
$q_mb_l->pack(-side => "right");
($q_mb_l->cget(-menu))->configure(-tearoff => 'no');
#
# create frame and innards...
$topframe->pack("-expand", "y", "-fill", "both");
#
# for received faxes
my $reclabel = $topframe->Label("-text" => $LANG{'RECFAX_TXT'},
				"-borderwidth" => 3,
				"-font"        => $BIGFONT,
				"-relief"      => "flat");
$reclabel->pack("-fill", "x");
#
my $recframe = $topframe->Frame("-relief", "ridge");
$recframe->pack("-expand", "yes", "-fill", "both");

my $rl_yscroll = $recframe->Scrollbar();
my $reclist  = $recframe->Listbox("-width"     => "88",
				  "-selectmode"  => "extended",
				  "-relief"    => "ridge",
				  "-exportselection" => $exp_sel,
				  "-yscrollcommand" => ['set', $rl_yscroll]);
$rl_yscroll->configure(-command => ['yview', $reclist]);
$rl_yscroll->pack("-side" => "right", "-fill" => "y");
$reclist->pack("-fill", "both", "-expand", "yes");
$reclist->bind( "<Double-Button-1>", \&viewit );
#
# for outgoing faxes
my $sendlabel = $topframe->Label("-text"        => $LANG{'SEND_TXT'},
			      "-borderwidth" => 3,
			      "-font"        => $BIGFONT,
			      "-relief"      => "flat");
$sendlabel->pack("-fill", "x");

my $sendframe = $topframe->Frame();
$sendframe->pack("-expand", "yes", "-fill", "both");
my $sf_yscroll = $sendframe->Scrollbar();
my $sf_xscroll = $sendframe->Scrollbar("-orient" => "horizontal");
my $sendlist  = $sendframe->Listbox("-width", "88",
				    "-selectmode"  => "extended",
				    "-height", "6",
				    "-relief"   => "ridge",
				    "-exportselection" => $exp_sel,
				    "-xscrollcommand" => ['set', $sf_xscroll],
				    "-yscrollcommand" => ['set', $sf_yscroll]);
$sf_yscroll->configure(-command => ['yview', $sendlist]);
$sf_xscroll->configure(-command => ['xview', $sendlist]);
$sf_yscroll->pack("-side" => "right", "-fill" => "y");
$sf_xscroll->pack("-side" => "bottom", "-fill" => "x");
$sendlist->pack("-expand", "yes", "-fill", "both");
$sendlist->bind( "<Double-Button-1>", \&viewit );
#
$faxmgrtop->wm("maxsize", 1024, 1024);
$faxmgrtop->wm("title", $LANG{'JOB_TITLE'});
my $timer_id = Tk::after($refreshdelay, \&refreshlists);
&refreshlists;
$times_through = $LOOPS_TO_WAIT+1;
Tk::MainLoop;

#
# -------------------------------------------------------------------
# An error has occured...
sub tel_error {
    my($command) = @_;
    my($err_frame, $err_top, $err_bit, $err_ok);

    $ErrorDialog->configure(-text => $command . $LANG{'GAB_ERR'});
    $ErrorDialog->Show;
}


my($alert_on) = 0;		# Don't do multiple warnings
my(@stat_arr);			# Global array for faxin time

sub alert_new_fax {
    my($alert_top);
    $alert_top      = $faxmgrtop->Toplevel;
    my $mbframe     = $alert_top->Frame();
    my $mbframe_bit = $mbframe->Label(-bitmap => 'info');

    $mbframe_bit->pack(-side => 'top');
    $mbframe->pack(-side => 'top', -expand => 'y',
		   -fill => 'y',   -pady => 5);
    my($alert_lb)  = $alert_top->Label("-text"   => $LANG{'FAXALERT_TXT'},
				       "-relief" => "groove");
    $alert_lb->pack(-side => 'top', -expand => 'y',
		    -fill => 'y',   -pady => 5);
    my($alert_ok)  = $alert_top->Button("-text"   => "OK",
					"-command" => sub {
					    $alert_top->grab("release");
					    $alert_top->wm("withdraw");
					    @stat_arr = stat($FAXINDIR);
					    $alert_on = 0;
					});
    $alert_ok->pack(-side => 'top', -expand => 'y',
		    -fill => 'y',   -pady => 5);
    $alert_top->grab;
}

#  My personal time interrupt
sub refreshlists {
    my($nam, $dev, $pag, $i, $lasttime);
    my($myline, $rest, $sec);

    Tk::after('cancel', $timer_id); # stop old timer

    $faxmgrtop->configure( "-cursor" => "watch" );
    $faxmgrtop->idletasks;
    @stat_arr = stat($FAXINDIR);
    if ($stat_dir_time != $stat_arr[9]) {
	if ($opt_A == 1 && $alert_on == 0 && $stat_dir_time > 0) {
	    $alert_on = 1;
	    &alert_new_fax;
	}
	$stat_dir_time = $stat_arr[9];
	$times_through = $LOOPS_TO_WAIT+1;
	$reclist->delete(0, "end");
	$i = 0;
	$lasttime = '';
	open(FAXIN, "ls -t1 $FAXINDIR 2>/dev/null |");
	while (<FAXIN>) { # Incoming faxes
	    chop;
	    next unless /^f[nf]./;
	    @stat_arr = stat("$FAXINDIR/$_");
	    if ($stat_arr[7] > 0) { # Size
		($sec, $min, $hour, $mday, $mon, $year, $rest) =
		    localtime($stat_arr[10]);
		$_ =~ /f([fn])(.......)(..)-*(.*)\.(..)$/;
		$res = $1;
		$dev = $3;
		if ($4 eq '') {
		    $nam = " (NO ID) ";
		} else {
		    $nam = &get_alias($4);
		}
		$pag = $5;
		if ($res eq 'f') {
		    $res = $LANG{'FINE_TXT'};
		} else {
		    $res = $LANG{'NORM_TXT'};
		}
		if ($year < 70) { # Unix helps a bit here ;-)
		    $year += 2000;
		} else {
		    $year += 1900;
		}
		if ($short_display == 1) {
		    if ($i > 0) {
			$received_faxes[$i-1] =~ /f[fn](.......)/;
			$lasttime = $1;
			$_ =~ /f[fn](.......)/;
			if ($lasttime ne $1) {
			    $myline = sprintf("%02d:%02d %02d.%02d.%04d $LANG{'SND_NAM'} %-22s Line %s $LANG{'PGS_NAM'} %2d %s",
					      $hour, $min, $mday, $mon+1,
					      $year, $nam, $dev, $pag, $res); #
			    $reclist->insert("end", $myline); #
			    $_ =~ /^(.*)\.\d\d$/;
			    $received_faxes[$i++] = "$FAXINDIR/$1.??";
			}
		    } else {
			$myline = sprintf("%02d:%02d %02d.%02d.%04d $LANG{'SND_NAM'} %-22s Line %s $LANG{'PGS_NAM'} %2d %s",
					  $hour, $min, $mday, $mon+1,
					  $year, $nam, $dev, $pag, $res); #
			$reclist->insert("end", $myline); #
			$_ =~ /^(.*)\.\d\d$/;
			$received_faxes[$i++] = "$FAXINDIR/$1.??";
		    }
		} else {
		    $myline = sprintf("%02d:%02d %02d.%02d.%04d $LANG{'SZ_TXT'} %6d $LANG{'SND_NAM'} %-22s Line %s $LANG{'PG_NAM'} %d %s",
				      $hour, $min, $mday, $mon+1, $year, # 
				      $stat_arr[7], $nam, $dev,
				      $pag, $res); # 
		    $reclist->insert("end", $myline); #
		    $received_faxes[$i++] = "$FAXINDIR/$_";
		}
	    }
	}
	close(FAXIN);
    }
    if ($times_through++ > $LOOPS_TO_WAIT) {
	$sendlist->delete(0, "end");
	$i = 0;
	open(FAXOUT, "cd $FAXOUTDIR; ls -t1 */JOB* 2>/dev/null |");
	while (<FAXOUT>) { # Outgoing faxes
	    chop;
	    $send_faxes[$i] = "$FAXOUTDIR/$_";
	    $_ =~ /JOB(.*)$/;
	    if ($1 eq ".suspended") {
		$stat = "Inaktiv";
	    } elsif ($1 eq ".done") {
		$stat = "Gesendet";
	    } else {
		$stat = "Aktiv";
	    }
	    open(THE_JOB, "$FAXOUTDIR/$_");
	    $phone = "";
	    $user  = "";
	    reset(@pages);
	    $verb  = "";
	    $time = "";
	    $sendstat = "";
	    while (<THE_JOB>) {
		if (/^phone (.*)$/) {
		    $phone = $1;
		} elsif (/^user (.*)$/) {
		    $user = $1;
		} elsif (/^pages (.*)$/) {
		    $send_faxes_pages[$i] = $1;
		    @pages = split(/ /, $1);
		} elsif (/^verbose_to (.*)/) {
		    $verb = $1;
		} elsif (/^time (.*)$/) {
		    $time = $1;
		} elsif (/^Status (.*)$/) {
		    $sendstat = $1;
		}
	    }
	    close(THE_JOB);
	    $myline = sprintf("Status: %8s $LANG{'TO_TXT'} %12s (%10.10s) $LANG{'FRM_TXT'} %8s $LANG{'PGS_TXT'} %d $LANG{'TIM_TXT'} %5s Last Status: %s",
			      $stat, $phone, $verb, $user, $#pages, $time,
			      $sendstat);
	    $sendlist->insert("end", $myline);
	    $i++,
	}
    }				# 
    $faxmgrtop->configure( "-cursor" => $cursor );
    $timer_id = Tk::after($refreshdelay, \&refreshlists); # Start a new timer
}

sub force_refresh {
    $times_through = $LOOPS_TO_WAIT+1;
    &refreshlists;
}

#  Methods
#
sub printit {
    my(@selfiles, $recs);

    $faxmgrtop->configure( "-cursor" => "watch" );
    $faxmgrtop->idletasks;

    if (length($reclist->curselection) > 0) {
	@selfiles = $reclist->curselection;
	$recs = 1;
    } elsif (length($sendlist->curselection) > 0) {
	@selfiles = $sendlist->curselection;
	$recs = 0;
    }
    &view_fax($recs, 1, @selfiles);

    $faxmgrtop->configure( "-cursor" => $cursor );
}

sub viewit {
    $faxmgrtop->configure( "-cursor" => "watch" );
    $faxmgrtop->idletasks;

    my(@selfiles, $recs);

    if (length($reclist->curselection) > 0) {
	@selfiles = $reclist->curselection;
	$recs = 1;
    } elsif (length($sendlist->curselection) > 0) {
	@selfiles = $sendlist->curselection;
	$recs = 0;
    }
    &view_fax($recs, 0, @selfiles);

    $faxmgrtop->configure( "-cursor" => $cursor );
}

sub ende {
    exit;
}

my $new_toplevel = "";
my $newnum = "                    ";
my $ent = "";
sub change_number {
    my(@selfiles, $fil, $i, $command);

    if (length($sendlist->curselection) == 0) {
	return;
    }
    @selfiles = $sendlist->curselection();
    $fil = $send_faxes[$selfiles[0]];
    open(JOBF, $fil);
    while(<JOBF>) {
	if (/^phone (.*)$/) {
	    $newnum = $1;
	}
    }
    close(JOBF);
    $new_toplevel = $faxmgrtop->Toplevel();
    my($frm)      = $new_toplevel->Frame;
    $frm->pack();
    $lb = $frm->Label("-text"   => $LANG{'CHNGNUM_TXT'},
		      "-relief" => "groove");
    $lb->pack("-fill", "x");
    $ent = $frm->Entry("-textvariable" => \$newnum);
    $ent->pack("-fill", "x");
    $ent->bind('<Return>', \&accept_new_number);
    $qut = $frm->Button("-text"        => $LANG{'CNCL_TXT'},
			"-command"     => [ 'destroy', $new_toplevel]);
    $qut->pack("-side", "left");
    $acc = $frm->Button("-text"        => $LANG{'DOCHNG_TXT'},
			"-command"     => \&accept_new_number);
    $acc->pack("-side", "right");
    $new_toplevel->grab;
}

sub change_time {
    my(@selfiles, $fil, $i, $command);

    if (length($sendlist->curselection) == 0) {
	return;
    }
    @selfiles = $sendlist->curselection();
    $fil = $send_faxes[$selfiles[0]];
    open(JOBF, $fil);
    $newnum = "hh:mm";
    while(<JOBF>) {
	if (/^time (.*)$/) {
	    $newnum = $1;
	}
    }
    close(JOBF);
    $new_toplevel = $faxmgrtop->Toplevel();
    my($frm)      = $new_toplevel->Frame;
    $frm->pack();
    $lb = $frm->Label("-text"   => $LANG{'CHNGTIM_TXT'},
		      "-relief" => "groove");
    $lb->pack("-fill", "x");
    $ent = $frm->Entry("-textvariable" => \$newnum);
    $ent->pack("-fill", "x");
    $ent->bind('<Return>', \&accept_new_time);
    $qut = $frm->Button("-text"        => $LANG{'CNCL_TXT'},
			"-command"     => [ 'destroy', $new_toplevel]);
    $qut->pack("-side", "left");
    $acc = $frm->Button("-text"        => $LANG{'DOCHNG_TXT'},
			"-command"     => \&accept_new_time);
    $acc->pack("-side", "right");
    $new_toplevel->grab;
}

sub accept_new_number {
    my(@selfiles, $fil, $i, $command, $tmpfil, $tmplock);

    $new_toplevel->grab("release");
    $new_toplevel->wm("withdraw");
    if (length($sendlist->get('active')) == 0) {
	return;
    }
    @selfiles = $sendlist->curselection();
    $fil = $send_faxes[$selfiles[0]];
    $tmpfil = sprintf("/tmp/JOB%d.tmp", getppid());
    my $v = system("mv -f $fil $tmpfil");
    if ($v) {
	&tel_error("mv -f $fil $tmpfil");
	return;
    }
    $tmplock = sprintf("/tmp/JOB-%d.lock", getppid());
    open(JOBF, $tmpfil);
    open(OUTJOB, ">$tmplock");
    while(<JOBF>) {
	if (/^phone (.*)$/) {
	    print OUTJOB "phone $newnum\n";
	} else {
	    print OUTJOB $_;
	}
    }
    close(JOBF);
    close(OUTJOB);
    $v = system("mv -f $tmplock $fil");
    if ($v) {
	&tel_error("mv -f $tmplock $fil");
	return;
    }
    system("rm $tmpfil");
    $times_through = $LOOPS_TO_WAIT+1;
    refreshlists;
}

sub accept_new_time {
    my(@selfiles, $fil, $i, $command, $tmpfil, $tmplock);

    $new_toplevel->grab("release");
    $new_toplevel->wm("withdraw");
    if (length($sendlist->get('active')) == 0) {
	return;
    }
    @selfiles = $sendlist->curselection();
    $fil = $send_faxes[$selfiles[0]];
    $tmpfil = sprintf("/tmp/JOB%d.tmp", getppid());
    my $v = system("mv -f $fil $tmpfil");
    if ($v) {
	&tel_error("mv -f $fil $tmpfil");
	return;
    }
    $tmplock = sprintf("/tmp/JOB-%d.lock", getppid());
    open(JOBF, $tmpfil);
    open(OUTJOB, ">$tmplock");
    $i = 0;
    while(<JOBF>) {
	if (/^time (.*)$/) {
	    $i = 1;
	    print OUTJOB "time $newnum\n";
	} else {
	    print OUTJOB $_;
	}
    }
    if ($i == 0) {		# No time directive up to now
	print OUTJOB "time $newnum\n";
    }
    close(JOBF);
    close(OUTJOB);
    $v = system("mv -f $tmplock $fil");
    if ($v) {
	&tel_error("mv -f $tmplock $fil");
	return;
    }
    system("rm $tmpfil");
    $times_through = $LOOPS_TO_WAIT+1;
    refreshlists;
}

sub change_state {
    my(@selfiles, $i, $command, $v);

    if (length($sendlist->get('active')) > 0) {
	@selfiles = $sendlist->curselection();
	for ($i = 0; $i <= $#selfiles; $i++) {
	    if ($send_faxes[$selfiles[$i]] =~ /JOB$/) {
		$command = sprintf("mv -f %s %s.suspended",
				   $send_faxes[$selfiles[$i]],
				   $send_faxes[$selfiles[$i]]);
	    } else {
		$send_faxes[$selfiles[$i]] =~ /^(.+JOB)\..+$/;
		$command = sprintf("mv -f %s %s",
				   $send_faxes[$selfiles[$i]], $1);
	    }
	    $v = system($command);
	    if ($v) {
		&tel_error($command);
		return;
	    }
	}
	refreshlists;
    }
}

sub del_fax {
    my(@selfiles);

    return unless ($ConfirmDel->Show eq $LANG{'CLR_TXT'});
    if (length($reclist->curselection()) > 0) {
	@selfiles = $reclist->curselection();
	sub_del_fax(1, @selfiles);
	$times_through = $LOOPS_TO_WAIT+1;
	$stat_dir_time = 0;	# rebuild list but dont launch alert
	refreshlists;
    } elsif (length($sendlist->curselection()) > 0) {
	@selfiles = $sendlist->curselection();
	sub_del_fax(0, @selfiles);
	$times_through = $LOOPS_TO_WAIT+1;
	refreshlists;
    }
}

sub sub_del_fax {
    my($recd, @selected) = @_;
    my($i, $command, $v);

    for ($i = 0; $i <= $#selected; $i++) {
	if ($recd == 1) {		# Received Faxes
	    $fname = $received_faxes[$selected[$i]];
	    $command = sprintf('rm -f %s', $fname);
	} else {
	    $command = sprintf('rm -rf `dirname %s`',
			       $send_faxes[$selected[$i]]);
	}
	$v = system($command);
	if ($v) {
	    &tel_error($command);
	    return;
	}
    }
}
#
#
# ------------------------------------------------------------------------
#
# Misc Routines
#
sub view_fax {
    my($recd, $v_or_p, @selected) = @_;
    my($fname, $i, $command, $v);

    for ($i = 0; $i <= $#selected; $i++) {
	if ($recd == 1) {		# Received Faxes
	    $fname = $received_faxes[$selected[$i]];
	    if ($v_or_p == 1) {	# Print
	      print_the_fax($fname);
#		$command = sprintf($PRINT_COMMAND, $fname);
	    } else {		# View
#		$command = sprintf($VIEW_COMMAND, $fname);
	      view_the_fax($fname);
	    }
	} else {
	    if ($v_or_p == 1) {
#	      multi_print($send_faxes_pages[$selected[i]],
#			   $send_faxes[$selected[$i]]);
		$command = sprintf($MULTIPAGE_PRINT,
				   $send_faxes_pages[$selected[$i]],
				   $send_faxes[$selected[$i]]);
	    } else {
#	      multi_view($send_faxes_pages[$selected[$i]],
#			$send_faxes[$selected[$i]],);
		$command = sprintf($MULTIPAGE_VIEW,
				   $send_faxes[$selected[$i]],
				   $send_faxes_pages[$selected[$i]]);
	    }
	    if ($opt_f == 1) {
	      exec($command) unless fork;
	    } else {
	      $v = system($command);
	      if ($v) {
		&tel_error($command);
		return;
	      }
	    }
	}
    }
}

sub toggle_style {
    $stat_dir_time = 0;
    &refreshlists;
}


sub saveit {
    my ($fname);
    my ($command, $cnt);
    my(@selfiles);
    my($i, $fil, $v);

    $cnt = 0;
    if (length($reclist->curselection) > 0) {
	@selfiles = $reclist->curselection;
	for ($i = 0; $i <= $#selfiles; $i++) {
	    $fil = $received_faxes[$selfiles[$i]];
	    
	    $fname = $TheFileSelector->Show;
	    next if (!defined($fname));

	    if ($short_display == 1) {
		$cnt = 1;
		foreach $page (<${fil}>) {
		    $command = sprintf("%s -f %s %s.%02d",
				       $mv_or_cp == 1 ? 'mv' : 'cp',
				       $page,
				       $fname, $cnt++);
		    $v = system($command);
		    print "$command\n";
		    last, &tell_error if $v;
		}
  	    } else {
		$command = sprintf("%s -f %s %s",
				   $mv_or_cp == 1 ? 'mv' : 'cp',
				   $fil,
				   $fname, $i++);
		$v = system($command);
		&tell_error if $v;
		$cnt = 1;
	    }
        }
    }
    if ($cnt != 0 && $mv_or_cp == 1) {
	$times_through = $LOOPS_TO_WAIT+1;
	$stat_dir_time = 0;	# rebuild list but dont launch alert
	&refreshlists;
    }
}

my $command;
my $newtop;

sub do_forward {
  my ($i, $fine);

  $fine = '';
  $newtop->destroy;
  for ($i = 0; $i <= $#selfiles; $i++) {
    $received_faxes[$selfiles[$i]] =~ m,/f([nf])[0-9a-f],;
    $fine = '-n' if $1 eq 'n';
  }
  $command .= " ";
  for ($i = 0; $i <= $#selfiles; $i++) {
    $command .= $received_faxes[$selfiles[$i]];
  }
  $faxmgrtop->configure( "-cursor" => "watch" );
  $faxmgrtop->idletasks;
  system("fax $fine $command");
  $faxmgrtop->configure( "-cursor" => $cursor );
  &refreshlists;
}

sub forward_fax {
    my($i, $fil, $v);

    if (length($reclist->curselection) > 0) {
      $command = '';
      @selfiles = $reclist->curselection;
      $newtop = $faxmgrtop->Toplevel();
      my $labentr = $newtop->LabeledEntry('Name' => "forwarder",
					  -label => 'Faxno: ',
					  -textvariable => \$command);
      $labentr->pack(-fill => "both");
      my $fr = $newtop->Frame();
      my $qb = $newtop->Button(-text => "OK", -command => \&do_forward);
      my $cb = $newtop->Button(-text => "Abbruch", -command => [ 'destroy',
								$newtop ]);
      $fr->pack(-side => 'bottom');
      $qb->pack(-side => 'left');
      $cb->pack(-side => 'right');
      $newtop->bind( "<Return>", \&do_forward );
    }
}

sub show_details {
    my($i, @selfiles, @z_job);

    if (length($sendlist->get('active')) > 0) {
	@selfiles = $sendlist->curselection();
	for ($i = 0; $i <= $#selfiles; $i++) {
	    my $newtop = $faxmgrtop->Toplevel();
	    $newtop->title($LANG{'DETAILHEAD'});
	    my $det_ok = $newtop->Button(-text => 'OK',
					 -command => ['destroy', $newtop]);
	    my $det_txt = $newtop->Text(-relief => 'sunken',
					-setgrid => 'true');
	    my $det_s   = $newtop->Scrollbar(-command => ['yview', $det_txt]);
	    my $det_sh  = $newtop->Scrollbar(-command => ['xview', $det_txt],
					     -orient  => "horizontal");
	    $det_txt->configure(-yscrollcommand => ['set', $det_s ],
				-xscrollcommand => ['set', $det_sh],
				-wrap           => "none");
	    $det_ok->pack(-side => 'bottom');
	    $det_s->pack(-side => 'right', -fill => 'y');
	    $det_txt->pack(-expand => 'yes', -fill => 'both');
	    $det_sh->pack(-side => 'bottom', -fill => 'x');
	    $det_txt->tag('configure', 'bold', -font => $BOLDFONT);
	    open(JOBF, "$send_faxes[$selfiles[$i]]");
	    @z_job = <JOBF>;
	    close(JOBF);
	    $det_txt->insert("0.0", "\n\n\n\n\n\n\n");
	    $det_txt->insert("end", "                     Status\n", qw(bold));
	    for ($j = 0; $j <= $#z_job; $j++) {
		if ($z_job[$j] =~ /(pages) (.*)$/) {
		    $det_txt->insert("3.0", "$1", qw(bold));
		    $det_txt->insert("3.8", "$2");
		} elsif ($z_job[$j] =~ /(user) (.*)$/) {
		    $det_txt->insert("1.0", "$1  ", qw(bold));
		    $det_txt->insert("1.8", "$2");
		} elsif ($z_job[$j] =~ /(phone) (.*)$/) {
		    $det_txt->insert("2.0", "$1 ", qw(bold));
		    $det_txt->insert("2.8", "$2");
		} elsif ($z_job[$j] =~ /(input) (.*)$/) {
		    $det_txt->insert("4.0", "$1 ", qw(bold));
		    $det_txt->insert("4.8", "$2");
		} elsif ($z_job[$j] =~ /(time) (.*)$/) {
		    $det_txt->insert("5.0", "$1  ", qw(bold));
		    $det_txt->insert("5.8", "$2");
		} elsif ($z_job[$j] =~ /(normal_res)$/) {
		    $det_txt->insert("6.0", "Normal Resolution ", qw(bold));
		} elsif ($z_job[$j] =~ /(Status) (.*)$/) {
		    $det_txt->insert("end", "$2\n");
		}
	    }
	    reset 'z';
	}
    }
}

sub init_aliases {
    if (open(GLOBAL_ALIASES, "/usr/local/lib/fax-aliases")) {
	while (<GLOBAL_ALIASES>) {
	    chop;
	    next if /^#/;
	    $_ =~ /^(\S+)[ \t]+(.+)$/;
	    $rec_alias{$1} = $2;
	}
	close(GLOBAL_ALIASES);
    }
    my($home) = POSIX::getenv("HOME");
    $home .= "/.rec_fax_alias";
    if (open(LOCAL_ALIASES, $home)) {
	while (<LOCAL_ALIASES>) {
	    chop;
	    next if /^#/;
	    $_ =~ /^(\S+)[ \t]+(.+)$/;
	    $rec_alias{$1} = $2;
	}
	close(LOCAL_ALIASES);
    }
}

sub get_alias {
    my($nam_in) = pop(@_);

    if (defined $rec_alias{$nam_in}) {
	return $rec_alias{$nam_in};
    } else {
	return $nam_in;
    }
}

sub save_opts {
  my $optsname;

  $optsname = $ENV{'HOME'} . '/.faxmanrc';

  open(OPTS, ">$optsname");
  save_print_commands(*OPTS);
  save_view_commands(*OPTS);
  close(OPTS);
}

sub read_opts {
  my $optsname;

  $optsname = $ENV{'HOME'} . '/.faxmanrc';

  if (open(OPTS, $optsname)) {
  
    read_print_commands(*OPTS);		# Same order as above!
    read_view_commands(*OPTS);
    close(OPTS);
  }
}
