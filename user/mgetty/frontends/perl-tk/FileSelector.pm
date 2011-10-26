#
# FileSelector - a Fileselectorbox for choosing files 
#
# Klaus Lichtenwalder, Datapat GmbH, Munich, April 22, 1995
# Lichtenwalder@ACM.org
#
# --------------------------------------------------------------------
#
# use Tk::FileSelector;
#
# $FSref = $top->FileSelector($start_dir);
#
#		$top		- a window reference, e.g. MainWindow->new
#		$start_dir	- the starting point for the FileSelector
# $FSref = $top->Show;
#               Executes the fileselector until either a filename is
#               accepted or the user hits Cancel. Returns the filename
#               or the empty string, respectively, and unmaps the
#               FileSelector.
# $FSref = $top->configure(option => value[, ...])
#               At the moment, only one option is taken care of:
#                 -directory changes the starting directory for the
#                  Fileselector to the one given as value.
#
# Actions:
#   This Module pops up a Fileselector box, with a directory entry on
#   top, a list of directories in the current directory, a list of
#   files in the current directory, an entry for entering/modifying a
#   file name, an accept button and a cancel button.
#
#   You can enter a starting directory in the directory entry. After
#   hitting Return, the listboxes get updated. Double clicking on any
#   directory shows you the respective contents. Single clicking on a
#   file brings it into the file entry for further consideration,
#   double clocking on a file pops down the file selector and calls
#   the optional command with the complete path for the selected file.
#   Hitting return in the file selector box or pressing the accept
#   button will also work. *NOTE* the file selector box will only then
#   get destroyed if the file name is not zero length. If you want
#   yourself take care of it, change the if(length(.. in sub
#   accept_file.
#
# By request of Henry Katz <katz@fs09.webo.dg.com>, I added the functionality
# of using the Directory entry as a filter. So, if you want to only see the
# *.c files, you add a .c (the *'s already there :) and hit return.

package Tk::FileSelector;
@ISA = qw(Tk::Composite Tk::Toplevel);
(bless \qw(FileSelector))->WidgetClass;

use Carp;
use English;
use Tk;
use Tk::Dialog;

sub new {
    my($class, $path, $dir) = @ARG;

    my $FileChooserTop = $path->Toplevel(-class => 'FileSelector');
    $FileChooserTop = bless $FileChooserTop, $class;
    $FileChooserTop->title($dir);
    $FileChooserTop->iconname($dir);
    $FileChooserTop->protocol('WM_DELETE_WINDOW' => sub {});
    $FileChooserTop->transient($FileChooserTop->parent->toplevel);

    $FileChooserTop->{'act_dir'} = $dir;
    $FileChooserTop->{'LastPath'} = $dir;
    $FileChooserTop->{'selected_file'} = '';

    my $top_f = $FileChooserTop->Frame(-relief      => 'flat',
				       -borderwidth => 2);
    $top_f->pack(-side => 'top',
		 -padx => 3,
		 -pady => 2);
    my $dir_entry_label = $top_f->Label(-text         => 'Directory');
    my $dir_entry_entry = $top_f->Entry(-relief       => 'sunken',
					-width        => 30,
					-textvariable => \$FileChooserTop->{'act_dir'});
    $dir_entry_entry->bind('<Return>',
			   sub {&change_dir($FileChooserTop);});
    $dir_entry_label->pack(-side => 'left');
    $dir_entry_entry->pack(-side   => 'left',
			   -fill   => 'x',
			   -expand => 'y');

    my $dir_entry_middle = $FileChooserTop->Frame();
    $dir_entry_middle->pack(-side => 'top',
			    -fill   => 'both',
			    -expand => 'yes');
    my $dir_entry_dir_frame = $dir_entry_middle->Frame();
    $dir_entry_dir_frame->pack(-side   => 'left',
			       -fill   => 'both',
			       -expand => 'yes');
    my $dir_entry_dir_label =
	$dir_entry_dir_frame->Label(-text => 'Directories:');
    $dir_entry_dir_label->pack(-side => 'top');
    my $dir_entry_dir_yscroll = $dir_entry_dir_frame->Scrollbar();
    my $dir_entry_dir_xscroll =
	$dir_entry_dir_frame->Scrollbar(-orient => 'horizontal');
    $FileChooserTop->{'dir_entry_dir_list'} =
	$dir_entry_dir_frame->Listbox(-relief  => 'sunken',
				      -width   => 20,
				      -height  => 8,
				      -xscrollcommand => [ 'set',
							  $dir_entry_dir_xscroll],
				      -yscrollcommand => [ 'set',
							  $dir_entry_dir_yscroll],
				      -setgrid => '1');
    $dir_entry_dir_xscroll->configure(-command => [ 'xview',
						   $FileChooserTop->{'dir_entry_dir_list'}]);
    $dir_entry_dir_yscroll->configure(-command => [ 'yview',
						   $FileChooserTop->{'dir_entry_dir_list'}]);
    $dir_entry_dir_yscroll->pack(-side => 'right', -fill => 'y');
    $dir_entry_dir_xscroll->pack(-side => 'bottom', -fill => 'x');
    $FileChooserTop->{'dir_entry_dir_list'}->pack(-side   => 'bottom',
			      -fill   => 'both',
			      -expand => 'yes');

    $FileChooserTop->{'dir_entry_dir_list'}->bind('<Double-Button-1>'
			      => sub {
				  $FileChooserTop->{'act_dir'} =
				      $FileChooserTop->{'dir_entry_dir_list'}->
					  get($FileChooserTop->{'dir_entry_dir_list'}->curselection);
				  &change_dir($FileChooserTop);
			      });
							       
    my $dir_entry_fil_frame = $dir_entry_middle->Frame();
    $dir_entry_fil_frame->pack(-side   => 'right',
			       -fill   => 'both',
			       -expand => 'yes');
    my $dir_entry_fil_label =
	$dir_entry_fil_frame->Label(-text => 'Files:');
    $dir_entry_fil_label->pack(-side => 'top');

    my $dir_entry_fil_yscroll =
	$dir_entry_fil_frame->Scrollbar();
    my $dir_entry_fil_xscroll =
	$dir_entry_fil_frame->Scrollbar(-orient => 'horizontal');
    $FileChooserTop->{'dir_entry_fil_list'} =
	$dir_entry_fil_frame->Listbox(-relief  => 'sunken',
				      -width   => 20,
				      -height  => 8,
				      -xscrollcommand => [ 'set',
							  $dir_entry_fil_xscroll],
				      -yscrollcommand => [ 'set',
							  $dir_entry_fil_yscroll]);
    $dir_entry_fil_xscroll->configure(-command => [ 'xview',
						   $FileChooserTop->{'dir_entry_fil_list'}]);
    $dir_entry_fil_yscroll->configure(-command => [ 'yview',
						   $FileChooserTop->{'dir_entry_fil_list'}]);
    $dir_entry_fil_yscroll->pack(-side => 'right', -fill => 'y');
    $dir_entry_fil_xscroll->pack(-side => 'bottom', -fill => 'x');
    $FileChooserTop->{'dir_entry_fil_list'}->bind('<Button-1>'
			      => sub {
				  $FileChooserTop->{'act_file'} =
				      $FileChooserTop->{'dir_entry_fil_list'}->
					  get($FileChooserTop->{'dir_entry_fil_list'}->curselection);
			       });
    $FileChooserTop->{'dir_entry_fil_list'}->bind('<Double-Button-1>'
			      => sub {
				  $FileChooserTop->{'act_file'} =
				      $FileChooserTop->{'dir_entry_fil_list'}->
					  get($FileChooserTop->{'dir_entry_fil_list'}->curselection);
				  &accept_file($FileChooserTop);
			       });
    $FileChooserTop->{'dir_entry_fil_list'}->pack(-side   => 'right',
			      -fill   => 'both',
			      -expand => 'yes');

    my $dir_entry_lower = $FileChooserTop->Frame(-relief => 'flat');
    $dir_entry_lower->pack(-side => 'bottom');
    my $bot_f = $dir_entry_lower->Frame(-relief      => 'flat',
					-borderwidth => 2);
    my $fil_entry_label = $bot_f->Label(-text         => 'File');
    my $fil_entry_entry = $bot_f->Entry(-relief       => 'sunken',
					-width        => ' 30',
					-textvariable => \$FileChooserTop->{'act_file'},);
    $fil_entry_entry->bind('<Return>', sub { &accept_file($FileChooserTop);});
    $fil_entry_label->pack(-side => 'left');
    $fil_entry_entry->pack(-side   => 'right',
			   -fill   => 'x',
			   -expand => 'y');
    $bot_f->pack(-side => 'top',
		 -padx => 3,
		 -pady => 2);

    my $dir_entry_btn_frm = $dir_entry_lower->Frame(-relief => 'flat');
    $dir_entry_btn_frm->pack(-side   => 'bottom',
			     -expand => 'y',
			     -fill   => 'x');
    my $dir_entry_btn_acc =
	$dir_entry_btn_frm->Button(-text    => 'Accept',
				   -command =>
				   sub { &accept_file($FileChooserTop); },
				   -relief  => 'raised');
    $dir_entry_btn_acc->pack(-side => 'left',
			     -padx => 5);
    my $dir_entry_btn_cnc =
	$dir_entry_btn_frm->Button(-text    => 'Cancel',
				   -command => sub {
				       $FileChooserTop->{'selected_file'} = '';
				       },
				   -relief  => 'raised');
    $dir_entry_btn_cnc->pack(-side => 'right',
			     -padx => 5);
    
    $FileChooserTop->withdraw;
    $FileChooserTop->{'ErrorPopup'} = $FileChooserTop->Dialog($MISCERR_TXT,
					  'Hi there', # Defined
					  'error',    # at popup time
					  'OK', # 
					  ('OK'));
    &change_dir($FileChooserTop);		# Initial Fill-In
    return $FileChooserTop;
}

sub translate {
    my ($fil_regex) = @_;
    my (@in, @out, $bs_seen);

    @in = split(//, $fil_regex);
    $bs_seen = 0;
    foreach $chr (@in) {
	if ($chr eq '?') {
	    if ($bs_seen == 1) {
		push(@out, '?');
	    } else {
		push(@out, '.');
	    }
	    $bs_seen = 0;
	} elsif ($chr eq '*') {
	    if ($bs_seen == 1) {
		push(@out, '\\');
		push(@out, '*');
	    } else {
		push(@out, '.');
		push(@out, '*');
	    }
	    $bs_seen = 0;
	} elsif ($chr eq '\\') {
	    if ($bs_seen == 1) {
		push(@out, '\\');
		push(@out, '\\');
		$bs_seen = 0;
	    } else {
		$bs_seen = 1;
	    }
	} elsif ($chr eq '.') {
	    push(@out, '\\');
	    push(@out, '.');
	    $bs_seen = 0;
	} elsif ($chr eq '/') {	# / not allowed!!
	    push(@out, '\\');
	    push(@out, '/');
	    $bs_seen = 0;
	} else {
	    push(@out, $chr);
	    $bs_seen = 0;
	}
    }
    return join('', @out);
}

sub get_filter {
    my($dir) = @_;
    my($realdir, $filter);

    if (-d $dir) {		# Exists and is dir
	return ($dir, '*');
    }

    $dir =~ m|^(.*)/([^/]+)$|;	# Get Dirname & Basename

    if (defined $1) {		# If match succeeded
	$realdir = $1;		#   It were two real parts
	$filter = $2;
    } else {
	$realdir = '.';		# Assume only filter given on command line
	$filter = $dir;
    }
    return ($realdir, $filter);
}

my $firsttime = 1;
sub change_dir {		# Change Directory and fill lists
    my ($w) = @_;
    my ($real_dir, $filter, $code);

    my $cursor = ($w->configure("-cursor"))[3];
    $w->configure("-cursor" => "watch" );

    # Don't flush X's output queue in the contructor.
    $w->idletasks unless $firsttime;
    $firsttime = 0; 

    $w->{'dir_entry_dir_list'}->delete(0, "end");
    $w->{'dir_entry_fil_list'}->delete(0, "end");

    chdir($w->{'LastPath'});	# Somebody might have changed it...

    ($real_dir, $filter) = &get_filter($w->{'act_dir'});
    if (! -d $real_dir) {
	$w->{'ErrorPopup'}->configure('Message',
			       -text => ($real_dir . " does not exist"));
	$w->{'ErrorPopup'}->Show;
	if (!defined ($real_dir = $ENV{'HOME'})) {
	    $real_dir = '/';
	}
	$w->{'act_dir'} = $real_dir;
    }

    # get_filter called a second time, because if the directory didn;t
    # exist, $real_dir and $filter are wrong;
    ($real_dir, $filter) = &get_filter($w->{'act_dir'});

    chdir($real_dir);
    $w->{'act_dir'} = `pwd`;
    chomp($w->{'act_dir'});

    $w->{'LastPath'} = $w->{'act_dir'};	# Remember it

    opendir(DIR, $w->{'act_dir'});

    $w->{'act_dir'} .= '/' . $filter;	# For dir-entry
    $filter = &translate($filter); # for file globbing

    $code = "if (\$fil =~ /^$filter\$/) {
	    \$w->{'dir_entry_fil_list'}->insert('end', \$fil);
}";
    foreach $fil (sort(readdir(DIR))) { # First, the Dirs, subject to no globbing
	next if ($fil eq '.');
	if ( -d $fil) {
	    $w->{'dir_entry_dir_list'}->insert('end', $fil);
	} else {
	    eval $code;
	}
    }
    closedir(DIR);

    $w->configure("-cursor" => $cursor );
}

sub accept_file {
    my ($w) = @_;
    my($real_dir, $filter);
    if (length($w->{'act_file'}) > 0) {
	($real_dir, $filter) = &get_filter($w->{'act_dir'});
	$w->{'selected_file'} = $real_dir . '/' . $w->{'act_file'};
    }
}

sub configure {
    my($w, %config) = @ARG;

    my $real_w;

    croak "FileSelector: `configure' method was not invoked with a \"Tk::FileSelector\" object" unless $w->IsFileSelector;
    croak "FileSelector: `configure' method requires at least 3 arguments" if scalar @ARG < 2;

    foreach $attr (keys %config) {
	if ($attr eq -directory) {
	    $w->{'act_dir'} = $config{$attr};
	    &change_dir($w);
	} else {
	    $w->Tk::Widget::configure($attr, $config{$attr});
	}
    }
    return $w;
}

sub Show {
    my ($w, $grab_type) = @ARG;

    croak "FileSelector: `show' method was not invoked with a \"Tk::FileSelector\" object" unless $w->IsFileSelector;
    croak "FileSelector: `show' method requires at least 1 argument" if scalar @ARG < 1;

    update('idletasks');
    my $winpar = $w->parent;
    my $winvx = $winpar->vrootx;
    my $winvy = $winpar->vrooty;
    my $winrw = $w->reqwidth;
    my $winrh = $w->reqheight;
    my $winsw = $w->screenwidth;
    my $winsh = $w->screenheight;
    my $x = int($winsw/2-$winrw/2-$winvx);
    my $y = int($winsh/2-$winrh/2-$winvy);
    $w->geometry("+$x+$y");
    $w->{'act_file'} = '';
    $w->deiconify;
    my $old_focus = Tk->focus();
    if ($grab_type) {
	$w->grab($grab_type);
    } else {
	$w->grab;
    }
    tkwait('visibility', $w);
    $w->focus;
    tkwait('variable' => \$w->{'selected_file'});
    $old_focus->focus if defined $old_focus;
    $w->grab('release');
    $w->withdraw;

    return $w->{'selected_file'};
}

1;
