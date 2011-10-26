#!/usr/bin/tkperl -w
#
# xfax -- simple X11 fax frontend for the command-line-impaired
#

push @INC, '/u/gert/mgetty/frontends/tkperl';

use Tk;
use Tk::XYListbox;
#use MyFileChooser;
#require 'mylbox.pl';
#use MyListBox;
#require 'mylbox.pl';

# current directory
$cdir=`pwd`;
chomp $cdir;

# configuration file for "standard file(s) buttons"
# Format: each line is a button, first field is the Label to put on it,
#         the following fields specify files to be sent when the button
#         is pressed. e.g.:
#  prices /usr/lib/prices.ps
#  offer  /usr/lib/offers*.g3
#
$xfax_auto="/usr/local/etc/mgetty+sendfax/xfax.autobuttons";

# default resolution ('' or '-n')
$fax_res = '';

# coverpage ('' or ' -C -'), default is "on". Memo text doesn't work yet.
$coverpage = '';

$headerfont="-adobe-times-medium-i-normal--18-*1";
$listboxfont="-adobe-courier-medium-r-*-12-*1";

# Initialize Toplevel
$pfaxtop = MainWindow->new();

# Top frame
$topframe = $pfaxtop->Frame( "-width" => 800 );

# Header line
$textlabel = $topframe->Label( "-text" => "Perl Fax 0.01 TEST",
			"-font" => $headerfont,
			"-borderwidth" => 3,
			"-relief" => "groove");

$textlabel->pack( "-side" => "top", "-fill" => "x" );

# LabeledEntry for fax number
$faxnr_frame = $topframe->Frame();
 $faxnr_label = $faxnr_frame->Label( "-text" => "Fax Number:",
				     "-borderwidth" => 3);
 $faxnr="";
 $faxnr_data  = $faxnr_frame->Entry( "-relief" => "sunken",
				     "-width" => "32",
				     "-textvariable" => \$faxnr);
 $faxnr_clear = $faxnr_frame->Button( "-text" => "clear",
			"-pady" => 1, "-command" => [ sub { $faxnr=''; } ] );

 $faxnr_label->pack( "-side" => "left", "-padx" => 4 );
 $faxnr_data ->pack( "-side" => "left", "-padx" => 4, 
		     "-fill" => "x", "-expand" => "1" );
 $faxnr_clear->pack( "-side" => "left" );

$faxnr_frame->pack( "-side" => "top", "-fill" => "x");

# LabeledEntry for receiver
$faxto_frame = $topframe->Frame;
 $faxto_label = $faxto_frame->Label( "-text" => "Receipient:",
				     "-borderwidth" => 3);
 $faxto="";
 $faxto_data  = $faxto_frame->Entry( "-relief" => "sunken",
				     "-width" => "32",
				     "-textvariable" => \$faxto);
 $faxto_clear = $faxto_frame->Button( "-text" => "clear",
			"-pady" => 1, "-command" => [ sub { $faxto=''; } ] );

 $faxto_label->pack( "-side" => "left", "-padx" => 4 );
 $faxto_data ->pack( "-side" => "left", "-padx" => 4,
		     "-fill" => "x", "-expand" => "1" );
 $faxto_clear->pack( "-side" => "left" );
$faxto_frame->pack( "-side" => "top", "-fill" => "x");

# Bind keyboard events
#$faxto_data->bind( "<a>", \&b_send );

# Send time / resolution on one line

$time_res_fr = $topframe->Frame;
# Send time input fields
$faxtime_fr = $time_res_fr->Frame;
$faxtime_l1 = $faxtime_fr->Label( "-text" => "Send time:",
				  "-borderwidth" => 3 );
$faxtime_h=$faxtime_m='';
$faxtime_d1 = $faxtime_fr->Entry( "-relief" => "sunken", "-width" => "2",
				  "-textvariable" => \$faxtime_h );
$faxtime_l2 = $faxtime_fr->Label( "-text" => ":" );
$faxtime_d2 = $faxtime_fr->Entry( "-relief" => "sunken", "-width" => "2",
				  "-textvariable" => \$faxtime_m );
$faxtime_l1->pack( "-side" => "left", "-padx" => "4" );
$faxtime_d1->pack( "-side" => "left" );
$faxtime_l2->pack( "-side" => "left" );
$faxtime_d2->pack( "-side" => "left" );
$faxtime_fr->pack( "-side" => "left", "-fill" => "x" );

# normal/fine resolution
$res_fr = $time_res_fr->Frame;
 $res_lb = $res_fr->Label( "-text" => "Resolution:" );
 $res_bn = $res_fr->Radiobutton( "-text" => "normal",
				 "-variable" => \$fax_res, "-value" => ' -n');
 $res_bf = $res_fr->Radiobutton( "-text" => "fine",
				 "-variable" => \$fax_res, "-value" => '');
 $res_lb->pack( "-side" => "left" );
 $res_bn->pack( "-side" => "left" );
 $res_bf->pack( "-side" => "left" );
$res_fr->pack( "-side" => "right", "-fill" => "x", "-anchor" => "e" );

$time_res_fr->pack( "-fill" => "x", "-expand" => 1 );

#
# File selector boxes, inside yet another frame
#
($topframe->Label( "-text" => "Files:" ))->
		pack( "-side" => "top", "-anchor" => "w" );

# Frame for the list boxes (file selector, buttons)
$listsframe = $topframe->Frame;

# Frame for File-Selector (I *love* nested frames)
$fs_frame = $listsframe->Frame;
 # Label
 $fs_label = $fs_frame->Label( "-text" => "Directory..." );
 $fs_label->pack( "-side" => "top", "-anchor" => "w" );

 # Entry field for the current path
 $cdir_in = $cdir;
 $fs_entry = $fs_frame->Entry(
			"-textvariable" => \$cdir_in,
			"-relief" => "sunken",
			"-font" => $listboxfont );
 $fs_entry->pack( "-side" => "top", "-fill" => "x", "-expand" => "1" ); 
 $fs_entry->bind( "<Return>", \&key_return_fs_entry );

 # Scrolledlistbox for File browser
# $filelist = $fs_frame->XYListbox(
 $filelist = $fs_frame->XYListbox(
			"-relief" => "groove",
			"-selectmode" => "extended",
			"-font" => $listboxfont );
 $filelist->pack( "-side" => "top", "-fill" => "both", "-expand" => "1" );
 $filelist->bind( "<Double-Button-1>", \&click_flist );
 $filelist->bind( "<Double-Button-2>", \&click_flist );

$fs_frame->pack( "-side" => "left", "-fill" => "both", "-expand" => "1" );

# Frame for buttons between lists
$listb_frame = $listsframe->Frame;

# Button for "gimme that file!"
$takebutton = $listb_frame->Button( "-text" => "-->",
				   "-command" => [ \&b_take ] );
$takebutton->pack( "-side" => "top", "-fill" => "x" );

# Button for "drop from list"
$rmvbutton  = $listb_frame->Button( "-text" => "remove",
			"-command" => [ \&b_remove ]);
$rmvbutton->pack( "-side" => "top", "-fill" => "x" );

# Button for "clean list"
$clearbutton= $listb_frame->Button( "-text" => "clear",
			"-command" => [ \&faxlist_clear ] );
$clearbutton->pack( "-side" => "top", "-fill" => "x" );

$listb_frame->pack( "-side" => "left" );

# Frame for "selected files"
$sf_frame = $listsframe->Frame;

 $sf_label = $sf_frame->Label( "-text" => "Documents to send:" );
 $sf_label->pack( "-side" => "top", "-anchor" => "w" );

# xylistbox fuer die "selection"??
 $xybox = $sf_frame->XYListbox(
			"-relief" => "sunken",
			"-font" => $listboxfont );
#$xybox->{XScrollbar}->configure( "-relief" => "ridge" );
#$xybox->{YScrollbar}->configure( "-relief" => "groove" );

 $xybox->pack( "-side" => "top", "-fill" => "both", "-expand" => "1" );

$sf_frame->pack( "-side" => "right", "-fill" => "both", "-expand" => 1 );

$listsframe->pack( "-fill" => "both", "-expand" => "1", "-pady" => "4" );

if ( open( AUTO, "$xfax_auto" ) )
{
    # Auto-Buttons below listboxes
    $midbotf = $topframe->Frame;
    while( <AUTO> )
    { 
	chomp;
	next if /^$/;
	next if /^#/;

	my( $label, @files ) = split;

    #    print "$label -> ", join( ' ', <@files>), "\n";

	$but = $midbotf->Button(
			"-text" => "$label",
		    "-command" => [ \&faxlist_addto, <@files>] );
	$but->pack( "-side" => "left" );
    }
    close( AUTO );
    $midbotf->pack;
}

# Text widget (for the "comment/memo" field on the cover page)

$tw_label = $topframe->Label( "-text" => "Memo text:" );
$tw_label->pack( "-anchor" => "w" );

$tw_fr = $topframe->Frame;
 $tw_data = $tw_fr->Text( "-height" => 6, "-width" => 60, "-wrap" => "none" );
 $tw_data->pack( "-side" => "left", "-fill" => "y", "-expand" => 1 );

 $tw_cp_fr = $tw_fr->Frame;
  $tw_cp_lb = $tw_cp_fr->Label( "-text" => "Coverpage" );
  $tw_cp_lb->pack( "-anchor" => "e" );
  $tw_cp_b1 = $tw_cp_fr->Radiobutton( "-text" => "on",
			     "-variable" => \$coverpage, "-value" => '' );
  $tw_cp_b1->pack( "-anchor" => "e" );
  $tw_cp_b0 = $tw_cp_fr->Radiobutton( "-text" => "off",
			     "-variable" => \$coverpage, "-value" => ' -C -' );
  $tw_cp_b0->pack( "-anchor" => "e" );
 $tw_cp_fr->pack( "-side" => "right" );
$tw_fr->pack( "-fill" => "both", "-expand" => 1 );


# button list
$button_f = $topframe->Frame;

# action button list, left side of the button lis
$acb_f = $button_f->Frame;

$send_b = $acb_f->Button("-text" => "*SEND*",
			 "-command" => [\&b_send] );
#$quit_b = $acb_f->Button("-text" => "exit",
#			 "-command" => [\&b_quit] );
$cmemo_b= $acb_f->Button("-text" => "clear memo",
		 "-command" => [ sub { $tw_data->delete( "1.0", "end" ); } ] );

# glue into frame
$send_b ->pack( "-side" => "left", "-padx" => 10 );
#$quit_b ->pack( "-side" => "left", "-padx" => 10 );
$cmemo_b->pack( "-side" => "left", "-padx" => 10 );
#$acb_f ->pack( "-side" => "left", "-fill" => "x", "-expand" => "1" );
$acb_f  ->pack( "-side" => "left", "-fill" => "x" );

# for experiments
#$hi_b = $button_f->Button( "-text" => "Hi!",
#			    "-command" => [\&b_hi] );
#$hi_b   ->pack( "-padx" => 10, "-side" => "right" );

# exit button
$quit_b2 = $button_f->Button( "-text" => "EXIT",
			    "-command" => [\&b_quit] );
$quit_b2->pack( "-padx" => 10, "-side" => "right" );

$button_f->pack( "-fill" => "x", "-expand" => 1 );

# set behaviour of TopFrame, pack
$topframe->pack(
#	"-side" => "bottom", "-pady" => 4, "-fill" => "both", "-padx" => 4);
	"-pady" => 4, "-padx" => 4, "-fill" => "both", "-expand" => 1 );

# Ende

$pfaxtop->maxsize( 800, 600 );
$pfaxtop->minsize( 200, 280 );
#wm("geometry", $pfaxtop, "200x280" );
$pfaxtop->title( "XPerlFax" );

&b_fill_list;
#
# command line arguments -> default file names
#
&faxlist_addto( @ARGV );

#
# build window, wait for user actions
#
Tk::MainLoop;

sub b_send {
    my $MemoText = $tw_data->get("1.0", "end");
    my $command = "faxspool";

    print "*SEND BUTTON*\n\n";
    print "Fax-Nr: $faxnr\n";

# options?

    if ( $faxto ne '' )
    {
	print "Verbose-To: $faxto\n";
	$command .= " -D \"$faxto\"";
    }
    if ( $faxtime_h ne '' || $faxtime_m ne '' )
    {
	if ( $faxtime_h =~ /^[0-9][0-9]$/ && 
	     $faxtime_m =~ /^[0-5][0-9]$/ &&
	     $faxtime_h >= 0 && $faxtime_h <=23 &&
	     $faxtime_m >= 0 && $faxtime_m <=59 )
	{
	    print "Time to send: $faxtime_h:$faxtime_m\n";
	    $command .= " -t $faxtime_h:$faxtime_m"
	}
	else
	{
	    alert( "Send time in wrong format!\nProper format: <hh:mm>\nData entered: <$faxtime_h:$faxtime_m>" );
	    return;
	}
    }

    print "Resolution:$fax_res\n";
    $command .= $fax_res;

    if ( chomp( $MemoText ) ne '' )		### TODO!!!
    {
	print "Memo-Text:\n$MemoText";
    }

    print "Coverpage:$coverpage\n";
    $command .= $coverpage;

# regular arguments: phone number, files to send

    if ( $faxnr eq '' )
    {
	alert( "Fax telephone number is missing!" );
	return;
    }

    my $tmp = $faxnr; $tmp =~ s/[\s()-]*//go;
    $command .= " $tmp ";

    if ( $#faxlist_names >= 0 )
    {
	$files = join( ' ', @faxlist_names );
        print "Files: $files\n";
	$command .= $files;
    }

    print "\ncommand: $command\n\n";

# now, execute command (for now, only with "system", but later, use window)
    my $cursor = ($pfaxtop->configure("-cursor"))[3];
    $pfaxtop->configure("-cursor" => "watch" );
    $pfaxtop->idletasks;

    alert( "Faxspool returned an error!" ) if (system $command) != 0;

    $pfaxtop->configure("-cursor" => $cursor );
}

sub b_quit { exit; }

sub b_hi {
    my $cursor = ($pfaxtop->configure("-cursor"))[3];
    $pfaxtop->configure("-cursor" => "watch" );
    $pfaxtop->idletasks;
    system "banner Hi!";
    $quit_b2->flash(); $quit_b2->flash();
    focus($faxto_data);
    sleep(2);
    $pfaxtop->configure("-cursor" => $cursor );
    alert("This was the HI! button");
}

sub b_fill_list {
    my $cursor = &cursor_watch;

    $filelist->delete(0, "end" );

    # read directory
    opendir(DIR, $cdir) or die "can't opendir $cdir: $!\n";
    foreach( sort(readdir(DIR)) ) 
    {
	chomp;
	next if $_ eq '.';
	$_ .= "/" if -d "$cdir/$_";
	$filelist->insert("end", $_);
    }
    closedir(DIR);

    $cdir_in = $cdir;				# for Entry field
    &cursor_restore( $cursor );
}

sub b_take {
    my $f;
    foreach( $filelist->curselection )
    {
	$f = $filelist->get( $_ );
	&faxlist_addto( $cdir . "/" . $f ) unless $f =~ /\/$/;
    }
    $filelist->selection( "clear", 0, "end" );
}

# double click into file list
sub click_flist {
    my $f;
    foreach( $filelist->curselection )
    {
	$f = $filelist->get( $_ );
	if ( $f =~ /(.*)\/$/ )			# directory?
	{
	    if ( $1 ne '..' ) 
	    {
		$cdir .= '/' . $1;
	    }
	    else
	    {
		$cdir =~ q!(.*)/[^/]*$!;
		$cdir = ($1 eq '') ? '/': $1;
	    }
	    $cdir =~ s!//!/!go;
	    &b_fill_list;
	}
	else					# normal file
	{
	    &faxlist_addto( $cdir . "/" . $f ) unless $f =~ /\/$/;
	}
    }
    $filelist->selection( "clear", 0, "end" );
}

# press return in file_selector entry field
sub key_return_fs_entry
{
    if ( -d $cdir_in ) {
	$cdir=$cdir_in;
	&b_fill_list;
    } elsif ( -f $cdir_in ) {
	&faxlist_addto( $cdir_in );
	$cdir_in =~ q!(.*)/[^/]*$!;
	$cdir = $1;
	&b_fill_list;
    } else {
	&alert("$cdir_in: no such file or directory!" );
    }
}


sub b_remove{
    foreach( $xybox->curselection )
    {
	&faxlist_remove( $_ );
    }
    $xybox->selection( "clear", 0, "end" );
}

#
# Liste der zu faxenden Dokumente loeschen
#
sub faxlist_clear {
    $xybox->delete( 0, "end" );
    @faxlist_names=();
}

#
# File in die Liste der zu faxenden Dokumente eintragen
#
sub faxlist_addto {
    foreach( @_ )
    {
	push @faxlist_names, $_;			# full name
	$_ =~ m!([^/]*)$!;
	$xybox->insert( "end", $1 );			# base name only
    }
}

#
# File nr. "$_" aus Liste loeschen
#
sub faxlist_remove {
    my $i = int($_[0]);
    my $n = $faxlist_names[$i];

    print "removing: $i ($n)\n";
#    @faxlist_names = @faxlist_names[0..$i-1,$i+1..$#faxlist_names];
    splice @faxlist_names, $i, 1;
    $xybox->delete( $i,$i );
}

#
# ALERT box -- barf loudly, display message, wait for "OK" click
#
sub alert
{
# new TopLevel window

    my $al_top = $pfaxtop->Toplevel;
    $al_top->title( "XPerlFax ERROR" );

    my $al_text = $al_top->Label( "-text" => "$_[0]" );
    my $al_close= $al_top->Button( "-text" => "close",
	    "-command" => [ sub{ my $top = shift; $top->grab("release");
	                         $top->wm( "withdraw" );
				 $top->destroy; }, $al_top ] );
    $al_text->pack( "-padx" => 10, "-pady" => 3 );
    $al_close->pack;
    $al_top->grab;
}

sub cursor_watch {
    my $cursor = ($pfaxtop->configure("-cursor"))[3];
    $pfaxtop->configure("-cursor" => "watch" );
    $pfaxtop->idletasks;

    return $cursor;
}

sub cursor_restore {
    $pfaxtop->configure( "-cursor" => $_[0] );
}
