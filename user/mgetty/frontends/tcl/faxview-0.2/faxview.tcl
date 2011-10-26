#! /usr/local/bin/wish
#
# faxview.tcl -- a simple dialog for viewing FAX messages.
#
# Copyright (C) 1994--1996 Ralph Schleicher <rs@purple.in-ulm.de>
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


# --------------------------------------------------------------
# Configuration section.
# --------------------------------------------------------------


# `$home_dir' is the startup directory and `$file_type' is the initial
# globbing pattern.
#
if [info exists env(FAXVIEW)] {

    set home_dir $env(FAXVIEW)

} else {

    set home_dir /var/spool/fax/incoming
}

set file_type *

# `$view_command' is the default command for viewing a FAX.  The
# variable `$f' will be replaced with the selected file name(s).
#
set view_command {viewfax $f &}
set print_command {g3topbm $f | pbmtolps | lpr &}

# Shall `$f' be replaced with multiple file names or with a single
# one?
#
set view_single 0
set print_single 1

# Shall multiple pages be displayed on a single line in the file
# selection box?
#
set multi_page 1

# Shall lines be truncated or wrapped in the logging window.
#
set wrap_lines 0


# --------------------------------------------------------------
# Basic initialization.
# --------------------------------------------------------------


# What is this.
#
wm title . FAXview

# Set the defaults.
#
set color_background	#dfdfdf		;# light gray
set color_active	#bfbfbf		;# medium gray
set color_disabled	#7f7f7f		;# dark gray
set color_foreground	#000000		;# black
set color_ground	#dfdfbf		;# gray-shaded ivory
set color_input		#ffffdf		;# light yellow
set color_selection	#ffdfbf		;# pale orange
set color_button	#bf5f5f		;# indian red
set color_highlight	$color_disabled

. configure \
	-background $color_background

option add *background $color_background
option add *foreground $color_foreground
option add *activeBackground $color_active
option add *activeForeground $color_foreground
option add *selectBackground $color_selection
option add *selectForeground $color_foreground
option add *insertBackground $color_foreground
option add *disabledForeground $color_disabled
option add *highlightColor $color_highlight
option add *troughColor $color_ground
option add *selector $color_button

option add *highlightThickness 0
option add *insertWidth 1

option add *Label.anchor w

option add *Message.anchor w

option add *Entry.relief sunken
option add *Entry.borderWidth 2
option add *Entry.background $color_input

option add *Listbox.relief sunken
option add *Listbox.borderWidth 2
option add *Listbox.background $color_input

option add *Scrollbar.relief sunken
option add *Scrollbar.borderWidth 2
option add *Scrollbar.width 15

option add *Menu.activeBorderWidth 2
option add *Menu.activeBackground $color_background

option add *Menubutton.activeBackground $color_background
option add *Menubutton.borderWidth 2

option add *Button.width 7
option add *Button.padX 2
option add *Button.padY 2
option add *Button.highlightThickness 1

option add *Radiobutton.relief flat
option add *Radiobutton.anchor w

option add *Checkbutton.relief flat
option add *Checkbutton.anchor w


# --------------------------------------------------------------
# A few general purpose widgets.
# --------------------------------------------------------------


proc xentry {path text variable} {

    global $variable

    frame $path

    pack [label $path.label -text $text] \
	    -fill x -anchor w

    pack [entry $path.entry -textvariable $variable] \
	    -fill x -anchor w

    return $path
}


proc xlistbox {path text args} {

    frame $path

    pack [label $path.label -text $text] \
	    -fill x -anchor w

    # `$path.listbox' must be created before `$path.list' and configured
    # afterwards (don't know why, must be black magic).
    #
    frame $path.listbox

    listbox $path.list \
	    -xscrollcommand "$path.horiz set" \
	    -yscrollcommand "$path.vert set"

    if {$args != ""} {

	eval $path.list configure $args
    }

    place $path.list \
	    -in $path.listbox \
	    -x 0 -y 0

    set width [winfo reqwidth $path.list]
    set height [winfo reqheight $path.list]

    $path.listbox configure \
	    -width [expr $width + 23] \
	    -height [expr $height + 23]

    pack $path.listbox

    # Next the scrollbars.  There is a gap of four points between them
    # and the listbox.
    #
    scrollbar $path.horiz \
	    -orient horizontal \
	    -command "$path.list xview"

    place $path.horiz \
	    -in $path.listbox -width $width \
	    -relx 0.0 -rely 1.0 -anchor sw

    scrollbar $path.vert \
	    -orient vertical \
	    -command "$path.list yview"

    place $path.vert \
	    -in $path.listbox -height $height \
	    -relx 1.0 -rely 0.0 -anchor ne

    return $path
}


proc xtoplevel {path title args} {

    toplevel $path \
	    -borderwidth 4

    wm title $path "FAXview: $title"

    return $path
}


set xdialog_seq 0

proc xdialog {title text args} {

    global xdialog_seq
    set dialog xdialog_#$xdialog_seq
    incr xdialog_seq

    xtoplevel .$dialog $title

    pack [frame .$dialog.message] \
	    -side top -fill both

    if [regexp {^(Error|Warning|Question|Info)$} $title] {

	pack [label .$dialog.message.bitmap -bitmap [string tolower $title]] \
		-side left -padx 4 -pady 4
    }

    pack [message .$dialog.message.text -text $text -width 3i] \
	    -side left -padx 4 -padx 4

    if {$args == ""} {

	if {$title == "Question"} {

	    set args {Yes No}

	} else {

	    set args OK
	}
    }

    pack [frame .$dialog.buttons] \
	    -side bottom -fill x

    pack [frame .$dialog.line -height 0] \
	    -side bottom -fill x -padx 4 -pady 4

    for {set i 0; set n [llength $args]} {$i < $n} {incr i} {

	button .$dialog.buttons.$i \
		-text [lindex $args $i] \
		-command "set $dialog $i; destroy .$dialog"

	pack .$dialog.buttons.$i \
		-side left -padx 4 -pady 4
    }

    global $dialog
    set $dialog [incr n -1]

    bind .$dialog <Return> ".$dialog.buttons.0 invoke"
    bind .$dialog <Escape> ".$dialog.buttons.$n invoke"

    grab set .$dialog

    set save [focus]
    focus .$dialog

    tkwait window .$dialog

    focus $save

    upvar 0 $dialog result
    return $result
}


# --------------------------------------------------------------
# FAXview itself.
# --------------------------------------------------------------


set curr_dir $home_dir
set curr_name ""


proc log_begin {} {

    .log.text configure -state normal
    .log.text insert end "[exec date {+%X %x}]: "
}


proc log_enter {args} {

    if {$args == ""} {

	.log.text insert end "\n"

    } else {

	.log.text insert end [join $args]
    }
}


proc log_end {} {

    if {[.log.text get {end lineend}] != "\n"} {

	.log.text insert end "\n"
    }

    .log.text configure -state disabled
    .log.text yview -pickplace end
}


proc log_entry {args} {

    log_begin
    log_enter [join $args]
    log_end
}


proc tkerror args {

    log_entry Tk: [join $args]
}


proc compare {command left right} {

    eval "expr \[$command $left\] - \[$command $right\]"
}


proc filenames {} {

    global curr_dir
    global curr_name

    if {$curr_name == ""} {

	log_entry {No filename selected}

	return ""
    }

    set files ""

    foreach n [split $curr_name] {

	# Non-matching files get lost without error message.
	#
	set t [glob -nocomplain $curr_dir/$n]

	if {[llength $t] > 0} {

	    eval lappend files $t
	}
    }

    if {$files == ""} {

	log_entry {No matching filename}
    }

    return $files
}


proc spawn {variable single {button ""} {log ""}} {

    upvar $variable command

    set files [filenames]

    if {$files == ""} {

	return
    }

    if {[llength $files] == 1} {

	set single 1
    }

    if {$button != ""} {

	$button flash
    }

    if {$log == ""} {

	set log "Invoking `$command'"
    }

    if $single {

	foreach f $files {

	    set d [file dirname $f]
	    set n [file tail $f]

	    eval "log_entry $log"

	    set res [catch "eval exec $command"]

	    if {$res != 0} {

		eval "log_entry $log -- failed"
	    }
	}

    } else {

	set f $files

	set first [lindex $files 0]

	set d "[file dirname $first]"
	set n "[file tail $first] ..."

	eval "log_entry $log"

	set res [catch "eval exec $command"]

	if {$res != 0} {

	    eval "log_entry $log -- failed"
	}
    }
}


proc do_view {} {

    global view_command view_single

    spawn view_command $view_single .button.view {$n: Viewing file}
}


proc do_print {} {

    global print_command print_single

    spawn print_command $print_single .button.print {$n: Printing file}
}


proc do_remove {} {

    set files [filenames]

    if {$files == ""} {

	return
    }

    foreach f $files {

	lappend n [file tail $f]
    }

    set b [xdialog Question "Do you really want to remove `[join $n {', `}]'?"]

    if {$b == 0} {

	set command {rm -f $f >/dev/null}

	spawn command 0 .button.remove {$n: Removing file}

	.button.update invoke
    }
}


proc do_update {} {

    global curr_dir
    global file_type
    global multi_page

    # We got the power ...
    #
    if [regexp {^[~/]} $file_type] {

	set path $file_type

    } else {

	if {$curr_dir == "/"} {

	    set path /$file_type

	} else {

	    set path $curr_dir/$file_type
	}
    }

    if [file isdirectory $path] {

	regsub {/?$} $path {&*} path
    }

    set directory [file dirname $path]

    if ![file readable $directory] {

	log_entry "$directory: Access denied\n"

	return 0
    }

    set curr_dir $directory
    set file_type [file tail $path]

    set match [lsort -command "compare {file mtime}" [glob -nocomplain $path]]

    .dialog.files.list delete 0 end
    .dialog.dirs.list delete 0 end

    if $multi_page {

	set pages {}

	foreach f $match {

	    if [file isdirectory $f] {

		continue
	    }

	    while 1 {

		if ![llength $pages] {

		    set name [file tail $f]
		    set base [file rootname $name]

		    if {$directory == "/"} {

			set root /$base

		    } else {

			set root $directory/$base
		    }

		    set ext [expr [string length $root] + 1]
		}

		if {[string first . $name] < 0} {

		    .dialog.files.list insert end $name

		    break;
		}

		if [string match $root.* $f] {

		    lappend pages [string range $f $ext end]

		    break;
		}

		if {[llength $pages] == 1} {

		    .dialog.files.list insert end $name

		} else {

		    .dialog.files.list insert end $base.\{[join $pages ,]\}
		}

		set pages {}
	    }
	}

	if {[llength $pages] == 1} {

	    .dialog.files.list insert end $name

	} elseif {[llength $pages] > 1} {

	    .dialog.files.list insert end $base.\{[join $pages ,]\}
	}

    } else {

	foreach f $match {

	    if ![file isdirectory $f] {

		.dialog.files.list insert end [file tail $f]
	    }
	}
    }

    if {$curr_dir != "/"} {

	.dialog.dirs.list insert end ".."
    }

    foreach f [lsort $match] {

	if [file isdirectory $f] {

	    set f [file tail $f]

	    if {$f != "." && $f != ".."} {

		.dialog.dirs.list insert end $f
	    }
	}
    }
}


proc do_home {} {

    global curr_dir
    global curr_name
    global home_dir

    set curr_dir $home_dir
    set curr_name ""

    .button.update invoke
}


proc set_name {} {

    global curr_name

    regsub -all "\n" [selection get] " " curr_name
}


proc set_dir {} {

    global curr_name
    global curr_dir

    # We should be able to go up, too.
    #
    if {$curr_dir == "."} {

	set dir [pwd]

    } else {

	set dir $curr_dir
    }

    # Apply the selection.
    #
    set sel [selection get]

    if {$sel == ".."} {

	set dir [file dirname $dir]

    } else {

	if {$dir != "/"} {

	    set dir "$dir/$sel"

	} else {

	    set dir "/$sel"
	}
    }

    # Check it out!
    #
    if ![file readable $dir] {

	return 0
    }

    # Deselect the filename.
    #
    set curr_dir $dir
    set curr_name ""
}


# Build the user interface.
#
. configure \
	-borderwidth 4

pack [frame .dialog] \
	-fill both -pady 4

xentry .dialog.name {Selected filenames:} curr_name
xentry .dialog.glob {Type of file:} file_type

pack .dialog.name [frame .dialog.gap -height 8] .dialog.glob \
	-fill x -padx 4

pack [frame .dialog.listboxes] \
	-fill both

xlistbox .dialog.files Files: -width 32 -height 8 -selectmode extended
xlistbox .dialog.dirs Directories: -width 32 -height 8 -selectmode single

pack .dialog.files .dialog.dirs \
	-in .dialog.listboxes \
	-side left -padx 4

checkbutton .dialog.files.multi_page \
	-text {Collect pages} -variable multi_page -command do_update

place .dialog.files.multi_page \
	-in .dialog.files.list \
	-relx 1.0 -y -2 -anchor se

pack [frame .command -borderwidth 4] \
	-fill both

pack [xentry .command.view {Viewing command:} view_command] \
	-fill x

checkbutton .command.view_single \
	-text {Single filenames} -variable view_single

place .command.view_single \
	-in .command.view.entry \
	-relx 1.0 -y -2 -anchor se

pack [xentry .command.print {Printing command:} print_command] \
	-fill x

checkbutton .command.print_single \
	-text {Single filenames} -variable print_single

place .command.print_single \
	-in .command.print.entry \
	-relx 1.0 -y -2 -anchor se

pack [frame .log -borderwidth 4] \
	-fill both

pack [label .log.label -text {Process information:}] \
	-fill x

text .log.text \
	-width 0 -height 6 \
	-padx 2 -state disabled \
	-relief sunken -borderwidth 2 \
	-yscrollcommand {.log.scrollbar set}

scrollbar .log.scrollbar \
	-command {.log.text yview}

pack .log.text \
	-side left -fill both -expand 1

pack .log.scrollbar [frame .log.gap -width 4] \
	-side right -fill y

checkbutton .log.wrap_lines \
	-text {Wrap lines} -variable wrap_lines -command set_wrap

place .log.wrap_lines \
	-in .log.text \
	-relx 1.0 -y -2 -anchor se

proc set_wrap {} {

    global wrap_lines

    if $wrap_lines {

	.log.text configure -wrap word

    } else {

	.log.text configure -wrap none
    }
}

set_wrap

proc buttons {args} {

    pack [frame .button] \
	    -side bottom -fill both

    while {[llength $args] > 1} {

	set t [lindex $args 0]
	set c [lindex $args 1]

	pack [button .button.[string tolower $t] -text $t -command $c] \
		-side left -padx 4 -pady 4

	set args [lrange $args 2 end]
    }

    pack [frame .seperator -height 8] \
	    -side bottom -fill x
}

buttons	View do_view \
	Print do_print \
	Remove do_remove \
	Update do_update \
	Home do_home \
	Exit exit

.button.update invoke

bind .dialog.name.entry <Return> {.button.view invoke}
bind .dialog.name.entry <Escape> {.button.exit invoke}
bind .dialog.glob.entry <Return> {.button.update invoke}
bind .dialog.glob.entry <Escape> {.button.exit invoke}
bind .command.view.entry <Return> {.button.view invoke}
bind .command.view.entry <Escape> {.button.exit invoke}
bind .command.print.entry <Return> {.button.print invoke}
bind .command.print.entry <Escape> {.button.exit invoke}

bind .dialog.files.list <ButtonRelease-1> \
	{set_name}
bind .dialog.files.list <Double-Button-1> \
	{set_name; .button.view invoke}
bind .dialog.dirs.list <Double-Button-1> \
	{set_dir; .button.update invoke}

log_entry {Starting session}
.log.text yview 0


# faxview.tcl ends here
