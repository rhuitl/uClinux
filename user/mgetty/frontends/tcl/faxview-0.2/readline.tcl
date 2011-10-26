# readline.tcl -- well known key bindings for Tk's entry widget.
#
# Copyright (C) 1995 Ralph Schleicher
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the Free
# Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


# Configure READLINE-CHARSET to suite your needs.
#
set readline-charset-iso-8859-1 "A-Za-zÀ-ÖØ-öø-ÿ"
set readline-charset ${readline-charset-iso-8859-1}

# The kill-ring (works application wide).
#
set readline-kill-ring {}

proc readline-add-to-kill-ring k {

    global readline-kill-ring

    set readline-kill-ring \
	    [linsert ${readline-kill-ring} 0 $k]
}

proc readline-last-kill {} {

    global readline-kill-ring

    return [lindex ${readline-kill-ring} 0]
}

proc readline-previous-kill {{n 1}} {

    global readline-kill-ring

    set length [llength ${readline-kill-ring}]
    if {$length > 1} {

	for {set i 0} {$i < $n} {incr i} {

	    set top [lindex ${readline-kill-ring} 0]

	    set readline-kill-ring \
		    [lrange ${readline-kill-ring} 1 end]

	    lappend readline-kill-ring $top
	}
    }
}

proc readline-next-kill {{n 1}} {

    global readline-kill-ring

    set length [llength ${readline-kill-ring}]
    if {$length > 1} {

	for {set i 0} {$i < $n} {incr i} {

	    set bottom [lindex ${readline-kill-ring} [expr $length - 1]]

	    set readline-kill-ring \
		    [lrange ${readline-kill-ring} 0 [expr $length - 2]]

	    set readline-kill-ring \
		    [linsert ${readline-kill-ring} 0 $bottom]
	}
    }
}

# Examine position of word boundaries.
#
set readline-end-of-word-regexp \
	^\[^${readline-charset}\]*\[${readline-charset}\]+

set readline-beginning-of-word-regexp \
	\[${readline-charset}\]+\[^${readline-charset}\]*\$

proc readline-upper-word-boundary w {

    global readline-end-of-word-regexp

    set point [$w index insert]
    set tail [string range [$w get] $point end]

    if [regexp -indices ${readline-end-of-word-regexp} $tail match] {

	return [expr $point + [lindex $match 1] + 1]
    }

    return end
}

proc readline-lower-word-boundary w {

    global readline-beginning-of-word-regexp

    set point [$w index insert]
    set head [string range [$w get] 0 [expr $point - 1]]

    if [regexp -indices ${readline-beginning-of-word-regexp} $head match] {

	return [lindex $match 0]
    }

    return 0
}

# Cursor movements.
#
proc readline-end-of-line w {

    $w icursor end
}

proc readline-beginning-of-line w {

    $w icursor 0
}

proc readline-forward-char w {

    $w icursor [expr [$w index insert] + 1]
}

proc readline-backward-char w {

    $w icursor [expr [$w index insert] - 1]
}

proc readline-forward-word w {

    $w icursor [readline-upper-word-boundary $w]
}

proc readline-backward-word w {

    $w icursor [readline-lower-word-boundary $w]
}

# Explicit kill and yank commands.
#
proc readline-clear-screen w {

    $w select clear
}

proc readline-set-mark w {

    $w select from [$w index insert]
}

proc readline-kill-region w {

    if [catch {set first [$w index sel.first]}] {

	$w select to [$w index insert]

	if [catch {set first [$w index sel.first]}] {

	    return
	}
    }

    set last [$w index sel.last]

    readline-add-to-kill-ring \
	    [string range [$w get] $first $last]

    $w delete $first $last
}

proc readline-yank w {

    $w insert insert [readline-last-kill]
}

# Other kill commands.
#
proc readline-delete-char w {

    $w delete insert
}

proc readline-kill-line w {

    set first [$w index insert]
    set last [$w index end]

    readline-add-to-kill-ring \
	    [string range [$w get] $first $last]

    $w delete $first $last
}

proc readline-backward-kill-line w {

    set last [expr [$w index insert] - 1]

    readline-add-to-kill-ring \
	    [string range [$w get] 0 $last]

    $w delete 0 $last
}

proc readline-kill-word w {

    set first [$w index insert]
    set last [readline-upper-word-boundary $w]

    if {$last != "end"} {

	set last [expr $last - 1]
    }

    readline-add-to-kill-ring \
	    [string range [$w get] $first $last]

    $w delete $first $last
}

proc readline-backward-kill-word w {

    set first [readline-lower-word-boundary $w]
    set last [expr [$w index insert] - 1]

    readline-add-to-kill-ring \
	    [string range [$w get] $first $last]

    $w delete $first $last
}

# Event bindings.
#
bind Entry <Control-Key-e> {readline-end-of-line %W}
bind Entry <Key-End> {readline-end-of-line %W}
bind Entry <Control-Key-a> {readline-beginning-of-line %W}
bind Entry <Key-Home> {readline-beginning-of-line %W}
bind Entry <Control-Key-f> {readline-forward-char %W}
bind Entry <Key-Right> {readline-forward-char %W}
bind Entry <Control-Key-b> {readline-backward-char %W}
bind Entry <Key-Left> {readline-backward-char %W}
bind Entry <Meta-Key-f> {readline-forward-word %W}
bind Entry <Control-Key-Right> {readline-forward-word %W}
bind Entry <Meta-Key-b> {readline-backward-word %W}
bind Entry <Control-Key-Left> {readline-backward-word %W}

bind Entry <Control-Key-l> {readline-clear-screen %W}
bind Entry <Control-Key-space> {readline-set-mark %W}
bind Entry <Control-Key-w> {readline-kill-region %W}
bind Entry <Control-Key-y> {readline-yank %W}
bind Entry <Key-Prior> {readline-previous-kill}
bind Entry <Key-Next> {readline-next-kill}

bind Entry <Control-Key-d> {readline-delete-char %W}
bind Entry <Key-Delete> {readline-delete-char %W}
bind Entry <Control-Key-k> {readline-kill-line %W}
bind Entry <Control-Key-End> {readline-kill-line %W}
bind Entry <Control-Key-Home> {readline-backward-kill-line %W}
bind Entry <Meta-Key-d> {readline-kill-word %W}
bind Entry <Meta-Key-Delete> {readline-backward-kill-word %W}


# set text {Hello, World!}
# pack [entry .t -textvar text]


# readline.tcl ends here
