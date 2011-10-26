#!/usr/bin/expect --

#set send_slow {1 .1}
#proc send {ignore arg} {
#    sleep .1
#    exp_send -s -- $arg
#}

set timeout -1
puts "Program invoked with $argv\n"
set argl [split $argv]
set program [lindex $argl 0]
set script  [lindex $argl 1]
puts "Starting UML $program"
spawn $program single

expect -exact "normal startup):"
puts stderr "Logging in\n"
send -- "root\r"

set initscript [open $script r]
while {[gets $initscript line] >= 0} {
    # skip empty lines.
    if {[string length [string trimright $line]] == 0} {
	continue;
    }	
    if {[string match [string index [string trimleft $line] 0] \#] == 0} {
	expect -exact "# "
	send -- "$line\r"
    }
}

puts stderr "Initialization done\n"
if {[fork] != 0} exit

expect -exact "# "

#disconnect

expect eof




