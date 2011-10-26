# Tcl debugger library
#
# Author: Don Libes, NIST, May, 1994

# print scalar or array
proc p args {
	foreach arg $args {
		upvar $arg var
		if {0 == [catch {set var}]} {
			puts "$arg = $var"
		} elseif {0 == [catch {array size var}]} {
			set maxl 0
			foreach name [lsort [array names var]] {
				if {[string length $name] > $maxl} {
					set maxl [string length $name]
				}
			}
			set maxl [expr {$maxl + [string length $arg] + 2}]
			foreach name [lsort [array names var]] {
				set nameString [format %s(%s) $arg $name]
				puts stdout [format "%-*s = %s" $maxl $nameString $var($name)]
			}
		} else {
			puts "$arg: no such variable"
		}
	}
}
