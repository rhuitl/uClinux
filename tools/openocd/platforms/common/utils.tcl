# General utility functions for all platforms

proc stepi { i } {
	set j $i	
	while {$j > 0} {
		step
		incr j -1
	}
}

proc mrw {addr} {
    set val ""
	mem2array val 32 $addr 1
	return [format 0x%x $val(0)]
}

proc mem-fill { a v } {
	set addr $a
	set val $v
	set num 0
	while { $num < 0x1000 } {
		mww $addr $val
		incr addr 4
		incr num
	}
}

proc mem-check { a v } {
	set num 0
	set addr $a
	set val $v
	while { $num < 0x1000 } {
		set rd [mrw $addr] 
		if { $rd != $val } {
			echo $addr
		}
		incr addr 4
		incr num
	}
}

proc mem_test {{addr 0x0} {len 8192}} {
	set a $addr
	for {set i 0} {$i < $len} {incr i; incr a 4} {
		mww $a $a
	}
	set a $addr
	for {set i 0} {$i < $len} {incr i; incr a 4} {
		set b [mrw $a]
		if {$a != $b} {
			puts "[format 0x%08x $a]: [format 0x%08x $a] != [format 0x%08x $b]"
		}
	}
	foreach val {0xffffffff 0x00000000 0xaaaaaaaa 0x55555555} {
		set a $addr
		for {set i 0} {$i < $len} {incr i; incr a 4} {
			mww $a $val
		}
		set a $addr
		for {set i 0} {$i < $len} {incr i; incr a 4} {
			set b [mrw $a]
			if {$val != $b} {
				puts "[format 0x%08x $a]: $val != [format 0x%08x $b]"
			}
		}
	}
}

