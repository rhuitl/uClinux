# XScale CPU Definition - SG560/U/D, SG565, SG580, NG5100

set  _CHIPNAME ixp42x
set  _ENDIAN big
set _CPUTAPID 0x19277013

#reset_config srst_only srst_pulls_trst
reset_config srst_only

jtag newtap $_CHIPNAME cpu -irlen 7 -ircapture 0x1 -irmask 0x7f -expected-id $_CPUTAPID

set _TARGETNAME $_CHIPNAME.cpu
target create $_TARGETNAME xscale -endian $_ENDIAN -chain-position $_TARGETNAME -variant ixp42x

# The _TARGETNAME is set by the above.

$_TARGETNAME configure -work-area-virt 0 -work-area-phys 0x00020000 -work-area-size 0x10000 -work-area-backup 0

# General Utility Functions

proc uart_init { } {
	mww 0xc800000c 0x83
	mww 0xc8000000 0x08
	mww 0xc8000004 0x00
	mww 0xc800000c 0x03
	mww 0xc8000004 0x40
}

proc uart_print { char } {
	mww 0xc8000000 [format 0x%08x $char]
}

proc mem-init { } {
# set for 32MB (3CAS, 3RAS)
	mww 0xcc000000 0x18

# disable refresh
	mww 0xcc000004 0

# send NOP command
	mww 0xcc000008 0x03
	sleep 1000

# set refresh count
	mww 0xcc000004 0x384
	sleep 1000

# send PRECHARGE-ALL command
	mww 0xcc000008 0x02
	sleep 1000

# send AUTO-REFRESH command
	set num 8
	while {$num > 0} {
		mww 0xcc000008 0x04
		sleep 1000
		incr num -1
	}

# send MODE (CAS3) command
	mww 0xcc000008 0x01
	sleep 1000

# send NORMAL-OPERATION command
	mww 0xcc000008 0x06
	sleep 1000
}

#
#	Switch memory and expansion regions
#
proc mem-switch { } {
	mww 0x10000000 0xe3a01331
	mww 0x10000004 0xe3811020
	mww 0x10000008 0xe5912000
	mww 0x1000000c 0xe3c22102
	mww 0x10000010 0xe5812000
	reg pc 0x10000000
	stepi 5
}

#
#	Set BIG endian mode
#
proc big { } {
	mww 0x10000000 0xee110f10
	mww 0x10000004 0xe3800080
	mww 0x10000008 0xee010f10
	mww 0x1000000c 0xee120f10
	mww 0x10000010 0xe1a00000
	mww 0x10000010 0xe24ff004
	reg pc 0x10000000
	stepi 6
}

#
#	Enable the caches.
#
proc cache { } {
	mww 0x10000000 0xee110f10
	mww 0x10000004 0xe3800a01
	mww 0x10000008 0xe380000c
	mww 0x1000000c 0xee010f10
	mww 0x10000010 0xee120f10
	mww 0x10000014 0xe1a00000
	mww 0x10000018 0xe24ff004
	mww 0x1000001c 0xee071f15
	mww 0x10000020 0xee120f10
	mww 0x10000024 0xe1a00000
	mww x10000028 0xe24ff004
	reg pc 0x10000000
	stepi 0xb
}

#
#	Enable the PCI clock (which is on GPIO14)
#
proc pci-clock { } {
	mww 0xc8004004 0x00003fff
	mww 0xc8004018 0x000001ff
	mww 0xc8004000 0x00004000
}

#
#	Configure the flash region to be writable.
#
proc writable { } {
	mww 0x10000000 0xe3a01331
	mww 0x10000004 0xe5912000
	mww 0x10000008 0xe3822002
	mww 0x1000000c 0xe5812000
	reg pc 0x10000000
	stepi 4
}

#
#	Set MAC addresses in the appropriate place. Makes it easier
#	for redboot to work right...
#
proc mem-setmac { } {
mwb 0x1c000 0x00
mwb 0x1c001 0xcf
mwb 0x1c002 0xd0
mwb 0x1c003 0x00
mwb 0x1c004 0x00
mwb 0x1c005 0x00
mwb 0x1c006 0x01
mwb 0x1c007 0x00
}
