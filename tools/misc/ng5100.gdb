#
#	CyberGuard/SE5100 (aka ATT/NG5100) target gdbinit script.
#

#
#	UART functions
#

define uart-init
set *((long*) 0xc800000c) = 0x83
set *((long*) 0xc8000000) = 0x08
set *((long*) 0xc8000004) = 0x00
set *((long*) 0xc800000c) = 0x03
set *((long*) 0xc8000004) = 0x40
end

define uart-print
set *((long*) 0xc8000000) = $arg0
end


#
#	Memory functions
#

define mem-init
# set for 64MB (3CAS, 3RAS)
set *((long*) 0xcc000000) = 0x1a

# disable refresh
set *((long*) 0xcc000004) = 0

# send NOP command
set *((long*) 0xcc000008) = 0x03
shell sleep 1

# set refresh count
set *((long*) 0xcc000004) = 0x384
shell sleep 1

# send PRECHARGE-ALL command
set *((long*) 0xcc000008) = 0x02
shell sleep 1

# send AUTO-REFRESH command
set $num = 8
while ($num > 0)
	set *((long*) 0xcc000008) = 0x04
	shell sleep 1
	set $num = $num - 1
end

# send MODE (CAS3) command
set *((long*) 0xcc000008) = 0x01
shell sleep 1

# send NORMAL-OPERATION command
set *((long*) 0xcc000008) = 0x06
shell sleep 1

end



#
#	Switch memory and expansion regions
#
define mem-switch
set *((unsigned long *) 0x10000000) = 0xe3a01331
set *((unsigned long *) 0x10000004) = 0xe3811020
set *((unsigned long *) 0x10000008) = 0xe5912000
set *((unsigned long *) 0x1000000c) = 0xe3c22102
set *((unsigned long *) 0x10000010) = 0xe5812000
set $pc = 0x10000000
stepi 5
end


define mem-fill
set $num = 0
set $addr = $arg0
set $val = $arg1
while ($num < 0x1000)
	set *((unsigned long *) $addr) = $val
	set $addr = $addr + 4
	set $num = $num + 1
end
end


define mem-check
set $num = 0
set $addr = $arg0
set $val = $arg1
while ($num < 0x1000)
	set $rd = *((unsigned long *) $addr)
	if ($rd != $val)
		print $addr
	end
	set $addr = $addr + 4
	set $num = $num + 1
end
end


#
#	Set BIG endian mode
#
define big
set *((unsigned long *) 0x10000000) = 0xee110f10
set *((unsigned long *) 0x10000004) = 0xe3800080
set *((unsigned long *) 0x10000008) = 0xee010f10
set *((unsigned long *) 0x1000000c) = 0xee120f10
set *((unsigned long *) 0x10000010) = 0xe1a00000
set *((unsigned long *) 0x10000010) = 0xe24ff004
set $pc = 0x10000000
stepi 6
end

#
#	Enable the caches.
#
define cache
set *((unsigned long *) 0x10000000) = 0xee110f10
set *((unsigned long *) 0x10000004) = 0xe3800a01
set *((unsigned long *) 0x10000008) = 0xe380000c
set *((unsigned long *) 0x1000000c) = 0xee010f10
set *((unsigned long *) 0x10000010) = 0xee120f10
set *((unsigned long *) 0x10000014) = 0xe1a00000
set *((unsigned long *) 0x10000018) = 0xe24ff004
set *((unsigned long *) 0x1000001c) = 0xee071f15
set *((unsigned long *) 0x10000020) = 0xee120f10
set *((unsigned long *) 0x10000024) = 0xe1a00000
set *((unsigned long *) 0x10000028) = 0xe24ff004
set $pc = 0x10000000
stepi 0xb
end

#
#	Enable the PCI clock (which is on GPIO14)
#
define pci-clock
set *((unsigned long *) 0xc8004004) = 0x00003fff
set *((unsigned long *) 0xc8004018) = 0x000001ff
set *((unsigned long *) 0xc8004000) = 0x00004000
end

#
#	Configure the flash region to be writable.
#
define writable
set *((unsigned long *) 0x10000000) = 0xe3a01331
set *((unsigned long *) 0x10000004) = 0xe5912000
set *((unsigned long *) 0x10000008) = 0xe3822002
set *((unsigned long *) 0x1000000c) = 0xe5812000
set $pc = 0x10000000
stepi 4
end

#
#	Initialize the LEDs
#
define set-led
set *((unsigned long *) 0x10000000) = 0xe59f1004
set *((unsigned long *) 0x10000004) = 0xe59f2004
set *((unsigned long *) 0x10000008) = 0xe5812000
set *((unsigned long *) 0x1000000c) = 0xc4000008
set *((unsigned long *) 0x10000010) = 0xbfff0003
set $pc = 0x10000000
stepi 3
set *((unsigned char *) 0x52000000) = $arg0
end

#
#	FLASH writing code (16bit functions)
#
define flash-erase
set $r1 = $arg0
set *((unsigned long *) 0x10000004) = 0xe3a02020
set *((unsigned long *) 0x10000008) = 0xe3822a02
set *((unsigned long *) 0x1000000c) = 0xe1c120b0
set *((unsigned long *) 0x10000010) = 0xe3a020d0
set *((unsigned long *) 0x10000014) = 0xe3822a0d
set *((unsigned long *) 0x10000018) = 0xe1c120b0
set $pc = 0x10000004
stepi 6
shell sleep 2
set *((unsigned long *) 0x10000000) = 0xe3a020ff
set *((unsigned long *) 0x10000004) = 0xe3822cff
set *((unsigned long *) 0x10000008) = 0xe1c120b0
set $pc = 0x10000000
stepi 3
end

define flash-erase1
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3a02020
set *((unsigned long *) 0x10000008) = 0xe3822a02
set *((unsigned long *) 0x1000000c) = 0xe1c120b0
set *((unsigned long *) 0x10000010) = 0xe3a020d0
set *((unsigned long *) 0x10000014) = 0xe3822a0d
set *((unsigned long *) 0x10000018) = 0xe1c120b0
set $pc = 0x10000000
stepi 7
shell sleep 2
set *((unsigned long *) 0x10000000) = 0xe3a020ff
set *((unsigned long *) 0x10000004) = 0xe3822cff
set *((unsigned long *) 0x10000008) = 0xe1c120b0
set $pc = 0x10000000
stepi 3
end

define flash-erase2
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3811802
set *((unsigned long *) 0x10000008) = 0xe3a02020
set *((unsigned long *) 0x1000000c) = 0xe3822a02
set *((unsigned long *) 0x10000010) = 0xe1c120b0
set *((unsigned long *) 0x10000014) = 0xe3a020d0
set *((unsigned long *) 0x10000018) = 0xe3822a0d
set *((unsigned long *) 0x1000001c) = 0xe1c120b0
set $pc = 0x10000000
stepi 8
shell sleep 2
set *((unsigned long *) 0x10000000) = 0xe3a020ff
set *((unsigned long *) 0x10000004) = 0xe3822cff
set *((unsigned long *) 0x10000008) = 0xe1c120b0
set $pc = 0x10000000
stepi 3
end

define flash-unlock
set $r1 = $arg0
set *((unsigned long *) 0x10000004) = 0xe3a02060
set *((unsigned long *) 0x10000008) = 0xe3822a06
set *((unsigned long *) 0x1000000c) = 0xe1c120b0
set *((unsigned long *) 0x10000010) = 0xe3a020d0
set *((unsigned long *) 0x10000014) = 0xe3822a0d
set *((unsigned long *) 0x10000018) = 0xe1c120b0
set *((unsigned long *) 0x1000001c) = 0xe3a020ff
set *((unsigned long *) 0x10000020) = 0xe3822cff
set *((unsigned long *) 0x10000024) = 0xe1c120b0
set $pc = 0x10000004
stepi 9
end

define flash-unlock1
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3a02060
set *((unsigned long *) 0x10000008) = 0xe3822a06
set *((unsigned long *) 0x1000000c) = 0xe1c120b0
set *((unsigned long *) 0x10000010) = 0xe3a020d0
set *((unsigned long *) 0x10000014) = 0xe3822a0d
set *((unsigned long *) 0x10000018) = 0xe1c120b0
set *((unsigned long *) 0x1000001c) = 0xe3a020ff
set *((unsigned long *) 0x10000020) = 0xe3822cff
set *((unsigned long *) 0x10000024) = 0xe1c120b0
set $pc = 0x10000000
stepi 10
end

define flash-unlock2
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3811802
set *((unsigned long *) 0x10000008) = 0xe3a02060
set *((unsigned long *) 0x1000000c) = 0xe3822a06
set *((unsigned long *) 0x10000010) = 0xe1c120b0
set *((unsigned long *) 0x10000014) = 0xe3a020d0
set *((unsigned long *) 0x10000018) = 0xe3822a0d
set *((unsigned long *) 0x1000001c) = 0xe1c120b0
set *((unsigned long *) 0x10000020) = 0xe3a020ff
set *((unsigned long *) 0x10000024) = 0xe3822cff
set *((unsigned long *) 0x10000028) = 0xe1c120b0
set $pc = 0x10000000
stepi 11
end

define flash-id
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3a02090
set *((unsigned long *) 0x10000008) = 0xe3822a09
set *((unsigned long *) 0x1000000c) = 0xe1c120b0
set $pc = 0x10000000
stepi 4
end

define flash-program
set *((unsigned long *) 0x10100000) = 0xe3a01205
set *((unsigned long *) 0x10100004) = 0xe3a02040
set *((unsigned long *) 0x10100008) = 0xe3822901
set *((unsigned long *) 0x1010000c) = 0xe3a03080
set *((unsigned long *) 0x10100010) = 0xe3a040ff
set *((unsigned long *) 0x10100014) = 0xe3844cff
set *((unsigned long *) 0x10100018) = 0xe3a05000
set *((unsigned long *) 0x1010001c) = 0xe3a06701
set *((unsigned long *) 0x10100020) = 0xe1c120b0
set *((unsigned long *) 0x10100024) = 0xe1d570b0
set *((unsigned long *) 0x10100028) = 0xe1c170b0
set *((unsigned long *) 0x1010002c) = 0xe1d170b0
set *((unsigned long *) 0x10100030) = 0xe1170003
set *((unsigned long *) 0x10100034) = 0x0afffffc
set *((unsigned long *) 0x10100038) = 0xe1c140b0
set *((unsigned long *) 0x1010003c) = 0xe2811002
set *((unsigned long *) 0x10100040) = 0xe2855002
set *((unsigned long *) 0x10100044) = 0xe1550006
set *((unsigned long *) 0x10100048) = 0x1afffff4
set *((unsigned long *) 0x1010004c) = 0xe1a00000
set *((unsigned long *) 0x10100050) = 0xe1a00000
set *((unsigned long *) 0x10100054) = 0xeafffffe
set $pc = 0x10100000
end

define flash-ready-to-write
flash-unlock 0x50000000
flash-erase  0x50000000
flash-unlock 0x50008000
flash-erase  0x50008000
flash-unlock 0x50010000
flash-erase  0x50010000
flash-unlock 0x50018000
flash-erase  0x50018000
flash-unlock 0x50020000
flash-erase  0x50020000
flash-unlock 0x50028000
flash-erase  0x50028000
flash-unlock 0x50030000
flash-erase  0x50030000
flash-unlock 0x50038000
flash-erase  0x50038000
end

define flash-redboot
mem-init
mem-switch
writable
flash-unlock
flash-erase1
flash-unlock2
flash-erase2
load boot/redboot/images/redboot-swap.elf
flash-program
c
end

define flash-boot
mem-init
mem-switch
writable
# flash-unlock1
# flash-erase1
# flash-unlock2
# flash-erase2
flash-ready-to-write
load boot/boot-swap.elf
mem-setmac
flash-program
c
end

#
#	FLASH writing code (8bit functions)
#
define flash8-erase1
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3a02020
set *((unsigned long *) 0x10000008) = 0xe5c12000
set *((unsigned long *) 0x1000000c) = 0xe3a020d0
set *((unsigned long *) 0x10000010) = 0xe5c12000
set $pc = 0x10000000
stepi 5
shell sleep 2
set *((unsigned long *) 0x10000000) = 0xe3a020ff
set *((unsigned long *) 0x10000004) = 0xe5c12000
set $pc = 0x10000000
stepi 2
end

define flash8-erase2
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3811802
set *((unsigned long *) 0x10000008) = 0xe3a02020
set *((unsigned long *) 0x1000000c) = 0xe5c12000
set *((unsigned long *) 0x10000010) = 0xe3a020d0
set *((unsigned long *) 0x10000014) = 0xe5c12000
set $pc = 0x10000000
stepi 6
shell sleep 2
set *((unsigned long *) 0x10000000) = 0xe3a020ff
set *((unsigned long *) 0x10000004) = 0xe5c12000
set $pc = 0x10000000
stepi 2
end

define flash8-unlock1
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3a02060
set *((unsigned long *) 0x10000008) = 0xe5c12000
set *((unsigned long *) 0x1000000c) = 0xe3a020d0
set *((unsigned long *) 0x10000010) = 0xe5c12000
set *((unsigned long *) 0x10000014) = 0xe3a020ff
set *((unsigned long *) 0x10000018) = 0xe5c12000
set $pc = 0x10000000
stepi 7
end

define flash8-unlock2
set *((unsigned long *) 0x10000000) = 0xe3a01205
set *((unsigned long *) 0x10000004) = 0xe3811802
set *((unsigned long *) 0x10000008) = 0xe3a02060
set *((unsigned long *) 0x1000000c) = 0xe5c12000
set *((unsigned long *) 0x10000010) = 0xe3a020d0
set *((unsigned long *) 0x10000014) = 0xe5c12000
set *((unsigned long *) 0x10000018) = 0xe3a020ff
set *((unsigned long *) 0x1000001c) = 0xe5c12000
set $pc = 0x10000000
stepi 8
end

define flash8-program
set *((unsigned long *) 0x10100000) = 0xe3a01205
set *((unsigned long *) 0x10100004) = 0xe3a02040
set *((unsigned long *) 0x10100008) = 0xe3a03080
set *((unsigned long *) 0x1010000c) = 0xe3a040ff
set *((unsigned long *) 0x10100010) = 0xe3a05000
set *((unsigned long *) 0x10100014) = 0xe3a06701
set *((unsigned long *) 0x10100018) = 0xe5c12000
set *((unsigned long *) 0x1010001c) = 0xe5d57000
set *((unsigned long *) 0x10100020) = 0xe5c17000
set *((unsigned long *) 0x10100024) = 0xe5d17000
set *((unsigned long *) 0x10100028) = 0xe1170003
set *((unsigned long *) 0x1010002c) = 0x0afffffc
set *((unsigned long *) 0x10100030) = 0xe5c14000
set *((unsigned long *) 0x10100034) = 0xe2811001
set *((unsigned long *) 0x10100038) = 0xe2855001
set *((unsigned long *) 0x1010003c) = 0xe1550006
set *((unsigned long *) 0x10100040) = 0x1afffff4
set *((unsigned long *) 0x10100044) = 0xe1a00000
set *((unsigned long *) 0x10100048) = 0xe1a00000
set *((unsigned long *) 0x1010004c) = 0xeafffffe
set $pc = 0x10100000
end

define flash8-redboot
mem-init
mem-switch
writable
flash8-unlock1
flash8-erase1
flash8-unlock2
flash8-erase2
load boot/redboot/images/redboot-swap.elf
flash8-program
c
end

define flash8-boot
mem-init
mem-switch
writable
#flash8-unlock1
flash8-erase1
#flash8-unlock2
flash8-erase2
load boot/boot-swap.elf
mem-setmac
flash8-program
c
end


#
#	Set MAC addresses in the appropriate place. Makes it easier
#	for redboot to work right...
#
define mem-setmac2
set *((unsigned char *) 0x1c000) = 0x00
set *((unsigned char *) 0x1c001) = 0xcf
set *((unsigned char *) 0x1c002) = 0xd0
set *((unsigned char *) 0x1c003) = 0x00
set *((unsigned char *) 0x1c004) = 0x00
set *((unsigned char *) 0x1c005) = 0x00
set *((unsigned char *) 0x1c006) = 0x01
set *((unsigned char *) 0x1c007) = 0x00
end

define mem-setmac
set *((unsigned char *) 0x20000) = 0x00
set *((unsigned char *) 0x20001) = 0xcf
set *((unsigned char *) 0x20002) = 0xd0
set *((unsigned char *) 0x20003) = 0x00
set *((unsigned char *) 0x20004) = 0xd0
set *((unsigned char *) 0x20005) = 0x00
set *((unsigned char *) 0x20006) = 0x01
set *((unsigned char *) 0x20007) = 0x00
set *((unsigned char *) 0x20008) = 0x02
set *((unsigned char *) 0x20009) = 0x00
set *((unsigned char *) 0x2000a) = 0x00
set *((unsigned char *) 0x2000b) = 0xcf
end


#
#	Set debugger into big endian mode.
#
define gdb-big
set endian big
monitor endian big
end


#
#	DoC programming macros. We rely on the modified boot loader to
#	program the DoC. It is just a little too compiicated to script
#	here.
#
define doc-programipl
mem-init
mem-switch
writable
big
load boot/ixp425/boot.elf
load boot/loadipl.elf
set $pc = 0x3fc0028
c
end

define doc-programboot
mem-init
mem-switch
writable
big
load boot/boot-jtag.elf
load boot/loadboot.elf
set $pc = 0x3fc0028
c
end

define doc-runipl
mem-init
mem-switch
load boot/ixp425/boot.elf
set $pc = 0x1000
c
end

define doc-runboot
mem-init
mem-switch
writable
big
load boot/boot.elf
set $pc = 0x1fe0028
end

#
#	Startup commands...
#
set output-radix 16
set input-radix 16

target remote localhost:8888

set print pretty
set print asm-demangle
display/i $pc

