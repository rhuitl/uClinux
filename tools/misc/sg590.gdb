#
#	SnapGear/SG720 target gdbinit script.
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

# set for the type of DDR1 RAM on the SG720
monitor long 0xcc00e504 = 0x52220106
monitor long 0xcc00e508 = 0x25609074

# set SDRAM phys base (SDBR)
monitor long 0xcc00e50c) = 0
monitor long 0xcc00e50c

# set SDRAM boundary (SBR0 and SBR1) (pairs of 512Mb x 16)
monitor long 0xcc00e510 = 0x00000004
monitor long 0xcc00e510
monitor long 0xcc00e514 = 0x00000008
monitor long 0xcc00e514

# disable refresh cycles
monitor long 0xcc00e548 = 0

# send NOP command
monitor long 0xcc00e500 = 3
shell sleep 1

# send PRECHARGE-ALL command
monitor long 0xcc00e500 = 2
shell sleep 1

# send ENABLE-DLL command
monitor long 0xcc00e500 = 4
shell sleep 1

# send MODE-SET-RESET command
monitor long 0xcc00e500 = 1
shell sleep 1

# send PRECHARGE-ALL command
monitor long 0xcc00e500 = 2
shell sleep 1

# send 2 AUTO-REFRESH cycles
monitor long 0xcc00e500 = 6
monitor long 0xcc00e500 = 6

# send MODE-SET command (without DLL reset)
monitor long 0xcc00e500 = 0
shell sleep 1

# start normal operation command
monitor long 0xcc00e500 = 0xf
shell sleep 1

# set refresh value
monitor long 0xcc00e548 = 0x410
shell sleep 1

end



#
#	Switch memory and expansion regions
#
define mem8-switch
monitor long 0xc4000020 = 0x00ffff7f
end

define mem16-switch
monitor long 0xc4000020 = 0x00ffff7f
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


define mem-wcycle
set $num = 0
set $addr = $arg0
while ($num < 0x80000)
	#set *((unsigned long *) $addr) = 0x55555555
	set *((unsigned long *) ($addr + 0x00002aaa)) = 0x55555555
	set $num = $num + 1
	#set *((unsigned long *) $addr) = 0xaaaaaaaa
	#set *((unsigned long *) $addr) = 0xffffffff
	set *((unsigned long *) ($addr + 0x00001555)) = 0xaaaaaaaa
end
end

define mem-rwcycle
set $num = 0
set $addr = $arg0
while ($num < 0x80000)
	set *((unsigned long *) $addr) = 0x55555555
	set $num = $num + 1
	set $val = *((unsigned long *) $addr)
end
end

define mem-bytecycle
set $num = 0
set $range = 0
set $addr = $arg0
while ($num < 0x80000)
	set $junk = *((unsigned char *) ($addr + $range))
	set $num = $num + 1
	set $range = $range + 1
	if ($range >= 0x10)
		set $range = 0
	end
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
set *((unsigned long *) 0x00000000) = 0xee110f10
set *((unsigned long *) 0x00000004) = 0xe3800080
set *((unsigned long *) 0x00000008) = 0xee010f10
set *((unsigned long *) 0x0000000c) = 0xee120f10
set *((unsigned long *) 0x00000010) = 0xe1a00000
set *((unsigned long *) 0x00000010) = 0xe24ff004
set $pc = 0x00000000
stepi 6
end

#
#	Enable the caches.
#
define cache
set *((unsigned long *) 0x00000000) = 0xee110f10
set *((unsigned long *) 0x00000004) = 0xe3800a01
set *((unsigned long *) 0x00000008) = 0xe380000c
set *((unsigned long *) 0x0000000c) = 0xee010f10
set *((unsigned long *) 0x00000010) = 0xee120f10
set *((unsigned long *) 0x00000014) = 0xe1a00000
set *((unsigned long *) 0x00000018) = 0xe24ff004
set *((unsigned long *) 0x0000001c) = 0xee071f15
set *((unsigned long *) 0x00000020) = 0xee120f10
set *((unsigned long *) 0x00000024) = 0xe1a00000
set *((unsigned long *) 0x00000028) = 0xe24ff004
set $pc = 0x00000000
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
define writable8
monitor long 0xc4000000 = 0xbfff3c43
end

define writable16
monitor long 0xc4000000 = 0xbfff3c42
end


#
#	Set debugger into big endian mode.
#
define gdb-big
set endian big
monitor endian big
end

#
#	FLASH writing code (8bit functions)
#
define flash8-erase1
monitor char 0x50000000 = 0x20
monitor char 0x50000000 = 0xd0
shell sleep 1
monitor char 0x50000000 = 0xff
end

define flash8-erase2
monitor char 0x50020000 = 0x20
monitor char 0x50020000 = 0xd0
shell sleep 1
monitor char 0x50020000 = 0xff
end

define flash8-unlock1
monitor char 0x50000000 = 0x60
monitor char 0x50000000 = 0xd0
shell sleep 1
monitor char 0x50000000 = 0xff
end

define flash8-unlock2
monitor char 0x50020000 = 0x60
monitor char 0x50020000 = 0xd0
shell sleep 1
monitor char 0x50020000 = 0xff
end

define flash8-program
set *((unsigned long *) 0x00100000) = 0xe3a01205
set *((unsigned long *) 0x00100004) = 0xe3a02040
set *((unsigned long *) 0x00100008) = 0xe3a03080
set *((unsigned long *) 0x0010000c) = 0xe3a040ff
set *((unsigned long *) 0x00100010) = 0xe3a05000
set *((unsigned long *) 0x00100014) = 0xe3a06701
set *((unsigned long *) 0x00100018) = 0xe5c12000
set *((unsigned long *) 0x0010001c) = 0xe5d57000
set *((unsigned long *) 0x00100020) = 0xe5c17000
set *((unsigned long *) 0x00100024) = 0xe5d17000
set *((unsigned long *) 0x00100028) = 0xe1170003
set *((unsigned long *) 0x0010002c) = 0x0afffffc
set *((unsigned long *) 0x00100030) = 0xe5c14000
set *((unsigned long *) 0x00100034) = 0xe2811001
set *((unsigned long *) 0x00100038) = 0xe2855001
set *((unsigned long *) 0x0010003c) = 0xe1550006
set *((unsigned long *) 0x00100040) = 0x1afffff4
set *((unsigned long *) 0x00100044) = 0xe1a00000
set *((unsigned long *) 0x00100048) = 0xe1a00000
set *((unsigned long *) 0x0010004c) = 0xeafffffe
set $pc = 0x00100000
end

define flash8-redboot
mem-init
mem8-switch
writable8
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
mem8-switch
writable8
flash8-unlock1
flash8-erase1
load boot/boot-swap.elf
mem-setmac
flash8-program
c
end

#
#	FLASH writing code (16bit functions)
#
define flash16-erase1
monitor short 0x50000000 = 0x20
monitor short 0x50000000 = 0xd0
shell sleep 1
monitor short 0x50000000 = 0xff
end

define flash16-erase2
monitor short 0x50020000 = 0x20
monitor short 0x50020000 = 0xd0
shell sleep 1
monitor short 0x50020000 = 0xff
end

define flash16-unlock1
monitor short 0x50000000 = 0x60
monitor short 0x50000000 = 0xd0
shell sleep 1
monitor short 0x50000000 = 0xff
end

define flash16-unlock2
monitor short 0x50020000 = 0x60
monitor short 0x50020000 = 0xd0
shell sleep 1
monitor short 0x50020000 = 0xff
end

define flash16-program
set *((unsigned long *) 0x00100000) = 0xe3a01205
set *((unsigned long *) 0x00100004) = 0xe3a02040
set *((unsigned long *) 0x00100008) = 0xe3822901
set *((unsigned long *) 0x0010000c) = 0xe3a03080
set *((unsigned long *) 0x00100010) = 0xe3a040ff
set *((unsigned long *) 0x00100014) = 0xe3844cff
set *((unsigned long *) 0x00100018) = 0xe3a05000
set *((unsigned long *) 0x0010001c) = 0xe3a06701
set *((unsigned long *) 0x00100020) = 0xe1c120b0
set *((unsigned long *) 0x00100024) = 0xe1d570b0
set *((unsigned long *) 0x00100028) = 0xe1c170b0
set *((unsigned long *) 0x0010002c) = 0xe1d170b0
set *((unsigned long *) 0x00100030) = 0xe1170003
set *((unsigned long *) 0x00100034) = 0x0afffffc
set *((unsigned long *) 0x00100038) = 0xe1c140b0
set *((unsigned long *) 0x0010003c) = 0xe2811002
set *((unsigned long *) 0x00100040) = 0xe2855002
set *((unsigned long *) 0x00100044) = 0xe1550006
set *((unsigned long *) 0x00100048) = 0x1afffff4
set *((unsigned long *) 0x0010004c) = 0xe1a00000
set *((unsigned long *) 0x00100050) = 0xe1a00000
set *((unsigned long *) 0x00100054) = 0xeafffffe
set $pc = 0x00100000
end

define flash16-redboot
mem-init
mem16-switch
writable16
flash16-unlock1
flash16-erase1
flash16-unlock2
flash16-erase2
load boot/redboot/images/redboot-swap.elf
flash16-program
c
end

define flash16-boot
mem-init
mem16-switch
writable16
flash16-unlock1
flash16-erase1
load boot/boot-swap.elf
mem-setmac
flash16-program
c
end


#
#	Set MAC addresses in the appropriate place. Makes it easier
#	for redboot to work right...
#
define mem-setmac
set *((unsigned char *) 0x1c000) = 0x00
set *((unsigned char *) 0x1c001) = 0xcf
set *((unsigned char *) 0x1c002) = 0xd0
set *((unsigned char *) 0x1c003) = 0x00
set *((unsigned char *) 0x1c004) = 0x00
set *((unsigned char *) 0x1c005) = 0x00
set *((unsigned char *) 0x1c006) = 0x01
set *((unsigned char *) 0x1c007) = 0x00
end



#
#	Startup commands...
#
set output-radix 16
set input-radix 16

target remote localhost:8888

monitor reset

set print pretty
set print asm-demangle
display/i $pc

