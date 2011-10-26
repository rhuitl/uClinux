#
#	PFW-WIRELESS - Atheros AR2317 target gdbinit script.
#
#	(C) Copyright 2007-2008, Greg Ungerer <gerg@snapgear.com>
#

define uart-init
# set 115200,8,n,1
monitor char 0x1110000f = 0x83
monitor char 0x11100003 = 0x15
monitor char 0x11100007 = 0x00
monitor char 0x1110000f = 0x03
end

define uart-print
monitor char 0x11100003 = $arg0
end

define uart-loop
while (1)
	monitor char 0x11100003 = 0x55
end
end


#
#	RAM setup!
#

define mem-init
# set MEMCTL_SCONR for xxx
monitor long 0x10300000 = 0x00001168
# set MEMCTL_STMG0R for xxx
monitor long 0x10300004 = 0x02265696
# set MEMCTL_STMG1R for xxx
monitor long 0x10300008 = 0x00070008
# set MEMCTL_SCTLR for xxx
monitor long 0x1030000c = 0x00003088
# set MEMCTL_SREFR for xxx
monitor long 0x10300010 = 0x00000410
end


#
#	Set of flash programming macros for SPI flash
#

define spi-write-enable
monitor long 0x1f000000 = 1
monitor long 0x1f000008 = 0x70000
monitor long 0x1f000008 = 0x60000
spi-bit-banger 6
monitor long 0x1f000008 = 0x70000
monitor long 0x1f000000 = 0
end


define spi-write-page
set $addr = $arg0
set $addrend = $addr + $arg1

spi-write-enable
monitor long 0x1f000000 = 1
monitor long 0x1f000008 = 0x70000
monitor long 0x1f000008 = 0x60000
spi-bit-banger 2
spi-send-addr $addr

while ($addr < $addrend)
	set $val = *((unsigned char *) $addr)
	spi-bit-banger $val
	set $addr = $addr + 1
end

monitor long 0x1f000008 = 0x70000
monitor long 0x1f000000 = 0
end


define spi-erase-sector
set $addr = $arg0
spi-write-enable
monitor long 0x1f000000 = 1
monitor long 0x1f000008 = 0x70000
monitor long 0x1f000008 = 0x60000
spi-bit-banger 0xd8
spi-send-addr $addr
monitor long 0x1f000008 = 0x70000
monitor long 0x1f000000 = 0
end


define spi-read-id
monitor long 0x11300004 = 0x000000ab
monitor long 0x11300008 = 0x00000000
monitor long 0x11300000 = 0x00000114
monitor long 0x11300000
monitor long 0x11300008
end


#
#	Complete flash programming macros.
#
define flash-program
uart-init
#mem-init
#load /tmp/boot.elf
#load tools/bin/ar2317-flasher
load /tmp/flasher
set $pc = 0
c 
end


#
#	Real startup now...
#
set output-radix 16
set input-radix 16

target remote localhost:8888

set endian big
monitor endian big
#set endian little
#monitor endian little

#display/i $pc

