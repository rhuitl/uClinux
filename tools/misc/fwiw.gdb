#
#	FWIW - Atheros AR7100 target gdbinit script.
#
#	(C) Copyright 2007-2008, Greg Ungerer <gerg@snapgear.com>
#

define uart-init
# Enable UART I/O lines
monitor long 0x18040000 = 0xc3e
monitor long 0x18040008 = 0x03e
monitor long 0x18040028 = 0x100
# set 115200,8,n,1
monitor char 0x1802000f = 0x83
monitor char 0x18020003 = 0x54
monitor char 0x18020007 = 0x00
monitor char 0x1802000f = 0x03
end


define uart-print
monitor char 0x18020003 = $arg0
end

define uart-loop
while (1)
	monitor char 0x18020003 = 0x55
end
end

define led-init
monitor long 0x18040000 = 0xc3e
monitor long 0x18040008 = 0x3e
end

define led-clear
monitor long 0x18040008 = 0x3e
end

define led-all
monitor long 0x18040008 = 0x00
end

define led-scan
while (1)
	monitor long 0x18040008 = 0x3c
	monitor long 0x18040008 = 0x3a
	monitor long 0x18040008 = 0x36
	monitor long 0x18040008 = 0x2e
	monitor long 0x18040008 = 0x1e
	monitor long 0x18040008 = 0x2e
	monitor long 0x18040008 = 0x36
	monitor long 0x18040008 = 0x3a
end
end


#
#	Set the PLL to high speed...
#
define pll-init
monitor long 0x18050004 = 0x000050c0
monitor long 0x18050000 = 0x000f00e8
monitor long 0x18050000 = 0x800f00e8
monitor long 0x18050008 = 0x1
end


#
#	RAM setup!
#

define mem-init
# set DDR_CONFIG for xxx
monitor long 0x18000000 = 0xefbc8cd0
shell sleep 1
# set DDR_CONFIG2 for xxx
monitor long 0x18000004 = 0x827156a2
shell sleep 1
# send PRECHARGE ALL cycle
monitor long 0x18000010 = 8
shell sleep 1
# send MRS update cycle
monitor long 0x18000010 = 1
shell sleep 1
# set DDR_EXTENDED_MODE 
monitor long 0x1800000c = 0
shell sleep 1
# send EMRS update cycle
monitor long 0x18000010 = 2
shell sleep 1
# send PRECHARGE ALL cycle
monitor long 0x18000010 = 8
shell sleep 1
# set DDR_MODE
monitor long 0x18000008 = 0x61
shell sleep 1
# send MRS update cycle
monitor long 0x18000010 = 1
shell sleep 1
# set DDR_REFRESH
monitor long 0x18000014 = 0x461b
shell sleep 1
# set DDR_RD_DATA_THIS_CYCLE
#monitor long 0x18000018 = 0xffff
monitor long 0x18000018 = 0xff
shell sleep 1
# set the TAP_CONTROL words
monitor long 0x1800001c = 7
monitor long 0x18000020 = 7
monitor long 0x18000024 = 7
monitor long 0x18000028 = 7
end


#
#	Set of flash programming macros for SPI flash
#

define spi-bit-banger
set $data = $arg0
set $cnt = 7
while ($cnt >= 0)
	set $bit = ($data >> $cnt) & 0x1
	if ($bit == 1)
		monitor long 0x1f000008 = 0x60001
		monitor long 0x1f000008 = 0x60101
	else
		monitor long 0x1f000008 = 0x60000
		monitor long 0x1f000008 = 0x60100
	end
	set $cnt = $cnt - 1
end
end


define spi-send-addr
set $bangaddr = $arg0
set $addrbyte = (($bangaddr & 0xff0000) >> 16)
spi-bit-banger $addrbyte
set $addrbyte = (($bangaddr & 0xff00) >> 8)
spi-bit-banger $addrbyte
set $addrbyte = $bangaddr & 0xff
spi-bit-banger $addrbyte
end

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
monitor long 0x1f000000 = 1

monitor long 0x1f000008 = 0x70000
monitor long 0x1f000008 = 0x60000
spi-bit-banger 0x9f

set $cnt = 0
while ($cnt < 0x18)
	monitor long 0x1f000008 = 0x60001
	monitor long 0x1f000008 = 0x60101
	set $cnt = $cnt + 1
end
monitor long 0x1f000008 = 0x60001

monitor long 0x1f000008 = 0x70000
monitor long 0x1f00000c
monitor long 0x1f000000 = 0

end


#
#	Complete flash programming macros.
#
define flash-program
pll-init
uart-init
mem-init
#load /tmp/boot.elf
load tools/bin/mips-flasher
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

