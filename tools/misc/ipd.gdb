#
#	GDB init script to support the Cirrus Logic EP9312 ARM
#	based CPU.
#
#	(C) Copyright 2003-2004, Greg Ungerer <gerg@snapgear.com>
#
#	Designed to be used with the Macraigor RAVEN wiggler for
#	ARM based 20ping JTAG setups. I use their OCdemon Linux
#	driver and arm-elf-gdb with it.
#

define uart-count
printf "%d\n", $r4
end

#
#	UART functions
#
define uart1-init
# This is set to 115200,8,n,1
set *((unsigned long *) 0x808c0010) = 0x07000000
set *((unsigned long *) 0x808c000c) = 0x00000000
set *((unsigned long *) 0x808c0008) = 0x60000000
set *((unsigned long *) 0x808c0014) = 0x01000000
end

define uart1-print
set *((unsigned long *) 0x808c0000) = $arg0
end

define uart1-loopback
set *((unsigned long *) 0x808c0014) = 0x81000000
end

define uart2-init
echo  uart2-init\n
# 8 fifo-enable 1 none
# fifo set *((unsigned char *) 0x808d0008) = 0x70
# BR = 0007 = 14.7456MHz / (16 * 115200) - 1
set *((unsigned char *) 0x808d0010) = 0x00
set *((unsigned char *) 0x808d000c) = 0x00
set *((unsigned char *) 0x808d0008) = 0x00
set *((unsigned char *) 0x808d0010) = 0x07
set *((unsigned char *) 0x808d000c) = 0x00
set *((unsigned char *) 0x808d0008) = 0x60
set *((unsigned char *) 0x808d0014) = 0x01
end

define uart2-print
set *((unsigned char *) 0x808d0000) = $arg0
end

define uart2-loopback
set *((unsigned char *) 0x808d0014) = 0x81
end

define uart3-init
# set UARTBAUD
set $tmp = * (unsigned long *) 0x80930004
set * (unsigned long *) 0x80930004 = ($tmp | 0x20000000)
# This is set to 115200,8,n,1
set *((unsigned long *) 0x808e0010) = 0x07000000
set *((unsigned long *) 0x808e000c) = 0x00000000
set *((unsigned long *) 0x808e0008) = 0x60000000
set *((unsigned long *) 0x808e0014) = 0x01000000
end

define uart3-print
set *((unsigned long *) 0x808e0000) = $arg0
end

define uart3-loopback
set *((unsigned long *) 0x808e0014) = 0x81000000
end


define uart-fetchcode
set *((unsigned long *) 0xc0000000) = 0xe3a01102 
set *((unsigned long *) 0xc0000004) = 0xe381188d 
set *((unsigned long *) 0xc0000008) = 0xe3a02007 
set *((unsigned long *) 0xc000000c) = 0xe5812010
set *((unsigned long *) 0xc0000010) = 0xe3a02000
set *((unsigned long *) 0xc0000014) = 0xe581200c
set *((unsigned long *) 0xc0000018) = 0xe3a02060
set *((unsigned long *) 0xc000001c) = 0xe5812008
set *((unsigned long *) 0xc0000020) = 0xe3a02001
set *((unsigned long *) 0xc0000024) = 0xe581200c
set *((unsigned long *) 0xc0000028) = 0xe3a04000 
set *((unsigned long *) 0xc000002c) = 0xe3a05103 
set *((unsigned long *) 0xc0000030) = 0xe3855a01 
# set *((unsigned long *) 0xc0000030) = 0xe38558ff 
set *((unsigned long *) 0xc0000034) = 0xe3a03010 
set *((unsigned long *) 0xc0000038) = 0xe5912018 
set *((unsigned long *) 0xc000003c) = 0xe1120003
set *((unsigned long *) 0xc0000040) = 0x1afffffc
set *((unsigned long *) 0xc0000044) = 0xe5912000
set *((unsigned long *) 0xc0000048) = 0xe5c52000
set *((unsigned long *) 0xc000004c) = 0xe2855001
set *((unsigned long *) 0xc0000050) = 0xe2844001
set *((unsigned long *) 0xc0000054) = 0xeafffff7
end

define uart-load
uart-fetchcode
set $pc = 0xc0000000
printf "Ready to download over serial line...\n"
c
end


define led-on
set *((unsigned long *) 0x03ffe600) = 0x00000006
set *((unsigned long *) 0x03ffe604) = 0x00000000
set *((unsigned long *) 0x03ffe608) = 0x00000006

end


define mem-init
echo  mem-init\n
# Set SDCS0 to be 16MB (2*64Mbit devices parallel on 32bit data bus)
# This sets it for RAS=2, CAS=3, 4 banks
set *((unsigned long *) 0x80060010) = 0x00210028
shell sleep 1

# Set global config to initiate NOPs
set *((unsigned long *) 0x80060004) = 0x80000003
shell sleep 1

# Send PRECHARGE-ALL command
set *((unsigned long *) 0x80060004) = 0x80000001

# Enable refresh engine to generate some fast refreshes
set *((unsigned long *) 0x80060008) = 0x00000010
shell sleep 1

# Switch refresh engine back to normal
set *((unsigned long *) 0x80060008) = 0x00000023

# Send MODE command
set *((unsigned long *) 0x80060004) = 0x80000002
set $junk = *((unsigned long *) 0xc0008800)
set $junk = *((unsigned long *) 0xc0408800)
set $junk = *((unsigned long *) 0xc0808800)
set $junk = *((unsigned long *) 0xc0c08800)

# Set the real value into the global configuration register
set *((unsigned long *) 0x80060004) = 0x80000000

shell sleep 1

end

define unlock
set *((unsigned char *) 0x809300C0 ) = 0xaa
end

#
#	Set the internal PLL clocks
#
define clk1-init
echo  clk1-init\n
# load tools/bin/clk
# set $pc = 0xc0000000
# stepi 9
# set * (unsigned long *) 0x80930020 = 0
#
# Fout = 14.7456MHz
# safe settings
#
set * (unsigned long *) 0x80930020 = 0
shell sleep 1
end

define clk2-init
echo  clk2-init\n
# load tools/bin/clk2
# set $pc = 0xc0000000
# stepi 9
# set * (unsigned long *) 0x80930024 = 0x300dc317
#
# Fout = 192000000.00
# USB  =  48000000.00
#
set * (unsigned long *) 0x80930024 = 0x300dc317
shell sleep 1
end

define dev-init
echo  dev-init\n
load tools/bin/devcfg
set $pc = 0xc0000000
stepi 8
#
# unlock the Syscon lock
#
# set * (unsigned long *) 0x809300c0 = 0x000000aa
#
# Uart1En, Uart2En

# unlock
# set * (unsigned long *) 0x80930080 = 0x00140000
# shell sleep 1
end

#
#	Some simple memory tests.
#
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

define mem-test
set $num = 0
#set $total = 0x100000
set $total = 0x100
set $addr = $arg0
set $val = $arg1
while ($num < $total)
	set *((unsigned long *) $addr) = $val
	set $addr = $addr + 4
	set $num = $num + 1
	set $val = $val + 1
end
set $num = 0
set $addr = $arg0
set $val = $arg1
while ($num < $total)
	set $rd = *((unsigned long *) $addr)
	if ($rd != $val)
		print $addr
	end
	set $addr = $addr + 4
	set $num = $num + 1
	set $val = $val + 1
end
end


define mem-compare
set $src1 = $arg0
set $src2 = $arg1
set $num = 0
while ($num < $arg2)
	set $val1 = *((unsigned long *) $src1)
	set $val2 = *((unsigned long *) $src2)
	if ($val1 != $val2)
		printf "ERROR: [%x]=%x [%x]=%x\n", $src1, $val1, $src2, $val2
	end
	set $src1 = $src1 + 4
	set $src2 = $src2 + 4
	set $num = $num + 4
end
end


#
#	FLASH handling code.
#
define flash-id-8
set  * (((unsigned short *) $arg0) + 0x00) = 0xf0
set  * (((unsigned short *) $arg0) + 0x55) = 0x98
p /x * (((unsigned short *) $arg0) + 0x10)
p /x * (((unsigned short *) $arg0) + 0x11)
p /x * (((unsigned short *) $arg0) + 0x12)
end

define flash-id-16
set  * ((unsigned short *) $arg0 + 0x00) = 0x00f0
set  * ((unsigned short *) $arg0 + 0xaa) = 0x0098
p /x * ((unsigned short *) $arg0 + 0x20)
end

define flash-erase
printf "ERASE: addr=%x", $arg0
set *((unsigned char *) $arg0) = 0x20
set *((unsigned char *) $arg0) = 0xd0
shell sleep 2
set *((unsigned char *) $arg0) = 0xff
printf "\n"
end


define flash-eraseall
set $addr = 0
while ($addr < 0x400000)
	flash-erase 0x00000000+$addr
	set $addr = $addr + 0x20000
end
end


define flash-eraseimage
set $addr = 0x40000
while ($addr < 0x400000)
	flash-erase 0x00000000+$addr
	set $addr = $addr + 0x20000
end
end


define flash-eraseboot
flash-erase 0x00000000
end


define flash-program-byte
set *((unsigned char *) $arg0) = 0x40
set *((unsigned char *) $arg0) = $arg1
set $delay = 0
while ($delay < 5)
	set $val = *((unsigned char *) $arg0)
	set $delay = $delay + 1
end
set *((unsigned char *) $arg0) = 0xff
end


define flash-program
set $num = $arg0
set $count = 0
set $src = 0xc0000000
set $dst = 0x00000000
while ($count < $num)
	set $byte = *((unsigned char *) $src)
	flash-program-byte $dst $byte
	set $src = $src + 1
	set $dst = $dst + 1
	if (($count & 0x3ff) == 0)
		printf "PROGRAMING FLASH: 0x%08x-0x%08x\n", $count, ($count+0x400)
	end
	set $count = $count + 1
end
end


define flash-burncode
set *((unsigned long *) 0xc0000000) = 0xe3a01000
set *((unsigned long *) 0xc0000004) = 0xe3a05103
set *((unsigned long *) 0xc0000008) = 0xe3855a01
set *((unsigned long *) 0xc000000c) = 0xe3856902
set *((unsigned long *) 0xc0000010) = 0xe3a02040
set *((unsigned long *) 0xc0000014) = 0xe3822901
set *((unsigned long *) 0xc0000018) = 0xe3a03080
set *((unsigned long *) 0xc000001c) = 0xe3a040ff
set *((unsigned long *) 0xc0000020) = 0xe3844cff
set *((unsigned long *) 0xc0000024) = 0xe1c120b0
set *((unsigned long *) 0xc0000028) = 0xe1d570b0
set *((unsigned long *) 0xc000002c) = 0xe1c170b0
set *((unsigned long *) 0xc0000030) = 0xe1d170b0
set *((unsigned long *) 0xc0000034) = 0xe1170003
set *((unsigned long *) 0xc0000038) = 0x0afffffc
set *((unsigned long *) 0xc000003c) = 0xe1c140b0
set *((unsigned long *) 0xc0000040) = 0xe2811002
set *((unsigned long *) 0xc0000044) = 0xe2855002
set *((unsigned long *) 0xc0000048) = 0xe1550006
set *((unsigned long *) 0xc000004c) = 0x1afffff4
set *((unsigned long *) 0xc0000050) = 0xe1a00000
set *((unsigned long *) 0xc0000054) = 0xe1a00000
set *((unsigned long *) 0xc0000058) = 0xeafffffe
end

define swreset
set * ((unsigned long *) 0x80940000) = 0x0000aaaa
shell sleep 1
# set * ((unsigned long *) 0x80930080) = 0x80000000
# set * ((unsigned long *) 0x80930080) = 0x00000000
end

#
#	Load and program the boot code into flash.
#
define init
# swreset
mem-init
clk1-init
clk2-init
# mem-init
shell sleep 1
dev-init
shell sleep 1

uart2-init
uart2-print 0x0a
uart2-print 0x0d
uart2-print 0x52
uart2-print 0x65
uart2-print 0x61
uart2-print 0x64
uart2-print 0x79
uart2-print 0x0a
uart2-print 0x0d
end

define flash-boot
flash-erase 0x00000000
shell sleep 1
flash-burncode
set $pc = 0xc0000000
c
end

define flash-memboot
# FIXME: this just does not seem to work right...
init
load boot/boot-ram.elf
flash-erase 0x00000000
flash-burncode
set $pc = 0xc0000000
c
end


#
#	Startup commands...
#
set output-radix 16
set input-radix 16

target remote localhost:8888

#set print pretty
#set print asm-demangle
display/i $pc

