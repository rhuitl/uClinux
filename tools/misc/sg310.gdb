#
#	GDB init script to support the Kendin/Micrel KS8695 ARM
#	based CPU on SG300 and SG310 boards.
#
#	(C) Copyright 2003-2009, Greg Ungerer <gerg@snapgear.com>
#
#	Designed to be used with the OpenOCD JTAG debugger and the
#	Amontec USB JtagKey (and similar) ARM based debuggers.
#	Designed to be used with the Macraigor RAVEN wiggler for
#	(A generic arm-linux-gdb is used as the front end).
#

#
#	UART functions
#
define uart-init
set *((long*) 0x03ffe00c) = 0x03000000
end

define uart-print
set *((long*) 0x03ffe004) = $arg0
end


define led-on
set *((unsigned long *) 0x03ffe600) = 0x00000006
set *((unsigned long *) 0x03ffe604) = 0x00000000
set *((unsigned long *) 0x03ffe608) = 0x00000006
end


#
#	Memory functions
#

define flash-init
# Map flash0 and flash1 banks contiguously from 0x02000000
monitor mww 0x03ff4010 0x8fe00040
monitor mww 0x03ff4014 0x9fe40040
monitor mww 0x03ff4020 0x30000005
end


define mem-init
# Set bank0 to map RAM to 0x00000000, 16bit, 9 columns, 4banks
#monitor mww 0x03ff4030 0x3fc0010c
monitor mww 0x03ff4030 0x3fc0000e
monitor mww 0x03ff4034 0

# Set global RAS/CAS timings
monitor mww 0x03ff4038 0x0000000a

# Send NOP command (via SDRAM buffer control register)
monitor mww 0x03ff403c 0x00030000
#shell sleep 1

# Send PRECHARGE-ALL command (via SDRAM buffer control register)
monitor mww 0x03ff403c 0x00010000
#shell sleep 1

# Fast refreash cycles (at least 2 needed)
monitor mww 0x03ff4040 0x00000020
#shell sleep 1
monitor mww 0x03ff4040 0x00000168

# Send MODE command (via buffer control register)
monitor mww 0x03ff403c 0x00020033
#shell sleep 1

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
set $total = 0x100000
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
define flash-erase
printf "ERASE: addr=%x", $arg0
monitor mwb $arg0 0x20
monitor mwb $arg0 0xd0
shell sleep 2
monitor mwb $arg0 0xff
printf "\n"
end

define flash-unlock
printf "UNLOCK: addr=%x", $arg0
monitor mwb $arg0 0x60
monitor mwb $arg0 0xd0
shell sleep 2
monitor mwb $arg0 0xff
printf "\n"
end

define flash-eraseall
set $addr = 0
while ($addr < 0x400000)
	flash-erase 0x02000000+$addr
	set $addr = $addr + 0x20000
end
end


define flash-eraseboot
flash-erase 0x02000000
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
set $src = 0
set $dst = 0x02000000
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


#
#	Load and program the boot code into flash.
#
define flash-boot
flash-init
mem-init
flash-unlock 0x02000000
flash-erase 0x02000000
load boot/boot-jtag.elf

load tools/bin/lite3
monitor reg r1 0x02000000		# <flash-addr>
monitor reg r5 0x10000			# <ram-start>
monitor reg r6 0x20000			# <ram-end>
monitor resume 0xf10000
shell sleep 20
monitor halt
printf "FLASH: boot loader programmed...\n"
end


#
#	Startup commands...
#
set output-radix 16
set input-radix 16

target remote localhost:3333

#set print pretty
#set print asm-demangle
display/i $pc

monitor reset halt

