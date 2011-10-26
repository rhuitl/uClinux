#
# GDB Init script for the ColdFire (5475) FireBee board.
#

#
#  Setup RAMBAR for the internal SRAM.
#

define setup-sram
set $rambar  = 0x20000001
end


#
#	Some FLASH programming code...
#

define flash-erase
printf "ERASE: addr=%x", (0x00000000 + $arg0)
set *((unsigned char *) (0x00000aaa + $arg0)) = 0xaa
set *((unsigned char *) (0x00000555 + $arg0)) = 0x55
set *((unsigned char *) (0x00000aaa + $arg0)) = 0x80
set *((unsigned char *) (0x00000aaa + $arg0)) = 0xaa
set *((unsigned char *) (0x00000555 + $arg0)) = 0x55
set *((unsigned char *) (0x00000000 + $arg0)) = 0x30
shell sleep 1
printf "\n"
end

define flash-erase-256k
set $num = 0x0
while ($num < 0x10000)
	flash-erase $num
	set $num = $num + 0x02000
end

flash-erase 0x10000
flash-erase 0x20000
flash-erase 0x30000
end

define flash-erase-all
set $num = 0x0
while ($num < 0x10000)
	flash-erase $num
	set $num = $num + 0x02000
end
while ($num < 0x800000)
	flash-erase $num
	set $num = $num + 0x10000
end
end

define flash-program-word
set *((unsigned char *) 0x00000aaa) = 0xaa
set *((unsigned char *) 0x00000555) = 0x55
set *((unsigned char *) 0x00000aaa) = 0xa0
set *((unsigned short *) $arg0) = $arg1
set $delay = 0
while ($delay < 10)
	set $val = *((char *) $delay)
	set $delay = $delay + 1
end
end

define flash-program
set $num = $arg0
set $dst = 0xffe00000
set $src = 0x00000000
while ($num > 0)
	set $word = *((unsigned short *) $src)
	flash-program-word $dst $word
	set $src = $src + 2
	set $dst = $dst + 2
	set $num = $num - 2
end
end


define flash-compare
set $num = $arg0
set $dst = 0xffe00000
set $src = 0x00000000
while ($num > 0)
	set $v1 = *((unsigned short *) $src)
	set $v2 = *((unsigned short *) $dst)
	if ($v1 != $v2)
		printf "diff at  SRC: %x[%x]  DST: %x[%x]\n", $src, $v1, $dst, $v2
	end
	set $src = $src + 2
	set $dst = $dst + 2
	set $num = $num - 2
end
end


#
#	Target is ColdFire based Firebee board...
#
target remote | m68k-bdm-gdbserver pipe /dev/bdmcf0

set print pretty
set print asm-demangle
display/i $pc
select-frame 0

