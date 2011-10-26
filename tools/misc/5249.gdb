#
# GDB Init script for the ColdFire 5249 processor.
#
# The main purpose of this script is to configure the 
# DRAM controller so code can be loaded.
#

define addresses

set $mbar  = 0x10000001
set $rsr   = $mbar - 1 + 0x000
set $sypcr = $mbar - 1 + 0x001
set $swivr = $mbar - 1 + 0x002
set $swsr  = $mbar - 1 + 0x003
set $simr  = $mbar - 1 + 0x003
set $par   = $mbar - 1 + 0x004
set $irqpar= $mbar - 1 + 0x006
set $pllcr = $mbar - 1 + 0x008
set $mpark = $mbar - 1 + 0x00c
set $ipr   = $mbar - 1 + 0x040
set $imr   = $mbar - 1 + 0x044

set $icr0  = $mbar - 1 + 0x04c
set $icr1  = $mbar - 1 + 0x04d
set $icr2  = $mbar - 1 + 0x04e
set $icr3  = $mbar - 1 + 0x04f
set $icr4  = $mbar - 1 + 0x050
set $icr5  = $mbar - 1 + 0x051
set $icr6  = $mbar - 1 + 0x052
set $icr7  = $mbar - 1 + 0x053
set $icr8  = $mbar - 1 + 0x054
set $icr9  = $mbar - 1 + 0x055
set $icr10 = $mbar - 1 + 0x056
set $icr11 = $mbar - 1 + 0x057

set $csar0 = $mbar - 1 + 0x080
set $csmr0 = $mbar - 1 + 0x084
set $cscr0 = $mbar - 1 + 0x08a
set $csar1 = $mbar - 1 + 0x08c
set $csmr1 = $mbar - 1 + 0x090
set $cscr1 = $mbar - 1 + 0x096
set $csar2 = $mbar - 1 + 0x098
set $csmr2 = $mbar - 1 + 0x09c
set $cscr2 = $mbar - 1 + 0x0a2
set $csar3 = $mbar - 1 + 0x0a4
set $csmr3 = $mbar - 1 + 0x0aa
set $cscr3 = $mbar - 1 + 0x0ae

set $dcr   = $mbar - 1 + 0x100
set $dacr0 = $mbar - 1 + 0x108
set $dmr0  = $mbar - 1 + 0x10c
set $dacr1 = $mbar - 1 + 0x110
set $dmr1  = $mbar - 1 + 0x114

set $tmr1  = $mbar - 1 + 0x140
set $trr1  = $mbar - 1 + 0x144
set $tcr1  = $mbar - 1 + 0x148
set $tcn1  = $mbar - 1 + 0x14C
set $ter1  = $mbar - 1 + 0x151
set $tmr2  = $mbar - 1 + 0x180
set $trr2  = $mbar - 1 + 0x184
set $tcr2  = $mbar - 1 + 0x188
set $tcn2  = $mbar - 1 + 0x18C
set $ter2  = $mbar - 1 + 0x191

set $paddr = $mbar - 1 + 0x244
set $padat = $mbar - 1 + 0x248

end


#
#  Setup RAMBAR for the internal SRAM.
#

define setup-sram
set $rambar  = 0x20000001
end


#
#  Setup chip selects... As per dBUG on M5249C3 board.
#

define setup-cs

# CS0 -- FLASH ROM
set *((unsigned long *) $csar0) = 0xffe00000
set *((unsigned long *) $csmr0)  = 0x001f0021
set *((unsigned short *) $cscr0) = 0x1180

# CS1 -- Ethernet smc91111
set *((unsigned long *) $csar1) = 0xe0000000
set *((unsigned long *) $csmr1)  = 0x001f0021
set *((unsigned short *) $cscr1) = 0x0080

# CS2 -- IDE interface
#set *((unsigned long *) $csar2) = 0x50000000
#set *((unsigned long *) $csmr2)  = 0x001f0001
#set *((unsigned short *) $cscr2) = 0x0080

end


#
#	Code to initialize the SDRAM
#

define setup-sdram

load /home/gerg/src/mem/m5249c3.elf
set $pc = 0x20000000
set $sp = 0x20000400
set $fp = 0x20000400
set $vbr = 0x20000000
set $ps = 0x2700

end


#
#	Some FLASH programming code...
#

define flash-erase
printf "ERASE: addr=%x", (0xffe00000 + $arg0)
set *((unsigned short *) (0xffe00aaa + $arg0)) = 0xaaaa
set *((unsigned short *) (0xffe00554 + $arg0)) = 0x5555
set *((unsigned short *) (0xffe00aaa + $arg0)) = 0x8080
set *((unsigned short *) (0xffe00aaa + $arg0)) = 0xaaaa
set *((unsigned short *) (0xffe00554 + $arg0)) = 0x5555
set *((unsigned short *) (0xffe00000 + $arg0)) = 0x3030
set $cnt = 0
while ($cnt < 10)
	printf "."
	set $cnt = $cnt + 1
	set $delay = 0
	while ($delay < 200)
		set $val = *((char *) $delay)
		set $delay = $delay + 1
	end
end
printf "\n"
end

define flash-eraseall
flash-erase 0x000000
flash-erase 0x004000
flash-erase 0x006000
flash-erase 0x008000
set $num = 0x010000
while ($num < 0x100000)
	flash-erase $num
	set $num = $num + 0x010000
end
end

define flash-program-word
set *((unsigned short *) 0xffe00aaa) = 0xaaaa
set *((unsigned short *) 0xffe00554) = 0x5555
set *((unsigned short *) 0xffe00aaa) = 0xa0a0
set *((unsigned short *) $arg0) = $arg1
set $delay = 0
while ($delay < 5)
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
#	Target is ColdFire M5249C3 board...
#
target bdm /dev/bdmcf0

addresses
setup-sram
setup-cs
setup-sdram

set print pretty
set print asm-demangle
display/i $pc
select-frame 0

