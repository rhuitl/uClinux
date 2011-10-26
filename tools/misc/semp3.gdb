#
# GDB Init script for the SecureEdge MP3 ColdFire 5307 board.
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
set $csmr3 = $mbar - 1 + 0x0a8
set $cscr3 = $mbar - 1 + 0x0ae
set $csar4 = $mbar - 1 + 0x0b0
set $csmr4 = $mbar - 1 + 0x0b4
set $cscr4 = $mbar - 1 + 0x0ba
set $csar5 = $mbar - 1 + 0x0bc
set $csmr5 = $mbar - 1 + 0x0c0
set $cscr5 = $mbar - 1 + 0x0c6
set $csar6 = $mbar - 1 + 0x0c8
set $csmr6 = $mbar - 1 + 0x0cc
set $cscr6 = $mbar - 1 + 0x0d2
set $csar7 = $mbar - 1 + 0x0d4
set $csmr7 = $mbar - 1 + 0x0d8
set $cscr7 = $mbar - 1 + 0x0de

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
#	Setup Parallel I/O ports...
#

define setup-pp
set *((unsigned short *) $par) = 0x005b
set *((unsigned short *) $paddr) = 0x0180
set *((unsigned short *) $padat) = 0x0000
end


#
#  Setup chip selects...
#
#  These are defined so that they are compatible with both the
#  old and new mask 5307 chips, so be carefull if you modify.
#

define setup-cs

# CS0 -- FLASH ROM, address=0xf000000, 1MB-2MB size, 8bit
set *((unsigned short *) $csar0) = 0xf000
set *((unsigned long *) $csmr0)  = 0x001f0001
set *((unsigned short *) $cscr0) = 0x3d40

# CS1 -- Optional DISK-ON-CHIP device, address=0xe0000000, 16MB, 8bit.
set *((unsigned short *) $csar1) = 0xe000
set *((unsigned long *) $csmr1)  = 0x00ff0001
set *((unsigned short *) $cscr1) = 0x3d40

# CS2 -- LCD display, address=0x30400000, 8bit
set *((unsigned short *) $csar2) = 0x3040
set *((unsigned long *) $csmr2)  = 0x000f0001
set *((unsigned short *) $cscr2) = 0x2940
# the next line is for old proto type HW with LCD behind ISA bus
# set *((unsigned short *) $cscr2) = 0x0040

# CS3 -- Ethernet, address=0x30600000, Davicom, 16bit
set *((unsigned short *) $csar3) = 0x3060
set *((unsigned long *) $csmr3)  = 0x000f0001
set *((unsigned short *) $cscr3) = 0x0080

# CS4 -- IDE interface, address=0x30800000, 16bit
set *((unsigned short *) $csar4) = 0x3080
set *((unsigned long *) $csmr4)  = 0x000f0001
set *((unsigned short *) $cscr4) = 0x0080

# CS5 -- Audio CODEC, address=0x30a00000, 8bit
set *((unsigned short *) $csar5) = 0x30a0
set *((unsigned long *) $csmr5)  = 0x000f0001
set *((unsigned short *) $cscr5) = 0x0040

# CS6 -- Nothing, address=0x30c00000
set *((unsigned short *) $csar6) = 0x30c0
set *((unsigned long *) $csmr6)  = 0x000f0001
set *((unsigned short *) $cscr6) = 0x3d40

# CS7 -- Nothing, address=0x30e00000
set *((unsigned short *) $csar7) = 0x30e0
set *((unsigned long *) $csmr7)  = 0x000f0001
set *((unsigned short *) $cscr7) = 0x3d40

end


#
#	GDB boot loader
#
define bootload
cont
load boot/etherboot/ethboot-bdm.elf
load boot/boot-bdm.elf
symbol-file boot/boot-bdm.elf
set $pc=_start
add-symbol-file boot/etherboot/ethboot-bdm.elf &etherboot_addr
echo \nType 'cont' to start bootloader...\n
end


#
#	FLASH prgramming code
#
define flash-erase
set *((unsigned char *) 0xf0000aaa) = 0xaa
set *((unsigned char *) 0xf0000555) = 0x55
set *((unsigned char *) 0xf0000aaa) = 0x80
set *((unsigned char *) 0xf0000aaa) = 0xaa
set *((unsigned char *) 0xf0000555) = 0x55
set *((unsigned char *) 0xf0000000) = 0x30
end

define flash-programbyte
set *((unsigned char *) 0xf0000aaa) = 0xaa
set *((unsigned char *) 0xf0000555) = 0x55
set *((unsigned char *) 0xf0000aaa) = 0xa0
set *((unsigned char *) $arg0) = $arg1
#while (*((unsigned char *) $arg0) != $arg1)
#	set $d0 = 0
end

define flash-programstartaddr
flash-programbyte 0xf0000004 0xf0
flash-programbyte 0xf0000005 0x00
flash-programbyte 0xf0000006 0x04
flash-programbyte 0xf0000007 0x00
end

define flash-program
set $num = $arg0
set $dst = 0xf0000400
set $src = 0x20000000
flash-programstartaddr
while ($num > 0)
	set $byte = *((unsigned char *) $src)
	flash-programbyte $dst $byte
	set $src = $src + 1
	set $dst = $dst + 1
	set $num = $num - 1
end
end

define goflash
set $pc = 0xf0000400
c
end


#
#	Set Audio for simple output
#
define audio

# left DAC control
set *((unsigned char *) 0x30a00000) = 0x46
set *((unsigned char *) 0x30a00001) = 0x00

# right DAC control
set *((unsigned char *) 0x30a00000) = 0x47
set *((unsigned char *) 0x30a00001) = 0x00

# clock and data format register
set *((unsigned char *) 0x30a00000) = 0x48
set *((unsigned char *) 0x30a00001) = 0x00

# interface configuration register
set *((unsigned char *) 0x30a00000) = 0x49
set *((unsigned char *) 0x30a00001) = 0x49

# upper base count
set *((unsigned char *) 0x30a00000) = 0x4e
set *((unsigned char *) 0x30a00001) = 0x00

# upper base count
set *((unsigned char *) 0x30a00000) = 0x4f
set *((unsigned char *) 0x30a00001) = 0x00

# pin control register
set *((unsigned char *) 0x30a00000) = 0x4a
set *((unsigned char *) 0x30a00001) = 0x02

# misc control register
set *((unsigned char *) 0x30a00000) = 0x4c
set *((unsigned char *) 0x30a00001) = 0xca

# crystal, clock select register
set *((unsigned char *) 0x30a00000) = 0x40 | 29
set *((unsigned char *) 0x30a00001) = 0x60

set *((unsigned char *) 0x30a00000) = 0x00
end


define play
set $num = 0
while ($num >= 0)
	set *((unsigned char *) 0x30a00003) = $num
	set $num = $num + 25
end
end


define mix
set *((unsigned char *) 0x30a00000) = 13
set *((unsigned char *) 0x30a00001) = 0x01
end


define rec
set *((unsigned char *) 0x30a00000) = 0x49
set *((unsigned char *) 0x30a00001) = 0xcb
set *((unsigned char *) 0x30a00000) = 0x09
set $num = 0
while ($num >= 0)
	x/1b 0x30a00003
	set $num = $num + 1
end
end


define replay
set *((unsigned char *) 0x30a00000) = 0x49
set *((unsigned char *) 0x30a00001) = 0xcb
set *((unsigned char *) 0x30a00000) = 0x09
set $num = 0
while ($num >= 0)
	set $byte = *((unsigned char *) 0x30a00003)
	set *((unsigned char *) 0x30a00003) = $byte
	set $num = $num + 1
end
end


define printreg
set $num = 0
while ($num < 32)
	set *((unsigned char *) 0x30a00000) = $num
	set $byte = *((unsigned char *) 0x30a00001)
	printf "REG[%02d] = %02x\n", $num, $byte
	set $num = $num + 1
end
end


define audio-setreg
set *((unsigned char *) 0x30a00000) = 0x40 | $arg0
set *((unsigned char *) 0x30a00001) = $arg1
end


define fixup
#audio-setreg 0  0x00
#audio-setreg 1  0x00
audio-setreg 2  0x88
audio-setreg 3  0x88
audio-setreg 4  0x88
audio-setreg 5  0x88
#audio-setreg 11 0x40
#audio-setreg 13 0x00
#audio-setreg 16 0x11
#audio-setreg 17 0x10
#audio-setreg 18 0x88
#audio-setreg 19 0x88
#audio-setreg 20 0x00
#audio-setreg 22 0x1f
#audio-setreg 23 0x40
#audio-setreg 24 0x11
#audio-setreg 26 0x03
#audio-setreg 27 0x00

# Re-enable...
set *((unsigned char *) 0x30a00000) = 0
end


#
#	LCD functions
#

define lcdinit
set *((unsigned short *) 0x10000248) = 0x0000
set *((unsigned char *) 0x30400000) = 0x38
set *((unsigned char *) 0x30400001) = 0   
set *((unsigned char *) 0x30400000) = 0x0f
set *((unsigned char *) 0x30400001) = 0
set *((unsigned char *) 0x30400000) = 0x01
set *((unsigned char *) 0x30400001) = 0
set *((unsigned char *) 0x30400000) = 0x06
set *((unsigned char *) 0x30400001) = 0
end

define lcd0
set *((unsigned short *) 0x10000248) = 0x0000
set *((unsigned char *) 0x30400000) = 0x38
set *((unsigned char *) 0x30400001) = 0   
end
define lcd1
set *((unsigned char *) 0x30400000) = 0x0f
set *((unsigned char *) 0x30400001) = 0
end
define lcd2
set *((unsigned char *) 0x30400000) = 0x06
set *((unsigned char *) 0x30400001) = 0
end
define lcd3
set *((unsigned char *) 0x30400000) = 0x01
set *((unsigned char *) 0x30400001) = 0
end

define lcdput
set *((unsigned short *) 0x10000248) = 0x0100
set *((unsigned char *) 0x30400000) = $arg0
set *((unsigned char *) 0x30400001) = 0
end

define lcdloop
set *((unsigned short *) 0x10000248) = 0x0100
set $num = 65
while ($num >= 0)
	set *((unsigned char *) 0x30400000) = $num
	set *((unsigned char *) 0x30400001) = 0
	set $num = $num + 1
	if ($num > 90)
		set $num = 65
	end
end
end

#
#	SecureEdge MP3 ColdFire 5307 target...
#
target bdm /dev/bdmcf0

addresses
setup-sram
setup-cs
setup-pp
load bin/eliamem.elf               # use nettel8mem.elf for old proto's
set $pc = 0x20000000
set $sp = 0x20000400
set $fp = 0x20000400
set $vbr = 0x20000000
set $ps = 0x2700
set print pretty
set print asm-demangle
display/i $pc
select-frame 0

