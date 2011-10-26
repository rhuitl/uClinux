#
# GDB Init script for the NETtel ColdFire 5307 board.
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
set *((unsigned short *) $par) = 0x0000
set *((unsigned short *) $paddr) = 0x00ec
set *((unsigned short *) $padat) = 0x0000
end


#
#  Setup chip selects...
#
#  These are defined so that they are compatible with both the
#  old and new mask 5307 chips, so be carefull if you modify.
#

define setup-cs

# CS0 -- FLASH ROM
set *((unsigned short *) $csar0) = 0xf000
set *((unsigned long *) $csmr0)  = 0x001f0001
set *((unsigned short *) $cscr0) = 0x3d80

# CS1 -- Optional 2nd FLASH ROM.
set *((unsigned short *) $csar1) = 0xf020
set *((unsigned long *) $csmr1)  = 0x001f0001
set *((unsigned short *) $cscr1) = 0x3d80

# CS2 -- LED bank is on address=0x30400000
set *((unsigned short *) $csar2) = 0x3040
set *((unsigned long *) $csmr2)  = 0x000f0001
set *((unsigned short *) $cscr2) = 0x3d40

# CS3 -- Ethernet, address=0x30600000
set *((unsigned short *) $csar3) = 0x3060
set *((unsigned long *) $csmr3)  = 0x000f0001
set *((unsigned short *) $cscr3) = 0x1180

# CS4 -- Nothing, address=0x30800000
set *((unsigned short *) $csar4) = 0x3080
set *((unsigned long *) $csmr4)  = 0x000f0001
set *((unsigned short *) $cscr4) = 0x3d40

# CS5 -- Nothing, address=0x30a00000
set *((unsigned short *) $csar5) = 0x30a0
set *((unsigned long *) $csmr5)  = 0x000f0001
set *((unsigned short *) $cscr5) = 0x3d40

# CS6 -- Optional Hifn 7901, address=0x30c00000
set *((unsigned short *) $csar6) = 0x30c0
set *((unsigned long *) $csmr6)  = 0x000f0001
set *((unsigned short *) $cscr6) = 0x3d00

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
#	NETtel ColdFire 5307 target...
#
target bdm /dev/bdmcf0

addresses
setup-sram
setup-cs
setup-pp
load bin/eliamem.elf
set $pc = 0x20000000
set $sp = 0x20000400
set $fp = 0x20000400
set $vbr = 0x20000000
set $ps = 0x2700

set print pretty
set print asm-demangle
display/i $pc
select-frame 0

