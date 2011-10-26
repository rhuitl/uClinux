#
# GDB Init script for the Coldfire 5407 processor.
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

set $csbar = $mbar - 1 + 0x098
set $csbamr= $mbar - 1 + 0x09c
set $csmr2 = $mbar - 1 + 0x09e
set $cscr2 = $mbar - 1 + 0x0a2
set $csmr3 = $mbar - 1 + 0x0aa
set $cscr3 = $mbar - 1 + 0x0ae
set $csmr4 = $mbar - 1 + 0x0b6
set $cscr4 = $mbar - 1 + 0x0ba
set $csmr5 = $mbar - 1 + 0x0c2
set $cscr5 = $mbar - 1 + 0x0c6
set $csmr6 = $mbar - 1 + 0x0ce
set $cscr6 = $mbar - 1 + 0x0d2
set $csmr7 = $mbar - 1 + 0x0da
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
#	Target is ColdFire board...
#
target bdm /dev/bdmcf0

addresses

set print pretty
set print asm-demangle
display/i $pc
select-frame 0

