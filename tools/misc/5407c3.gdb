# GDB/BDM init file for 5407C3 development board from Motorola
# based on a file by Kendrick Hamilton of SED Systems Inc.
# Modified by Steve Keppel-Jones of Precidia Technologies Inc.
#
# This is designed to set up the 5407C3 for loading a Linux
# kernel (or other similar code) and running it, e.g. with
# "load image.elf", "set $pc = 0x20000", "cont".
# It also assumes that the file "linux" is available in the
# current directory for symbol information; this can be changed
# below if desired (see "file linux").
#
# This file has been tested to allow loading of the Linux kernel
# as described above, but some setup items have not been 
# extensively tested (e.g. the 2nd SDRAM memory bank and the
# PCI chip select), and there is no SDRAM probing code here.

# Address shortcut definition function
define set_addresses

# The syntax here is fairly confusing if you are new to GDB:
# The following line refers to a predefined "register" ("mbar")
# and thus constitutes a "poke" command (to use trusty ol' BASIC
# terminology), or in other words it actually sets a register
# inside the 5407 chip:
set $mbar  = 0x10000001

# These lines refer to "convenience variables", since they are not
# predefined to GDB, and so these do not constitute "pokes" but
# rather setting of internal variable addresses.  (No data are
# sent through the BDM for these statements.)
# The dereference of $mbar, however, still constitutes a "peek" since
# it is still a predefined register.
# It might make more sense to set an internal convenience variable
# for $mbar to be used to calculate these offsets, so that we
# wouldn't have to subtract 1 from each one.
set $rsr   = (unsigned char *)($mbar - 1 + 0x000)
set $sypcr = (unsigned char *)($mbar - 1 + 0x001)
set $swivr = (unsigned char *)($mbar - 1 + 0x002)
set $swsr  = (unsigned char *)($mbar - 1 + 0x003)
set $par   = (unsigned short*)($mbar - 1 + 0x004)
set $irqpar= (unsigned char *)($mbar - 1 + 0x006)
set $pllcr = (unsigned char *)($mbar - 1 + 0x008)
set $mpark = (unsigned char *)($mbar - 1 + 0x00c)
set $ipr   = (unsigned long *)($mbar - 1 + 0x040)
set $imr   = (unsigned long *)($mbar - 1 + 0x044)
set $avr   = (unsigned char *)($mbar - 1 + 0x04b)

set $icr0  = (unsigned char *)($mbar - 1 + 0x04c)
set $icr1  = (unsigned char *)($mbar - 1 + 0x04d)
set $icr2  = (unsigned char *)($mbar - 1 + 0x04e)
set $icr3  = (unsigned char *)($mbar - 1 + 0x04f)
set $icr4  = (unsigned char *)($mbar - 1 + 0x050)
set $icr5  = (unsigned char *)($mbar - 1 + 0x051)
set $icr6  = (unsigned char *)($mbar - 1 + 0x052)
set $icr7  = (unsigned char *)($mbar - 1 + 0x053)
set $icr8  = (unsigned char *)($mbar - 1 + 0x054)
set $icr9  = (unsigned char *)($mbar - 1 + 0x055)
set $icr10 = (unsigned char *)($mbar - 1 + 0x056)
set $icr11 = (unsigned char *)($mbar - 1 + 0x057)

set $csar0 = (unsigned short*)($mbar - 1 + 0x080)
set $csmr0 = (unsigned long *)($mbar - 1 + 0x084)
set $cscr0 = (unsigned short*)($mbar - 1 + 0x08a)

set $csar1 = (unsigned short*)($mbar - 1 + 0x08c)
set $csmr1 = (unsigned long *)($mbar - 1 + 0x090)
set $cscr1 = (unsigned short*)($mbar - 1 + 0x096)

set $csar2 = (unsigned short*)($mbar - 1 + 0x098)
set $csmr2 = (unsigned long *)($mbar - 1 + 0x09c)
set $cscr2 = (unsigned short*)($mbar - 1 + 0x0a2)

set $csar3 = (unsigned short*)($mbar - 1 + 0x0a4)
set $csmr3 = (unsigned long *)($mbar - 1 + 0x0a8)
set $cscr3 = (unsigned short*)($mbar - 1 + 0x0ae)

set $csar4 = (unsigned short*)($mbar - 1 + 0x0b0)
set $csmr4 = (unsigned long *)($mbar - 1 + 0x0b4)
set $cscr4 = (unsigned short*)($mbar - 1 + 0x0ba)

set $csar5 = (unsigned short*)($mbar - 1 + 0x0bc)
set $csmr5 = (unsigned long *)($mbar - 1 + 0x0c0)
set $cscr5 = (unsigned short*)($mbar - 1 + 0x0c6)

set $csar6 = (unsigned short*)($mbar - 1 + 0x0c8)
set $csmr6 = (unsigned long *)($mbar - 1 + 0x0cc)
set $cscr6 = (unsigned short*)($mbar - 1 + 0x0d2)

set $csar7 = (unsigned short*)($mbar - 1 + 0x0d4)
set $csmr7 = (unsigned long *)($mbar - 1 + 0x0d8)
set $cscr7 = (unsigned short*)($mbar - 1 + 0x0de)

set $dcr   = (unsigned short*)($mbar - 1 + 0x100)
set $dacr0 = (unsigned long *)($mbar - 1 + 0x108)
set $dmr0  = (unsigned long *)($mbar - 1 + 0x10c)
set $dacr1 = (unsigned long *)($mbar - 1 + 0x110)
set $dmr1  = (unsigned long *)($mbar - 1 + 0x114)

set $tmr0  = (unsigned short*)($mbar - 1 + 0x140)
set $trr0  = (unsigned short*)($mbar - 1 + 0x144)
set $tcr0  = (unsigned short*)($mbar - 1 + 0x148)
set $tcn0  = (unsigned short*)($mbar - 1 + 0x14C)
set $ter0  = (unsigned char *)($mbar - 1 + 0x151)
set $tmr1  = (unsigned short*)($mbar - 1 + 0x180)
set $trr1  = (unsigned short*)($mbar - 1 + 0x184)
set $tcr1  = (unsigned short*)($mbar - 1 + 0x188)
set $tcn1  = (unsigned short*)($mbar - 1 + 0x18C)
set $ter1  = (unsigned char *)($mbar - 1 + 0x191)

set $paddr = (unsigned short*)($mbar - 1 + 0x244)
set $padat = (unsigned short*)($mbar - 1 + 0x248)

end

# Tell GDB what to use for symbol information.  This does
# not load anything onto the board.
file linux

echo Setting up BDM\n
target bdm /dev/bdmcf0
#disable caching of values in gdb
set remotecache off
bdm_setdelay 2
bdm_reset

echo Setting up Coldfire Memory Map\n
set $sr=0x2700

# Call function defined above; this sets $mbar
set_addresses

echo Disabling cache\n
set $cacr=0x00000000
set $acr0=0x00000000
set $acr1=0x00000000
set $acr2=0x00000000
set $acr3=0x00000000

echo Enabling internal SRAM\n
set $rambar=0x20000001
set $rambar1=0x20000801

#Clear the system protection control register (disable to watchdog)
set *$sypcr=0x00

#Set bus arbitration control to park on Coldfire, I am not using DMA
# there is no external master to use internal chip resources or access internal
# devices.
set *$mpark=0x40

#Configure the PLL Control Register. Enable CPU stop but any interrupt can
# wake the processor. Bus clock us driven (used for SDRAM).
#set *$pllcr=0x80
set *$pllcr=0x00

#Mask interrupts
#set *$imr=0x0003fffe
set *$imr=0xfff0ff7f
#printf "The interrupt pending register is set to 0x%08x\n", *(unsigned long *)0x10000040

#Enable autovectoring of external interrupts
#set *$avr=0x00
set *$avr=0xff

#Configure Pin Assignment Register
#printf "The Pin Assignment Register is set to 0x%04x\n", *(unsigned short*)0x10000004
set *$par=0xff00
#configure parallel port to outputs
# This affects the DRAM muxing so get it right!
set *$paddr=0xffff
set *$padat=0x0003

#Configure Interrupt Port Assignment Register to IRQ5/3/1
set *$irqpar=0x00

#Disable chipselect 1-7
set *$csmr1=0x00000000
set *$csmr2=0x00000000
set *$csmr3=0x00000000
set *$csmr4=0x00000000
set *$csmr5=0x00000000
set *$csmr6=0x00000000
set *$csmr7=0x00000000

#Configure Chipselect 3 for Ethernet to address 0x40000000
set *$csar3=0x4000
set *$cscr3=0x0080
set *$csmr3=0x000F0001

#Configure Chipselect 2 for External SRAM to address 0x30000000
# Note there is no external SRAM on a stock 5407C3 board, but we
# set this up anyway
set *$csar2=0x3000
set *$cscr2=0x0100
set *$csmr2=0x00070001

#Configure Chipselect 1 for PCI at 0xFFFF0000
set *$csar1=0xFFFF
set *$cscr1=0x0000
set *$csmr1=0x00000001

#Configure Chipselect 0 for Flash at address 0x7fe00000
set *$csar0=0x7fe0
set *$cscr0=0x1980
set *$csmr0=0x001f0001


#DRAM configure - modified - Kendrick Hamilton & SKJ
# Bank 0
set *$dcr = 0x822f
set *$dacr0 = 0x00001304
set *$dmr0 = 0x00fc0001
set *$dacr0 = 0x0000130c
set *(unsigned long  *)(0x4) = 0xbeaddeed
printf "DRAM setup delay\n"
set *$dacr0 = 0x00009304
printf "Another DRAM setup delay\n"
set *$dacr0 = 0x00009344
set *(unsigned long  *)(0x80400) = 0x00000000

# Bank 1
set *$dacr1 = 0x01001304
set *$dmr1 = 0x00fc0001
set *$dacr1 = 0x0100130c
set *(unsigned long  *)(0x01000004) = 0xbeaddeed
printf "DRAM setup delay\n"
set *$dacr1 = 0x01009304
printf "Another DRAM setup delay\n"
set *$dacr1 = 0x01009344
set *(unsigned long  *)(0x01080400) = 0x00000000

printf "\tTo print a byte(8 bits):  x/1xb\n"
printf "\tTo print a word(16 bits): x/1xh\n"
printf "\tTo print a long(32 bits): x/1xw\n"
