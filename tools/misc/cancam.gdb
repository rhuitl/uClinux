#
# GDB Init script for the Feith CanCam board with 5272 processor.
#
# The main purpose of this script is to configure the
# DRAM controller so code can be loaded.
#
#

define addresses

set $mbar  = 0x10000001
set $scr   = $mbar - 1 + 0x004
set $spr   = $mbar - 1 + 0x006
set $pmr   = $mbar - 1 + 0x008
set $apmr  = $mbar - 1 + 0x00e
set $dir   = $mbar - 1 + 0x010
set $icr1  = $mbar - 1 + 0x020
set $icr2  = $mbar - 1 + 0x024
set $icr3  = $mbar - 1 + 0x028
set $icr4  = $mbar - 1 + 0x02c
set $isr   = $mbar - 1 + 0x030
set $pitr  = $mbar - 1 + 0x034
set $piwr  = $mbar - 1 + 0x038
set $pivr  = $mbar - 1 + 0x03f
set $csbr0 = $mbar - 1 + 0x040
set $csor0 = $mbar - 1 + 0x044
set $csbr1 = $mbar - 1 + 0x048
set $csor1 = $mbar - 1 + 0x04c
set $csbr2 = $mbar - 1 + 0x050
set $csor2 = $mbar - 1 + 0x054
set $csbr3 = $mbar - 1 + 0x058
set $csor3 = $mbar - 1 + 0x05c
set $csbr4 = $mbar - 1 + 0x060
set $csor4 = $mbar - 1 + 0x064
set $csbr5 = $mbar - 1 + 0x068
set $csor5 = $mbar - 1 + 0x06c
set $csbr6 = $mbar - 1 + 0x070
set $csor6 = $mbar - 1 + 0x074
set $csbr7 = $mbar - 1 + 0x078
set $csor7 = $mbar - 1 + 0x07c
set $pacnt = $mbar - 1 + 0x080
set $paddr = $mbar - 1 + 0x084
set $padat = $mbar - 1 + 0x086
set $pbcnt = $mbar - 1 + 0x088
set $pbddr = $mbar - 1 + 0x08c
set $pbdat = $mbar - 1 + 0x08e
set $pcddr = $mbar - 1 + 0x094
set $pcdat = $mbar - 1 + 0x096
set $pdcnt = $mbar - 1 + 0x098
set $sdcr  = $mbar - 1 + 0x180
set $sdtr  = $mbar - 1 + 0x184
set $wrrr  = $mbar - 1 + 0x280
set $wirr  = $mbar - 1 + 0x284
set $wcr   = $mbar - 1 + 0x288
set $wer   = $mbar - 1 + 0x28c

end


#
# Setup system configuration
#
define setup-sys
set *((unsigned short *) $scr) = 0x8003
set *((unsigned short *) $spr) = 0x00ff
set *((unsigned long *) $pmr) = 0x02640000

set *((unsigned char *) $pivr) = 0x40
end


#
# Setup Chip Selects
#
define setup-cs

# CS0 -- FLASH
set *((unsigned long *) $csbr0) = 0xf0000201
set *((unsigned long *) $csor0) = 0xff800014

# CS1 -- FPGA
set *((unsigned long *) $csbr1) = 0x30400001
set *((unsigned long *) $csor1) = 0xfffff008

# CS2 -- Optional FSRAM
set *((unsigned long *) $csbr2) = 0x00000000
set *((unsigned long *) $csor2) = 0x00000000

# CS3 -- not used
set *((unsigned long *) $csbr3) = 0x00000000
set *((unsigned long *) $csor3) = 0x00000000

# CS4 --  not used
set *((unsigned long *) $csbr4) = 0x00000000
set *((unsigned long *) $csor4) = 0x00000000

# CS5 -- not used
set *((unsigned long *) $csbr5) = 0x00000000
set *((unsigned long *) $csor5) = 0x00000000

# CS6 -- not used
set *((unsigned long *) $csbr6) = 0x00000000
set *((unsigned long *) $csor6) = 0x00000000

# CS7 -- SDRAM CANCam
set *((unsigned long *) $csbr7) = 0x00000701
set *((unsigned long *) $csor7) = 0xfc00007c

end

define setup-sram
set $rambar  = 0x20000001
end


#
# Setup the DRAM controller.
#
define setup-dram
#set *((unsigned long *) $sdtr) = 0x0000f715

#set *((unsigned long *) $sdcr) = 0x00006511
#set *((unsigned long *) 0) = 0
#set *((unsigned long *) $sdcr) = 0x00006510

set *((unsigned long *) $sdtr) = 0x0000f715

set *((unsigned long *) $sdcr) = 0x00004411
set *((unsigned long *) 0) = 0
set *((unsigned long *) $sdcr) = 0x00004410

# Dummy write to start SDRAM
set *((unsigned long *) 0) = 0
end

#
# Setup for GPIO pins
#
define setup-ppio

# PORT A
set *((unsigned long *) $pacnt) = 0x00000000
set *((unsigned short *) $paddr) = 0x0000
set *((unsigned short *) $padat) = 0x0352

# PORT B
set *((unsigned long *) $pbcnt) = 0x55550405
set *((unsigned short *) $pbddr) = 0x0000
set *((unsigned short *) $pbdat) = 0x0000

# PORT C
set *((unsigned short *) $pcddr) = 0x0000
set *((unsigned short *) $pcdat) = 0x0000

# PORT D
set *((unsigned long *) $pdcnt) = 0x00000208

end


#
#	Added for uClinux-coldfire target...
#
target bdm /dev/bdmcf0

addresses
setup-sram
setup-sys
setup-cs
setup-dram
setup-ppio
load images/image.elf
set $pc = 0x00000400
set $vbr = 0x00000000
set $ps = 0x2700

set print pretty
set print asm-demangle
display/i $pc
select-frame 0

