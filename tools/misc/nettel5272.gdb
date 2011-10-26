#
# GDB Init script for the Coldfire 5272 based NETtel board.
#
# The main purpose of this script is to configure the 
# DRAM controller so code can be loaded.
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
set $wirr  = $mbar - 1 + 0x283
set $wcr   = $mbar - 1 + 0x288
set $wer   = $mbar - 1 + 0x28c

end


#
# Setup system configuration
#
define setup-sys
set *((unsigned short *) $scr) = 0x9003
set *((unsigned short *) $spr) = 0x00ff
set *((unsigned char *) $pivr) = 0x4f
end


#
# Setup Chip Selects
#
define setup-cs

# CS0 -- FLASH
set *((unsigned long *) $csbr0) = 0xf0000201
set *((unsigned long *) $csor0) = 0xf0000014

# CS1 -- not used
set *((unsigned long *) $csbr1) = 0x00000000
set *((unsigned long *) $csor1) = 0x00000000

# CS2 -- not used
set *((unsigned long *) $csbr2) = 0x00000000
set *((unsigned long *) $csor2) = 0x00000000

# CS3 -- Davicom 10Mb ethernet, 16bit,
set *((unsigned long *) $csbr3) = 0x30600201
set *((unsigned long *) $csor3) = 0xfff0007c

# CS4 --  not used
set *((unsigned long *) $csbr4) = 0x00000000
set *((unsigned long *) $csor4) = 0x00000000

# CS5 -- not used
set *((unsigned long *) $csbr5) = 0x00000000
set *((unsigned long *) $csor5) = 0x00000000

# CS6 -- not used
set *((unsigned long *) $csbr6) = 0x00000000
set *((unsigned long *) $csor6) = 0x00000000

# CS7 -- SDRAM, 4MB, 32 bit
set *((unsigned long *) $csbr7) = 0x00000701
set *((unsigned long *) $csor7) = 0xffc0007c

# CS7 -- SDRAM, 8MB, 16 bit
#set *((unsigned long *) $csbr7) = 0x00000601
#set *((unsigned long *) $csor7) = 0xff80017c

end


#
# Setup the DRAM controller.
#

define setup-dram
set *((unsigned long *) $sdtr) = 0x0000f539
# SDRAM, 32 bit
set *((unsigned long *) $sdcr) = 0x00004211
# SDRAM, 16 bit
#set *((unsigned long *) $sdcr) = 0x00002211

# Dummy write to start SDRAM
set *((unsigned long *) 0) = 0
end


#
# Setup for GPIO pins
#
define setup-ppio

# PORT A
set *((unsigned long *) $pacnt) = 0x00000000
set *((unsigned short *) $paddr) = 0x001f
set *((unsigned short *) $padat) = 0xffff

# PORT B
set *((unsigned long *) $pbcnt) = 0x55550555
set *((unsigned short *) $pbddr) = 0x0040
set *((unsigned short *) $pbdat) = 0xffff

# PORT C -- not used, in 32 bit mode

# PORT D
set *((unsigned long *) $pdcnt) = 0x00000000

end


#
#       FLASH prgramming code
#
define flash-erase
set *((unsigned short *) 0xf0000aaa) = 0xaaaa
set *((unsigned short *) 0xf0000554) = 0x5555
set *((unsigned short *) 0xf0000aaa) = 0x8080
set *((unsigned short *) 0xf0000aaa) = 0xaaaa
set *((unsigned short *) 0xf0000554) = 0x5555
set *((unsigned short *) 0xf0000000) = 0x3030
end

define flash-programword
set *((unsigned short *) 0xf0000aaa) = 0xaaaa
set *((unsigned short *) 0xf0000554) = 0x5555
set *((unsigned short *) 0xf0000aaa) = 0xa0a0
set *((unsigned short *) $arg0) = $arg1
#while (*((unsigned short *) $arg0) != $arg1)
#       set $d0 = 0
end

define flash-programstartaddr
flash-programword 0xf0000004 0x0000
flash-programword 0xf0000006 0x0400
end

define flash-program
set $num = $arg0
set $dst = 0xf0000400
set $src = 0x20000000
flash-programstartaddr
while ($num > 0)
	set $word = *((unsigned short *) $src)
	flash-programword $dst $word
	set $src = $src + 2
	set $dst = $dst + 2
	set $num = $num - 2
end
end


#
#	GDB boot loader
#
define bootload
load boot/etherboot/ethboot-bdm.elf
load boot/boot-bdm.elf
symbol-file boot/boot-bdm.elf
set $pc=_start
add-symbol-file boot/etherboot/ethboot-bdm.elf &etherboot_addr
echo \nType 'cont' to start bootloader...\n
end


#
#	NETtel 5272 uClinux-coldfire target...
#
target bdm /dev/bdmcf0

addresses
setup-sys
setup-cs
setup-dram
setup-ppio
set $rambar = 0x20000001
set print pretty
set print asm-demangle
display/i $pc

