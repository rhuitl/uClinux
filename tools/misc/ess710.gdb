#
#	SnapGear/ESS710 target gdbinit script.
#


#
#	UART functions
#

define uart-init
set *((long*) 0xc800000c) = 0x83
set *((long*) 0xc8000000) = 0x08
set *((long*) 0xc8000004) = 0x00
set *((long*) 0xc800000c) = 0x03
set *((long*) 0xc8000004) = 0x40
end

define uart-print
set *((long*) 0xc8000000) = $arg0
end


#
#	Memory functions
#

define mem-init
# set for 128MB (3CAS, 3RAS)
set *((long*) 0xcc000000) = 0x1b

# disable refresh
set *((long*) 0xcc000004) = 0

# send NOP command
set *((long*) 0xcc000008) = 0x03
shell sleep 1

# set refresh count
set *((long*) 0xcc000004) = 0x384
shell sleep 1

# send PRECHARGE-ALL command
set *((long*) 0xcc000008) = 0x02
shell sleep 1

# send AUTO-REFRESH command
set $num = 8
while ($num > 0)
	set *((long*) 0xcc000008) = 0x04
	shell sleep 1
	set $num = $num - 1
end

# send MODE (CAS3) command
set *((long*) 0xcc000008) = 0x01
shell sleep 1

# send NORMAL-OPERATION command
set *((long*) 0xcc000008) = 0x06
shell sleep 1

end



#
#	Switch memory and expansion regions
#
define mem-switch
set *((unsigned long *) 0x10000000) = 0xe3a01331
set *((unsigned long *) 0x10000004) = 0xe3811020
set *((unsigned long *) 0x10000008) = 0xe5912000
set *((unsigned long *) 0x1000000c) = 0xe3c22102
set *((unsigned long *) 0x10000010) = 0xe5812000
set $pc = 0x10000000
stepi 5
end


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


#
#	Set BIG endian mode
#
define big
set *((unsigned long *) 0x10000000) = 0xee110f10
set *((unsigned long *) 0x10000004) = 0xe3800080
set *((unsigned long *) 0x10000008) = 0xee010f10
set *((unsigned long *) 0x1000000c) = 0xee120f10
set *((unsigned long *) 0x10000010) = 0xe1a00000
set *((unsigned long *) 0x10000010) = 0xe24ff004
set $pc = 0x10000000
stepi 6
end

#
#	Enable the caches.
#
define cache
set *((unsigned long *) 0x10000000) = 0xee110f10
set *((unsigned long *) 0x10000004) = 0xe3800a01
set *((unsigned long *) 0x10000008) = 0xe380000c
set *((unsigned long *) 0x1000000c) = 0xee010f10
set *((unsigned long *) 0x10000010) = 0xee120f10
set *((unsigned long *) 0x10000014) = 0xe1a00000
set *((unsigned long *) 0x10000018) = 0xe24ff004
set *((unsigned long *) 0x1000001c) = 0xee071f15
set *((unsigned long *) 0x10000020) = 0xee120f10
set *((unsigned long *) 0x10000024) = 0xe1a00000
set *((unsigned long *) 0x10000028) = 0xe24ff004
set $pc = 0x10000000
stepi 0xb
end

#
#	Enable the PCI clock (which is on GPIO14)
#
define pci-clock
set *((unsigned long *) 0xc8004004) = 0x00003fff
set *((unsigned long *) 0xc8004018) = 0x000001ff
set *((unsigned long *) 0xc8004000) = 0x00004000
end

#
#	Configure the flash region to be writable.
#
define writable
set *((unsigned long *) 0x10000000) = 0xe3a01331
set *((unsigned long *) 0x10000004) = 0xe5912000
set *((unsigned long *) 0x10000008) = 0xe3822002
set *((unsigned long *) 0x1000000c) = 0xe5812000
set $pc = 0x10000000
stepi 4
end


#
#	Set debugger into big endian mode.
#
define gdb-big
set endian big
monitor endian big
end


#
#	DoC programming macros. We rely on the modified boot loader to
#	program the DoC. It is just a little too compiicated to script
#	here.
#
define doc-programipl
mem-init
mem-switch
writable
big
load boot/ixp425/boot.elf
load boot/loadipl.elf
set $pc = 0x1ff0028
c
end

define doc-programboot
mem-init
mem-switch
writable
big
load boot/boot-jtag.elf
load boot/loadboot.elf
set $pc = 0x1ff0028
c
end

define doc-runipl
mem-init
mem-switch
load boot/ixp425/boot.elf
set $pc = 0x1000
c
end

define doc-runboot
mem-init
mem-switch
writable
big
load boot/boot.elf
set $pc = 0x1fe0028
end

#
#	Startup commands...
#
set output-radix 16
set input-radix 16

target remote localhost:8888

set print pretty
set print asm-demangle
display/i $pc

