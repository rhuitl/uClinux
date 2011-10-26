#	XScale DoC Functions - NG5100, SG710

#
#	DoC programming macros. We rely on the modified boot loader to
#	program the DoC. It is just a little too compiicated to script
#	here.
#
proc doc-programipl { } {
	mem-init
	mem-switch
	writable
	big
	load_image boot/ixp425/boot.elf
	load_image boot/loadipl.elf
	reg pc 0x3fc0000
	resume
}

proc doc-programboot { } {
	mem-init
	mem-switch
	writable
	big
	load_image boot/boot-jtag.elf
	load_image boot/loadboot.elf
	#reg pc 0x1fc0028
	reg pc 0x3fc0000
	resume
}

proc doc-runboot { } {
	mem-init
	mem-switch
	writable
	big
	load_image boot.elf
	verify_image boot.elf
	#reg pc 0x1fe0028
	reg pc 0x1000	
	resume
}
