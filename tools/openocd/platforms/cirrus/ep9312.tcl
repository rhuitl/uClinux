# Cirrus Logic EP9312 processor
source [find interface/jtagkey.cfg]
source [find tools/openocd/platforms/common/utils.tcl]

if { [info exists CHIPNAME] } {
   set  _CHIPNAME $CHIPNAME
} else {
   set  _CHIPNAME ep9312
}
set CPUTAPID 0x10920f0f

if { [info exists ENDIAN] } {
   set  _ENDIAN $ENDIAN
} else {
   set  _ENDIAN little
}

if { [info exists CPUTAPID ] } {
   set _CPUTAPID $CPUTAPID
} else {
  # force an error till we get a good number
   set _CPUTAPID 0xffffffff
}

jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id $_CPUTAPID
adapter_nsrst_delay 100
jtag_ntrst_delay 100

set _TARGETNAME $_CHIPNAME.cpu
target create $_TARGETNAME arm920t -endian $_ENDIAN -chain-position $_TARGETNAME -work-area-phys 0x80014000 -work-area-size 0x1000 -work-area-backup 1

#flash configuration
#flash bank <driver> <base> <size> <chip_width> <bus_width> [driver_options ...]
# set _FLASHNAME $_CHIPNAME.flash
# flash bank $_FLASHNAME cfi 0x60000000 0x1000000 2 2 $_TARGETNAME

proc uart_init {{num 1}} {
	if {$num == 0} {
		# This is set to 115200,8,n,1
		mww 0x808c0010 0x07000000
		mww 0x808c000c 0x00000000
		mww 0x808c0008 0x60000000
		mww 0x808c0014 0x01000000
	} elseif {$num == 1} {
		# 8 fifo-enable 1 none
		# fifo set *((unsigned char *) 0x808d0008) = 0x70
		# BR = 0007 = 14.7456MHz / (16 * 115200) - 1
		mwb 0x808d0010 0x00
		mwb 0x808d000c 0x00
		mwb 0x808d0008 0x00
		mwb 0x808d0010 0x07
		mwb 0x808d000c 0x00
		mwb 0x808d0008 0x60
		mwb 0x808d0014 0x01
	}
}

proc uart_putc {c {num 1}} {
	if {$num == 0} {
		mww 0x808c0000 $c
	} elseif {$num == 1} {
		mwb 0x808d0000 $c
	}
}

proc ram32_init {} {
	# Set SDCS0 to be 16MB (2*64Mbit devices parallel on 32bit data bus)
	# This sets it for RAS=2, CAS=3, 4 banks
	mww 0x80060010 0x00210028
	sleep 1000
	# Set global config to initiate NOPs
	mww 0x80060004 0x80000003
	sleep 1000
	# Send PRECHARGE-ALL command
	mww 0x80060004 0x80000001
	# Enable refresh engine to generate some fast refreshes
	mww 0x80060008 0x00000010
	sleep 1000
	# Switch refresh engine back to normal
	mww 0x80060008 0x00000023
	# Send MODE command
	mww 0x80060004 0x80000002
	set junk [mrw 0xc0008800]
	set junk [mrw 0xc0408800]
	set junk [mrw 0xc0808800]
	set junk [mrw 0xc0c08800]
	# Set the real value into the global configuration register
	mww 0x80060004 0x80000000
}


proc clk1_init {} {
	# Fout = 14.7456MHz
	# safe settings
	#
	mww 0x80930020 0
	sleep 1000
}

proc clk2_init {} {
	# Fout = 192000000.00
	# USB  =  48000000.00
	#
	mww 0x80930024 0x300dc317
	sleep 1000
}

proc dev_init {} {
	#mov     r1, #0x80000000
	mww 0xc0000000 0xe3a01102
	#orr     r1, r1, #0x930000
	mww 0xc0000004 0xe3811893
	#mov     r0, #0xaa
	mww 0xc0000008 0xe3a000aa
	#str     r0, [r1, #192]
	mww 0xc000000c 0xe58100c0
	#mov     r0, #0x140000
	mww 0xc0000010 0xe3a00705
	#str     r0, [r1, #128]
	mww 0xc0000014 0xe5810080
	#nop     (mov r0,r0)
	mww 0xc0000018 0xe1a00000
	#nop     (mov r0,r0)
	mww 0xc000001c 0xe1a00000
	mdw 0xc0000000 0x1c
	reg pc 0xc0000000
	stepi 8
}

proc my_init {} {
	# swreset
	ram32_init
	clk1_init
	clk2_init
	# mem-init
	sleep 1000
	dev_init
	sleep 1000

	uart_init 1
	uart_putc 0x0a 1
	uart_putc 0x0d 1
	uart_putc 0x52 1
	uart_putc 0x65 1
	uart_putc 0x61 1
	uart_putc 0x64 1
	uart_putc 0x79 1
	uart_putc 0x0a 1
	uart_putc 0x0d 1
}

