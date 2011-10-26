# Marvell 88F6281

source [find interface/jtagkey.cfg]

jtag_rclk 3000
jtag newtap feroceon cpu -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id 0x20a023d3

target create feroceon.cpu feroceon -endian little -chain-position feroceon.cpu

reset_config trst_and_srst trst_push_pull srst_open_drain srst_nogate
jtag_nsrst_delay 200
jtag_ntrst_delay 200

feroceon.cpu configure \
	-work-area-phys 0x10000000 \
	-work-area-size 65536 \
	-work-area-backup 0

# arm7_9 dcc_downloads enable
arm7_9 dcc_downloads disable
arm7_9 dbgrq disable

# this assumes the hardware default peripherals location before u-Boot moves it
nand device orion 0 0xd8000000

proc dram_667 {} {
	# MT47H128M8 dram config
	#tRAS - 14
	#tRCD - 5
	#tRP  - 5
	#tWR  - 5
	#tWTR - 3
	#xRAS - (rest of ras)
	#tRRD - 3
	#tRTP - 3
	#
	#tRFC - 43
	#tR2R - 1
	#tR2W-W2R - 1
	#tW2W - 1

	mww 0xD0001400 0x43000400 #  SDRAM Configuration Register (FIX timer)
	mww 0xD0001404 0x39543000 #  DDR Controller Control Low Register
	mww 0xD0001408 0x22125451 #  SDRAM Timing (Low) Register
	mww 0xD000140C 0x00000833 #  SDRAM Timing (High) Register
	mww 0xD0001410 0x00000001 #  SDRAM Address Control Register
	mww 0xD0001414 0x00000000 #  SDRAM Open Pages Control Register
	mww 0xD0001418 0x00000000 #  SDRAM Operation Register
	mww 0xD000141C 0x00000652 #  SDRAM Mode Register
	mww 0xD0001420 0x00000042 #  Extended DRAM Mode Register
	mww 0xD0001424 0x0000F17F #  DDR Controller Control High Register
	mww 0xD0001428 0x00085520 #  DDR2 SDRAM Timing Low Register
	mww 0xD000147c 0x00008552 #  DDR2 SDRAM Timing High Register
	mww 0xD0001504 0x0FFFFFF1 #  CS0n Size Register
	mww 0xD000150C 0x00000000 #  CS1n Size Register
	mww 0xD0001514 0x00000000 #  CS2n Size Register
	mww 0xD000151C 0x00000000 #  CS3n Size Register
	mww 0xD0001494 0x003C0000 #  DDR2 SDRAM ODT Control (Low) Register
	mww 0xD0001498 0x00000000 #  DDR2 SDRAM ODT Control (High) REgister
	mww 0xD000149C 0x0000F80F #  DDR2 Dunit ODT Control Register
	mww 0xD0001480 0x00000001 #  DDR SDRAM Initialization Control Register
}

proc dram_400 {} {
	mww 0xD0001400 0x43000400 #  SDRAM Configuration Register (FIX timer)
	mww 0xD0001404 0x34143000 #  DDR Controller Control Low Register
	mww 0xD0001408 0x11012228 #  SDRAM Timing (Low) Register
	mww 0xD000140C 0x00000015 #  SDRAM Timing (High) Register
	mww 0xD0001410 0x00000009 #  SDRAM Address Control Register
	mww 0xD0001414 0x00000000 #  SDRAM Open Pages Control Register
	mww 0xD0001418 0x00000000 #  SDRAM Operation Register
	mww 0xD000141C 0x00000632 #  SDRAM Mode Register
	mww 0xD0001420 0x00000000 #  Extended DRAM Mode Register
	mww 0xD0001424 0x0000F17f #  DDR Controller Control High Register
	mww 0xD0001428 0x00085520 #  DDR2 SDRAM Timing Low Register
	mww 0xD000147c 0x00008551 #  DDR2 SDRAM Timing High Register
	mww 0xD0001500 0x00000000 #  CS0n Base Address
	mww 0xD0001504 0x03FFFFF1 #  CS0n Size Register
	mww 0xD0001508 0x10000000 #  CS1n Base Address
	mww 0xD000150C 0x00000000 #  CS1n Size Register
	mww 0xD0001510 0x20000000 #  CS2n Base Address
	mww 0xD0001514 0x00000000 #  CS2n Size Register
	mww 0xD0001518 0x30000000 #  CS3n Base Address
	mww 0xD000151C 0x00000000 #  CS3n Size Register
	mww 0xD0001494 0x00110011 #  DDR2 SDRAM ODT Control (Low) Register
	mww 0xD0001498 0x0000000c #  DDR2 SDRAM ODT Control (High) REgister
	mww 0xD000149C 0x0000E8FF #  DDR2 Dunit ODT Control Register
	mww 0xD0001480 0x00000001 #  DDR SDRAM Initialization Control Register
}

proc uart_init {} {
	mww 0xD001200C 0x83 # LCR
	mww 0xD0012000 90   # DLL
	mww 0xD0012004 0x00 # DLH
	mww 0xD001200C 0x03 # LCR
	mww 0xD0012008 0x00 # FCR
	mww 0xD0012010 0x00 # MCR
}

proc uart_putc {c} {
	mww 0xD0012000 $c   # THR
}

proc 88f6281_init {} {
	# We need to assert DBGRQ while holding nSRST down.
	# However DBGACK will be set only when nSRST is released.
	# Furthermore, the JTAG interface doesn't respond at all when
	# the CPU is in the WFI (wait for interrupts) state, so it is
	# possible that initial tap examination failed.  So let's
	# re-examine the target again here when nSRST is asserted which
	# should then succeed.

	jtag_reset 0 1
	feroceon.cpu arp_examine
	halt 0
	jtag_reset 0 0
	wait_halt

	#arm mcr 15 0 0 1 0 0x00052078
}

proc utm400_reflash_uboot { } {

	# reflash the u-Boot binary and reboot into it
	utm400_init
	nand probe 0
	nand erase 0 0x0 0xa0000
	nand write 0 uboot.bin 0 oob_softecc_kw
	resume

}

proc utm400_reflash_uboot_env { } {

	# reflash the u-Boot environment variables area
	utm400_init
	nand probe 0
	nand erase 0 0xa0000 0x40000
	nand write 0 uboot-env.bin 0xa0000 oob_softecc_kw
	resume

}

proc utm400_load_uboot { } {

	# load u-Boot into RAM and execute it
	utm400_init
	load_image uboot.elf
	verify_image uboot.elf
	resume 0x00600000

}

