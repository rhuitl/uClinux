/*
 *	Copyright (C) 2003, David McCullough <davidm@snapgear.com>
 */

ENTRY(__start)

MEMORY {
	flash : ORIGIN = 0x00000000, LENGTH = 0x20000
	ram   : ORIGIN = 0x00FFB000, LENGTH = 0x1000
}

SECTIONS {
	.text : {
		__stext = . ;
		*(.text)
		*(.rodata)
		*(.rodata.*)
		. = ALIGN(4) ;
		__etext = . ;
	} > flash

	.data : AT (ADDR(.text) + SIZEOF(.text)) {
		__sdata = . ;
		*(.data)
		. = ALIGN(4) ;
		__edata = . ;
	} > ram

	.bss : AT (ADDR(.text) + SIZEOF(.text) + SIZEOF(.data)) {
		__sbss = . ;
		*(.bss)
		*(COMMON)
		. = ALIGN(4) ;
		__ebss = . ;
	} > ram
}

