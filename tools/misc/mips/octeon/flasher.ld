
ENTRY(__start)

MEMORY {
	ram : ORIGIN = 0x00000000, LENGTH = 0x00010000
}

SECTIONS {
	.text : {
		_stext = .;
		*(.text)
		*(.rodata)
		*(.rodata.*)
		*(.reginfo)
		. = ALIGN(0x10) ;
		_etext = .;
	} > ram

	.data : AT (ADDR(.text) + SIZEOF(.text)) {
		_sdata = . ;
		*(.data)
		. = ALIGN(0x10) ;
		_edata = . ;
	} > ram

	.bss : AT (ADDR(.data) + SIZEOF(.data)) {
		_sbss = . ;
		*(.bss)
		*(COMMON)
		. = ALIGN(0x10) ;
		_ebss = . ;
	} > ram

	/DISCARD/ : {
		*(.MIPS.options)
	}
}

