# This file contains stuff that goes at the end of the .init and .fini
# sections.  The idea is that the linker simply strings together the init
# sections from the various input files, and this end up at the end.

	.section .init
	rts

	.section .fini
	rts
