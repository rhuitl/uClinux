	.file	"initfini.c"
	
	.section .init
	.align 4
	.global _init
	.type	_init, %function
	.proc	020
	ret
	restore
	.size	_init, .-_init
	
	.section .fini
	.align 4
	.global _fini
	.type	_fini, %function
	.proc	020
	ret
	restore
	.size	_fini, .-_fini
