	.file	"initfini.c"
	.version	"01.01"
gcc2_compiled.:
__gnu_compiled_c:

	.section .init
	.align 1
.globl _init
	.type	 _init,@function
	ret
.Lfe2:
	.size	 _init,.Lfe2-_init

	.section .fini
	.align 1
.globl _fini
	.type	 _fini,@function
	ret
.Lfe3:
	.size	 _fini,.Lfe3-_fini
	.ident	"GCC: (GNU) 2.95.2 19991024 (release) (Linux/VAX CVS)"
