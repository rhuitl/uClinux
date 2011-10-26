/*
 * Setup some glibc defines so we can just drop in the
 * asm files from glibc without any modification.
 */

#include <features.h>
#include <bits/wordsize.h>

#if __WORDSIZE == 32
# define ENTRY_ALIGN 4
#else
# define ENTRY_ALIGN 2
#endif

#define ENTRY(sym) \
	.global sym; \
	.align  ENTRY_ALIGN; \
	.type   sym,%function; \
	sym:

#define BP_SYM(sym) sym

#define L(sym) LOC(sym)
#define LOC(sym) \
	.L ## sym

#define END(sym) \
	.size sym,.-sym;
