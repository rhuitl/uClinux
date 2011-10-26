#ifdef __ELF__
#define ____sig_restore ___sig_restore
#define ____masksig_restore ___masksig_restore
#define ___sigsetmask __sigsetmask
#endif

.globl ____sig_restore
.globl ____masksig_restore

____sig_restore:
	addql #4,%sp    | signr
	rts
#ifdef __ELF__
	.type	___sig_restore,@function
	.size	___sig_restore,.-___sig_restore
#endif

____masksig_restore:
	addql #4,%sp	       | signr
#if defined(__PIC__) || defined(__pic__)
	bsrl ___sigsetmask@PLTPC | old blocking
#else
	jbsr   ___sigsetmask   | old blocking
#endif
	addql #4,%sp
	rts
#ifdef __ELF__
	.type	___masksig_restore,@function
	.size	___masksig_restore,.-___masksig_restore
#endif
