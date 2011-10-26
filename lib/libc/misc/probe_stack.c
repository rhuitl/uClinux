#ifdef __mcf5200__

/*
 * This attempts to determine the approximate stack size used by a process.
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/flat.h>

#define KEYVALUE 0xDEAD8008

/* This routine gets a pointer to the flat file header associated with
 * this executable.  We rely on the fact that there is no memory protection
 * and we also know the executable layout.
 */
static struct flat_hdr *
get_flat_hdr(void) {
	extern int _start;
	char *p = (char *)&_start;		/* Grab start of program */

//	p -= 4;					/* Move back past two nops */
	return ((struct flat_hdr *)p) - 1;	/* Return sturcture */
}

/* Determine the location of the stack base.  We just add the data segment
 * sizes from the header onto the current value of a5 which is our
 * data pointer.
 */
static void *
stack_bottom(struct flat_hdr *h) {
	unsigned long a5;
	unsigned long res;
	asm("move.l %%a5, %0": "=g" (a5));
	res = a5 + h->bss_end - h->data_start;
	return (void *)res;
}

/* This is the atexit routine that runs back through the allocated stack
 * and attempts to determine the lowest it ever came.
 */
static void
do_probe_stack(void) {
	struct flat_hdr *h;
	unsigned long end, top;
	unsigned long *sp;

	h = get_flat_hdr();
	sp = (unsigned long *) stack_bottom(h);
	end = (unsigned long)sp;
	sp++;
	while(*sp == KEYVALUE) sp++;
		
	top = end + h->stack_size;
	fprintf(stderr, "\n\nStack length used:  %d\nStack length alloc: %d\n",
			top - (unsigned long)sp, h->stack_size);
}

/* This is the main driver routine.  It fills the stack from the current position
 * downwards with a secret value.  It then installs an atexit handler to
 * seek out the lowest extent of the stack's growth.
 */
void
__probe_stack_size(void) {
	struct flat_hdr *h;
	unsigned long *sp;
	void *end;

	atexit(do_probe_stack);		/* Install probe handler */
	h = get_flat_hdr();		/* Point to the header */
	asm("move.l %%sp, %0": "=g" (sp));
	
	(unsigned long)sp &= ~0x3;	/* Round down to long boundary */
	sp--;				/* And skip one to be sure */
	
	end = stack_bottom(h);
	while ((void *)sp > end)
		*sp-- = KEYVALUE;
}

#endif
