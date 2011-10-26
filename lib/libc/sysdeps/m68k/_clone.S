/* Adapted from glibc */
/* Copyright (C) 1996, 1997 Free Software Foundation, Inc. */

/* clone is even more special than fork as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <sysdep.h>
#include <linux/errno.h>

/* int _clone(int (*fn)(void *arg), void *child_stack, int flags, void *arg); */
 
        .text
ENTRY (_clone)

        /* Sanity check arguments.  */
        movel   #-EINVAL, %d0
        movel   4(%sp), %d1             /* no NULL function pointers */
	movel	%d1, %a0
        tstl    %d1
        jeq     syscall_error
        movel   8(%sp), %d1             /* no NULL stack pointers */
	movel	%d1, %a1
        tstl    %d1
        jeq     syscall_error

        /* Allocate space and copy the argument onto the new stack.  */
        movel   16(%sp), -(%a1)

        /* Do the system call */
#if defined (CONFIG_COLDFIRE)
        movel   %d2, %d1                /* save %d2 and get stack pointer */
        movel   %a1, %d2
        movel   %d1, %a1
#else
        exg     %d2, %a1                /* save %d2 and get stack pointer */
#endif
        movel   12(%sp), %d1            /* get flags */
        movel   #SYS_clone, %d0
        trap    #0
#if defined (CONFIG_COLDFIRE)
        movel   %d2, %d1                /* restore %d2 */
        movel   %a1, %d2
        movel   %d1, %a1
#else
        exg     %d2, %a1                /* restore %d2 */
#endif

        tstl    %d0
        jmi     syscall_error
        jeq     thread_start

        rts

syscall_error:
	negl	%d0
	movel	%d0, %sp@-
	lea   ERRNO_LOCATION-.-8, %a0
	jsr  0(%pc, %a0)
	movel	%d0, %a0
	movel	%sp@+, %a0@
	moveq	#-1, %d0

	rts

thread_start:
        /*subl    %fp, %fp*/        /* terminate the stack frame */
        jsr     (%a0)
        movel   %d0, -(%sp)
	movel	#SYS_exit, %d0
	trap	#0
        /*jsr    exit*/

