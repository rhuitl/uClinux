
#include <sysdep.h>

@ r0 = argc
@ r1 = argv
@ r2 = envp
@ sl = data segment

	.data
	.align 2
	.global	environ,errno

environ:  .long 0
errno:    .long 0

	.text
	.align 2
	.global start,_start,__syscall_error
	.type start,%function
	.type __syscall_error,%function

start:
_start:
#ifdef __PIC__
	ldr	r2, .L3
	ldr r3, [sl,r2]
#else
	ldr	r3, .L3
#endif

	ldr r0,[sp, #0]
	ldr r1,[sp, #4]
	ldr r2,[sp, #8]
	str r2,[r3, #0]
#ifdef __PIC__
	bl  main(PLT)
#else
	bl  main
#endif
	ldr r0,=0
#ifdef __PIC__
	bl  exit(PLT)
#else
	bl  exit
#endif

.L3:
#ifdef __PIC__
	.word environ(GOT)
#else
	.word environ
#endif

__syscall_error:
#ifdef __PIC__
	ldr  r1, .L4	  @ load the address of errno
	ldr  r3, [sl,r1]
#else
	ldr  r3, .L4	  @ load the address of errno
#endif
	rsb  r2, r0, $0
	str  r2, [r3]
	mvn  r0, $0       @ return -1
	ret

.L4:
#ifdef __PIC__
	.word errno(GOT)
#else
	.word errno
#endif

