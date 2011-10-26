
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
	.type __sycall_error,%function

start:
_start:
    @ adjust the data sgement base pointer
	ldr r3,=__data_start
	sub sl,sl,r3

	ldr	r3, .L3
	str r2,[sl,r3]
	bl  main
	ldr r0,=0
	bl  exit

.L3:  .word environ

__syscall_error:
	ldr  r3, .L4	  @ load the address of errno
	rsb  r2, r0, $0	
	str	 r2, [sl,r3]  @ errno = -result
	mvn  r0, $0       @ return -1
	ret

.L4:  .word errno
