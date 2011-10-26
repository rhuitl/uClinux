/* dump.S  -  LILO register dumper */

 Copyright 1995-1997 Werner Almesberger.
 All rights reserved.

 Licensed under the terms contained in the file 'COPYING' in the 
 source directory.

*/


#define LILO_ASM
#include "lilo.h"


	.text

	.globl	_main
	.org	0

_main:	push	sp	! push all registers
	push	ss
	pushf
	push	es
	push	ds
	push	cs
	push	bp
	push	di
	push	si
	push	dx
	push	cx
	push	bx
	push	ax
	mov	ax,#BOOTSEG	! let DS point to where we really are
	mov	ds,ax
	mov	bx,#msgs	! set up loop
l:	call	say		! output message
	cmp	byte ptr (bx),#0 ! at end ?
	je	back		! yes -> back to LILO
	pop	ax		! get next data word
	push	bx
	call	wout		! output data word
	pop	bx
	jmp	l		! next round

#if 0
back:	mov	ax,#FIRSTSEG
	mov	ds,ax
	mov	word ptr (CODE_START_1),#CODE_START_1+8
	mov	word ptr (CODE_START_1+2),#FIRSTSEG
	mov	word ptr (CODE_START_1+4),#CODE_START_1+12
	mov	byte ptr (CODE_START_1+6),#0xfe
	mov	es,ax		! adjust segments
	mov	ax,#BOOTSEG
	mov	ds,ax
	mov	word ptr (10),#0xffff ! no timeout
	mov	si,#haltnow	! copy string data
	mov	di,#CODE_START_1+8
	mov	cx,#6
	rep
	movsb
	mov	ax,#FIRSTSEG	! restart LILO
	jmpi	#GO,FIRSTSEG
#else
back:	hlt			! stay here
	jmp	back
#endif

! Display a NUL-terminated string on the console

say:	mov	al,(bx)		! get byte
	inc	bx		! move pointer
	or	al,al		! NUL ?
	jz	aret		! yes -> done
	push	bx		! save pointer
	mov	ah,#14		! display, tty-style
	xor	bh,bh
	int	0x10
	pop	bx
	jmp	say		! next one

wout:	push	ax		! display one word
	mov	al,ah
	call	bout
	pop	ax
bout:	push	ax		! display one byte
	shr	al,#4
	call	nout
	pop	ax
nout:	and	al,#15		! display one nibble
	add	al,#48
	cmp	al,#58
	jb	nokay
	add	al,#7
nokay:	xor	bh,bh		! display on screen
	mov	ah,#14
	int	0x10
aret:	ret
 
msgs:	.byte	13,10
	.ascii	"Register dump:"
	.byte	13,10,10
	.ascii	"AX="
	.byte	0
	.ascii	" BX="
	.byte	0
	.ascii	" CX="
	.byte	0
	.ascii	" DX="
	.byte	0,13,10
	.ascii	"SI="
	.byte	0
	.ascii	" DI="
	.byte	0
	.ascii	" BP="
	.byte	0,13,10
	.ascii	"CS="
	.byte	0
	.ascii	" DS="
	.byte	0
	.ascii	" ES="
	.byte	0,13,10
	.ascii	"F="
	.byte	0,13,10
	.ascii	"SS:SP="
	.byte	0
	.ascii	":"
	.byte	0,13,10,10
#if 0
	.ascii	"Restarting LILO ..."
#else
	.ascii	"System halted."
#endif
	.byte	13,10,10,0,0

haltnow:.ascii	"LILO"			! prevent automatic reboot
	.byte	0
