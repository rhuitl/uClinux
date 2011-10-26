/* strlen.S

 Copyright 2000-2004 John Coffman.
 All rights reserved.

 Licensed under the terms contained in the file 'COPYING' in the 
 source directory.

*/

;
; strlen:  find length of a string
;	enter with:
;		DS:BX = pointer to string
;
;	return with:
;		AX = length of string
;
strlen:
	mov	ax,bx
strlen1:
	test	byte (bx),#0xFF
	jz	strlen2
	inc	bx
	jmp	strlen1
strlen2:
	sub	bx,ax
	xchg	ax,bx
	ret

; end strlen.S
