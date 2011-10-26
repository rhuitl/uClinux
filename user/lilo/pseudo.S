; pseudo.S -- produce a pseudo kernel header
;
;	This file is useful for booting arbitrary binary images
;	at	0x1000:0000
;
; Copyright 2002-2005 John Coffman.
; All rights reserved.
; 
; Licensed under the terms contained in the file 'COPYING' in the 
; source directory.
;

#define DEBUG 0
#define DELL_DIRTY_HACK


SYSSEG	=  0x1000	; DEF_SYSSEG
SETUPSEG = 0x9020	; DEF_SETUPSEG

CL_MAGIC_ADDR	= 0x20			! command line magic number
CL_MAGIC	= 0xa33f		! very unusual command sequence
CL_OFFSET	= 0x22			! command line offset
CL_LENGTH	= 256			! maximum length

		.text
#if 0
.globl	_main
_main:
#endif
		.globl	zero
zero:

; we want this to look like a bootable kernel image
; so we include the following header
;
		jmp	begin
		.ascii	"HdrS"		; looks like a real kernel
		.word	0x0200		; header format version number
		.word	0,0		; realmode switch, SETUPSEG
		.word	SYSSEG		; SYSSEG -- load at 1000:0000
		.word	id_string
		.byte	0		; type of loader
		.byte	0		; flags 0=load low
		.word	2*512		; move size: 2 sectors
		dd	0x10000		; load us here
		dd	0		; ramdisk image
		dd	0		; ramdisk size
		.word	bs_helper,SETUPSEG	; kludge???
;;		.word	modelist+1024	; heap end pointer
;----------end of header------------
		
begin:
	xor	di,di
	cmp	word ptr [CL_MAGIC_ADDR],#CL_MAGIC
	jne	gotoit
	mov	di,[CL_OFFSET]
gotoit:
	jmpi	0000,SYSSEG			; jmp to 0x1000:0000


bs_helper:      int     0x19			;label here for kludge


id_string:	.ascii	"pseudo.b"
		.byte	0

		.blkb	zero+512-*

modelist:

theend:
