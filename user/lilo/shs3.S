; shs3.S
/*
Copyright 2000-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/
;
;;;	group   dgroup _data

;;;	segment _data public align=16 class=data

;		global  _shsInfo
#ifdef BSS_DATA
#if 0
		.align	4
_shsInfo:
shs_digest:	.blkb	5*4
shs_count:	.blkb	2*4

Wshs:	      .blkb	16*4
#else
_shsInfo	=	*
shs_digest	=	*
		.org	*+5*4
shs_count	=	*
		.org	*+2*4

Wshs		=	*
		.org	*+16*4
#endif
#else

;;;	segment _text public align=16 class=code

#define Ashs eax
#define Bshs esi
#define Cshs ecx
#define Dshs edx
#define Eshs edi
#define temp_shs ebp

shsTransform:
	push    bp
	push	di
	push	si

	mov     di,#shs_digest    ;##
	mov	Ashs,dword (di)
	mov	Bshs,dword (di+4)
	mov	Cshs,dword (di+8)
	mov	Dshs,dword (di+12)
	mov	Eshs,dword (di+16)
	sub     bx,bx		   ; count = 0

;	align   4	       ;align
shs_F356:
	mov	temp_shs,Bshs
	and	temp_shs,Cshs
	push    Bshs
	not	Bshs
	and	Bshs,Dshs
	or	temp_shs,Bshs
	pop     Bshs
	add	temp_shs,#0x5a827999	;##

	call    shsTransCommon
	
	cmp	bx,#20*4		;##
	jb	shs_F356

;	align   4	       ;align
shs_F359:
	mov	temp_shs,Dshs
	xor	temp_shs,Cshs
	xor	temp_shs,Bshs
	add	temp_shs,#0x6ed9eba1

	call    shsTransCommon

	cmp	bx,#40*4
	jb	shs_F359

;	align   4	       ;align
shs_F362:
	mov	temp_shs,Cshs
	and	temp_shs,Bshs
	push    Cshs
	or	Cshs,Bshs
	and	Cshs,Dshs
	or	temp_shs,Cshs
	pop     Cshs
	sub	temp_shs,#0x70e44324

	call    shsTransCommon
	
	cmp	bx,#60*4
	jb	shs_F362

;	align   4	       ;align
shs_F365:
	mov	temp_shs,Dshs
	xor	temp_shs,Cshs
	xor	temp_shs,Bshs
	sub	temp_shs,#0x359d3e2a

	call    shsTransCommon

	cmp	bx,#80*4
	jb	shs_F365

	mov     bx,#shs_digest   ;##
	add	dword (bx),Ashs
	add	dword (bx+4),Bshs
	add	dword (bx+8),Cshs
	add	dword (bx+12),Dshs
	add	dword (bx+16),Eshs

	pop	si
	pop	di
	pop     bp
	ret	

;	align   4
shsTransCommon:
	add	temp_shs,Eshs
	mov     Eshs,Dshs
	mov     Dshs,Cshs
	ror     Bshs,2
	mov     Cshs,Bshs
	mov     Bshs,Ashs
	rol     Ashs,5
	add     temp_shs,Ashs
	cmp     bx,#16*4
	jae     shsJ1
	mov     Ashs,dword Wshs(bx)
	jmp     shsJ2
shsJ1:
	push    bx
	add     bx,#13*4
	and     bx,#15*4
	mov     Ashs,dword Wshs(bx)
	sub     bx,#5*4
	and     bx,#15*4
	xor     Ashs,dword Wshs(bx)
	sub     bx,#6*4
	and     bx,#15*4
	xor     Ashs,dword Wshs(bx)
	sub     bx,#2*4
	and     bx,#15*4
	xor     Ashs,dword Wshs(bx)
	rol     Ashs,1
	mov     dword Wshs(bx),Ashs
	pop     bx
shsJ2:
	add     Ashs,temp_shs
	add	bx,#4
	ret

;	align   4
byteReverse:
	push    di
	mov	cx,#16	   ;##
	mov     di,#Wshs	    ;##

;	align   4	       ;align
shs_F376:
	mov     eax,dword (di)
;;;	bswap   eax
	xchg    ah,al
	rol     eax,16
	xchg    ah,al

	stosd
	loop    shs_F376

	pop     di
	ret

 


;	align   4

;	global	_shsInit, _shsUpdate, _shsFinal
_shsInit:
	push    bp
	mov     bp,sp
;	push    ds
	push    di

	mov     di,#shs_digest			;##
	mov	dword (di),#0x67452301		;##
	mov	dword (di+4),#0xefcdab89
	mov	dword (di+8),#0x98badcfe
	mov	dword (di+12),#0x10325476
	mov	dword (di+16),#0xc3d2e1f0	;##
	sub	eax,eax
	mov     dword (di+20),eax
	mov     dword (di+24),eax

	pop     di
;	pop     ds
	leave
	ret


;	align   4

_shsUpdate:
	push    bp
	mov     bp,sp

;       buffer  [bp+4]
;       count   [bp+6]

	push    si
	push    di
;	push    ds

	push    ds
	pop     es

;   remain = shsInfo.countLo & (SHS_BLOCKSIZE-1);
	mov     di,[shs_count]
	and     di,#63	   ;##

	movzx   eax,word (bp+6)      ;count
	add     [shs_count],eax
	adc     dword [shs_count+4],#0 ;##

	mov     si,(bp+4)       ;buffer

shs_J4:
	mov     cx,#64	   ;##
	sub     cx,di	   ;CX = SHS_BLOCKSIZE-remain
	cmp     ax,cx	   ; count >= SHS_BLOCKSIZE-remain
	jb      shs_J6

	add     di,#Wshs	    ;##
	sub     ax,cx	   ; count -= SHS_BLOCKSIZE-remain
	push    ax
	rep
#ifdef SHS_PASSWORDS
	  seg ss
#endif
	     movsb	   ;memcpy

	call    byteReverse
	call    shsTransform

	pop     ax
	sub     di,di	   ;remain
	jmp     shs_J4
shs_J6:
	add     di,#Wshs	    ;##
	mov     cx,ax
	rep
#ifdef SHS_PASSWORDS
	  seg ss
#endif
	     movsb

;	pop     ds
	pop     di
	pop     si
	leave
	ret

;	align   4
_shsFinal:
	push    bp
	mov     bp,sp
	push    si
	push    di
;	push    ds

	push    ds
	pop     es

	mov     di,[shs_count]
	and     di,#63	   ;##
	mov     byte Wshs(di),#0x80	;##
	inc     di
	sub     ax,ax
	cmp     di,#56	   ;##
	jbe     shs_J10
; count > 56
	mov     cx,#64
	sub     cx,di	   ;SHS_BLOCKSIZE - count
	add     di,#Wshs	    ;##
	rep
	     stosb

	call    byteReverse
	call    shsTransform

	mov     cx,#56			 ;##
	mov     di,#Wshs		    ;##
	sub     ax,ax
	jmp     shs_J11
shs_J10:
	mov     cx,#56	   ;##
	sub     cx,di
	add     di,#Wshs	    ;##
shs_J11:
	rep
	     stosb
	call    byteReverse
	mov     eax,[shs_count]
	mov     ebx,[shs_count+4]
	shld    ebx,eax,3
	shl     eax,3
	mov     [Wshs+14*4],ebx
	mov     [Wshs+15*4],eax
	call    shsTransform

;	pop     ds
	pop     di
	pop     si
	leave
	ret

#undef Ashs
#undef Bshs
#undef Cshs
#undef Dshs
#undef Eshs
#undef temp_shs

#endif	/* BSS_DATA */

; end shs3.S

