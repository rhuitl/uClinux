;  mapper.S  -  LILO chain loader subroutine
;
; Copyright 2003-2004 John Coffman.
; All rights reserved.
;
; Licensed under the terms contained in the file 'COPYING' in the 
; source directory.
;
; Check for presence of existing drive mapper
;
;	Enter with  DS == CS,  SS == 0000	  (chain loader)
;	Enter with  DS == CS == ES,  SS != 0000   (second stage)
;
;	If a previous drive mapper exists, ES:DI points at the  drvmap
;		and ZF=0	(DI != 0)
;
;	If no recognizable drive map exists, DI == 0  and  ZF==1
;		ES is indeterminate
;
;
;
is_prev_mapper:
	push	cx
	push	si

#ifndef CHAIN_LOADER
	push	#0
	pop	es
	seg es
#else
	seg ss
#endif
	  les	di,[4*0x13]	; vector to int 0x13
	or	di,di
	jnz	is_p_no_mapper	; our mappers start at offset 0

	mov	di,es
	cmp	di,#0xA000	; start of system reserved locations
	jae	is_p_no_mapper
	cmp	di,#0x0060	; VERY conservative
	jb	is_p_no_mapper

; first test for new mapper
	xor	di,di
	mov	cx,#new13_length
	mov	si,#new13
	repe
	  cmpsb
	jne	is_p_try_old

; found new (v.22) mapper
	seg es
	  mov	di,[new13_drvmap_offset]
#if defined CHAIN_LOADER && defined DEBUG_NEW
	mov	si,#msg_new
	call	say
#endif
	jmp	is_prev_ret

is_p_try_old:
	xor	di,di
	mov	cx,#new13_old_length
	mov	si,#new13_old
	repe
	  cmpsb
	jne	is_p_no_mapper

; likely old (<=v.21) mapper
	seg es
	  mov	di,(di)	
	cmp	di,#new13_old_min_offs	; validate the range of values
	jb	is_p_no_mapper
	cmp	di,#new13_old_max_offs	; validate the range of values
#if defined CHAIN_LOADER && defined DEBUG_NEW
	ja	is_p_no_mapper
	mov	si,#msg_old
	call	say
	jmp	is_prev_ret
#else
	jbe	is_prev_ret
#endif

is_p_no_mapper:
	xor	di,di		; set DI = 0, ZF=1
is_prev_ret:
	or	di,di		; set ZF by DI
	pop	si
	pop	cx
	ret


/* LILO version 21 (and maybe earlier) drive map header signature code */
new13_old:
	push	ax		! save AX (contains function code in AH)
	push	bp		! need BP to mess with stack
	mov	bp,sp
	pushf			! push flags (to act like interrupt)
	push	si
	mov	si,#drvmap-new13

new13_old_drvmap_offs	=	* - new13_old - 2
new13_old_length	=	new13_old_drvmap_offs
new13_old_min_offs	=	0x46	; min seen in old code is 0x49
new13_old_max_offs	=	0x50	; maxed out at  21.7.5 at 0x4d

	.even			! this is very important

new13:	push	ax		! save AX (contains function code in AH)
	push	bp		! need BP to mess with stack
	mov	bp,sp
	jmp	new13a		! make space for signature

	.org	new13+6
	.ascii	"LILO"
	.word	STAGE_DRIVE_MAP
new13_length		=	*-new13		; max compare length
	.word	VERSION
new13_drvmap_offset	=	* - new13
	.word	drvmap-new13	! relative pointer to drive map
new13a:
#ifdef CHAIN_LOADER
	! Stack layout:
	!
	!   +8	INT flags
	!   +6	INT CS
	!   +4	INT IP
	!   +2	AX
	! BP+0 BP
	pushf			! push flags (to act like interrupt)
	push	si
	mov	si,#drvmap-new13
mapfl:	seg	cs		! get next entry
	 mov	ax,(si) 	! do not depend on DIRECTION flag
	lea	si,(si+2)	! **
	or	ax,ax		! at end ?
	jz	nomap		! yes -> do not map
	cmp	dl,al		! match ?
	jne	mapfl		! no -> continue
	mov	dl,ah		! map drive
nomap:	pop	si		! restore SI
	mov	8(bp),ax	! overwrite old flags (to remember mapping)
	mov	ax,2(bp)	! restore AX
	mov	bp,(bp)		! restore BP
old13of	=	*+1
old13sg	=	*+3
	callf	0,0

	push	bp		! save BP again
	mov	bp,sp
	! New stack layout:
	!
	!   +10	mapping (was flags)
	!   +8	INT CS
	!   +6	INT IP
	!   +4	AX
	!   +2  obsolete BP
	! BP+0  BP
	xchg	ax,4(bp)	! save AX and get command
	pushf			! fix driver number, if necessary
	cmp	ah,#8 ! do not fix
	je	done13
	cmp	ah,#0x15 ! do not fix
	je	done13
	mov	ax,10(bp)	! no mapping ?
	or	ax,ax
	jz	done13
	mov	dl,al		! fix mapping
done13:	mov	ax,4(bp)	! restore AX
	pop	10(bp)		! restore flags
	pop	bp		! get BP
	add	sp,#4		! fix SP
	iret			! done
	
	.even
drvmap:	.blkw	DRVMAP_SIZE+1

new13end:
#endif
#ifdef SECOND_STAGE_LOADER
drvmap:
#endif

/* end of mapper.S  */
