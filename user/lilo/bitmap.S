; bitmap.S
;
; Copyright 2001-2005 John Coffman.
; All rights reserved.
; 
; Licensed under the terms contained in the file 'COPYING' in the 
; source directory.
;
;
#define ncol KEYTABLE+256+mt_ncol


; menu_setup:
;   main setup menu for LILO boot selection process
;
;   replaces code to load & display the message in second.S
;
;   exit with DS=ES=CS
;
menu_setup:
	pusha

;;	BEG_FS
;;	SEG_FS			! message disabled ?
	cmp	word ptr par2_msg_len+SSDIFF,#0		;MSG_OFF+SSDIFF,#0
;;	END_FS
	je	ms_do_find	! yes -> skip this


;BEG_FS
;SEG_FS		! load the message file
	mov	cx,mt_msg+KEYTABLE+256			;MSG_OFF+SSDIFF+2
;SEG_FS
	mov	dx,mt_msg+2+KEYTABLE+256
;SEG_FS
	mov	al,mt_msg+4+KEYTABLE+256
;END_FS
	mov	bx,#MAP
	call	sread
	call	loadfile

	push	#SYSSEG
	pop	es
	xor	bx,bx
	push	es		; save for later
	push	bx

	call	_display4	; ES:BX points to the Message or BITMAP

	pop	bx

;;	BEG_FS
;;	SEG_FS
	xchg	bx,par2_msg_len+SSDIFF		;MSG_OFF+SSDIFF
;;	END_FS

	cmp	ax,#1
	jb	good_bitmap		; AX==0, bitmap was displayed

	pop	ds	
	ja	ms_do_find		; AX==2, 3, or 4; "BM" sig found, but
					; wrong bitmap or no VGA adapter
					; or no VESA support (4)

	; AX==1, no "BM" signature, assume "message"

	mov	byte ptr (bx),#0
	call	crlf
	xor	bx,bx		! display the message
	call	say
	jmp	ms_do_find
;--------------------------------------------

good_bitmap:
	pop	es
	inc	word [suppress]
	mov	word [abs_cx],#0x101	; mark screen in use	


ms_do_find:
	push	cs
	pop	ds		; make sure DS is good
	xor	si,si		; number of names
	xor	di,di		; max. name length
	mov	cx,#IMAGES	; get max number to search
	mov	bx,#DESCR0	; get address to start at
findl1:	call	strlen		; get length in ax
	or	ax,ax
	jz	findl3
#ifdef LCF_VIRTUAL
	test	word ptr (bx+id_flags),#FLAG_VMDEFAULT
	jz	findl1c
	call	vmtest
	jnc	findl1c
	mov	[vimage],si
findl1c:
#endif
#ifdef LCF_NOKEYBOARD
	test	word ptr (bx+id_flags),#FLAG_NOKBDEFAULT
	jz	findl1d
	call	kbtest
	jc	findl1d
	mov	[vimage],si
findl1d:
#endif
	cmp	ax,di
	jb	findl2
	xchg	ax,di
findl2:	add	bx,#id_size
	inc	si
	loop	findl1

findl3:	mov	[nimage],si
	mov	[limage],di
;;;
	mov	ax,si			; number of images
	mov	bx,[ncol]		; 
	add	ax,bx
	dec	ax
	div	bl
;MINROW = 4
	cmp	al,[KEYTABLE+256+mt_mincol]
	ja	row1
	mov	al,[KEYTABLE+256+mt_mincol]
row1:
	mov	bx,[KEYTABLE+256+mt_maxcol]	;
	cmp	al,bl
	jbe	row2
	xchg	ax,bx
row2:
	mov	[nrow],al
;;;
	xor	ax,ax			;display the list of names
	mov	cx,si
findl4:	call	lowlite
	inc	ax
	loop	findl4
	mov	ax,[dimage]		; bug fix
#if defined(LCF_VIRTUAL) || defined(LCF_NOKEYBOARD)
	test	byte ptr [cmdline],#0xFF
	jnz	vdone3
	mov	ax,[vimage]
vdone3:
#endif
	call	hilite

	push	cs
	pop	es			; make sure ES is good on exit

	popa
	ret
; end of menu_setup subroutine
#if DEBUG_NEW
no_bmp:	.ascii	" = AL; NOT a bitmap file\n"
	.byte	0
#endif


#if 0
; find_image
;	if there is something on the command line
;	return the image number it selects
;
;	enter with:
;		nothing
;	exit with:
;		If nothing selected:
;		    Carry Clear
;		    AX==0
;		If an image is selected:
;		    Carry SET
;		    AX==#image
;		    BX==pointer to descriptor
;		    
;
;	side effect:
;		The selected image is hi-lited if the menu is displayed
;
find_image:
	push	cx
	push	si
	push	di
	
	mov	cx,#IMAGES	! test all names
	mov	si,#DESCR0
	push	si
fi_nextn:
	mov	di,#cmdline
fi_nextc:
	mov	al,(si)		! get next character in descr
				! get the character
#ifdef LCF_IGNORECASE
	call	upcase
#endif
	mov	ah,al
	mov	al,(di)		! get next char in cmdline
#ifdef LCF_IGNORECASE
	call	upcase
#endif
	or	ah,ah		! NUL in descriptor name
	jz	fi_dscend
	cmp	al,ah		! character equal ?
	jne	fi_skipn		! no -> try next one
	inc	si		! test next character
	inc	di
	jmp	fi_nextc
fi_dscend:	
	cmp	al,#32		! space or NUL -> equal
	je	fi_found
	or	al,al
	jz	fi_found

fi_skipn:
	pop	si
	add	si,#id_size	! test next name
	push	si
	loop	fi_nextn

	pop	si
	xor	ax,ax		; clears the carry
fi_exit:
	pop	di
	pop	si
	pop	cx
	ret
	
fi_found:
	pop	bx		! BX is matched descriptor
	mov	ax,bx
	sub	ax,#DESCR0
	mov	cl,#id_size
	div	cl
	cbw
	mov	di,[dimage]
	cmp	ax,di
	je	fi_nochange
	mov	[dimage],ax
	cmp	byte [abs_cx+1],#0	! see if menu is displayed
	je	fi_nochange
	xchg	ax,di
	call	lowlite
	xchg	ax,di
	call	hilite
fi_nochange:
	stc
	jmp	fi_exit
#endif


; menu_delline:
;	delete the current command line
;  				common code from original second.S
;
;	enter with:
;		BX = command line pointer
;
;	exit with:
;		BX = updated command line pointer
;
;
menu_delline:
	cmp	bx,#cmdline	! done ?
	je	mdel9		! yes -> done
	push	bx		! display BS,SPC,BS
	mov	bx,#bs
	call	say
	pop	bx
	dec	bx		! move the pointer
	jmp	menu_delline		! next one
mdel9:	ret


; menu_setcmd:
;	set currently selected image to be the command line
;
;	enter with:
;		AX = image# to select
;		BX = cmdline pointer
;
;	exit with:
;		BX = updated
;
;
menu_setcmd:
	push	si

	push	ax

	call	menu_delline	; delete the current line

	pop	si		; get image# back

	imul	si,#id_size
	add	si,#DESCR0
mset1:	lodsb
	or	al,al
	jz	mset6
	mov	(bx),al
	inc	bx
	push	bx
	call	display
	pop	bx
	jmp	mset1
	
mset6:
	pop	si	
	ret


; arrow
;
;   Code that handles the arrow keys:  left, up, down, right
;
;
arrow:	cbw			; signed delta vector in AL
	mov	dx,[dimage]	;
	add	dx,ax		; new position
	or	dx,dx
	jns	arr1
arr0:	xor	dx,dx		; set to zero if neg.
arr1:	mov	ax,[nimage]
	cmp	dx,ax		; compare to max.
	jb	arr2
	mov	dx,ax
	dec	dx
arr2:			; we know the one to hi-lite is in range
	mov	ax,[dimage]
	cmp	ax,dx
	je	arr6

	call	lowlite		; un-hilite the old
	xchg	ax,dx
	call	hilite

	call	menu_setcmd	; set new command line
arr6:
	jmp	arr_vector

	
null:	mov	al,#1
	cmp	ah,#0x50		; down arrow
	je	arrow

	neg	al
	cmp	ah,#0x48		; up arrow
	je	arrow

	mov	dx,[nimage]
	cmp	ah,#0x4f		; end
	je	arr1

	cmp	ah,#0x47		; home
	je	arr0

	mov	al,[nrow]
	xchg	ax,dx
	mov	ax,[dimage]
	div	dl			
	xchg	ax,dx			; DL = cur col.

	cmp	ah,#0x4d		; right arrow
	jne	arr8
	inc	dx			; similar to  dec al
	cmp	dl,[ncol]		; cmp (CUR COL + 1) : (NCOL)
	jb	arrow
	jmp	arr9
	
arr8:
	cmp	ah,#0x49		; pg up
	jne	arr84
	neg	dh			; remainder [0..(nrow-1)]
	mov	al,dh
arrow1:	jmp	arrow

arr84:
	cmp	ah,#0x51		; pg dn
	jne	arr88
	not	dh
	add	al,dh
	jmp	arrow

arr88:
	neg	al
	cmp	ah,#0x4b		; left arrow
	jne	arr9
	or	dl,dl
	jnz	arrow1

arr9:
	cmp	ah,#0x53		; DEL
	jne	arr_vector
	br	delch			; treat as 0177 (rubout)

arr_vector:
	br	input		; ignore the rest

; menu_exit:
;	erase the menu box to black
;
menu_exit:
	push	es
	pusha
#if DEBUG_NEW
	call	me1
	.ascii	"menu_exit entered"
	.byte	10,0
me1:	pop	bx
	call	say
;;	call	pause
#endif
	xor	ax,ax
	cmp	word [abs_cx],ax
	mov	word [suppress],ax
	mov	word [abs_cx],ax
	je	mn_exit_ret
	call	_done4
#if DEBUG_NEW
	call	me2
	.ascii	"called done4"
	.byte	10,0
me2:	pop	bx
	call	say
;;	call	pause
#endif
mn_exit_ret:
#if DEBUG_NEW
	call	me3
	.ascii	"exit from menu_exit"
	.byte	10,0
me3:	pop	bx
	call	say
;;	call	pause
#endif
	popa
	pop	es
	ret

#if 0
; menu_form_feed:
;	simulate a FF on the console
;
menu_form_feed:
	ret
#endif

; timer_display:
;	check the timer 'cntdown' and display changes
;
timer_display:
	push	es
	pusha

	test	byte [KEYTABLE+256+mt_t_row+1],#0xff	; see if not initialized
	js	timer99

	mov	dx,#0x2d2d	; get "--" means disabled
	mov	[tim_min],dx
	mov	[tim_sec],dx
	mov	ax,[cntdown]	; get timer countdown location
	cmp	ax,[tim_tick]
	je	timer99
	mov	[tim_tick],ax	; save last tick count	
	inc	ax
	jz	timer8

	mul	c55		; get time remaining in ms.
	div	c1000		; convert to seconds
	cmp	ax,[tim_old]	
	je	timer99
	mov	[tim_old],ax	; save seconds remaining
	xor	dx,dx
	div	c60		; minutes in AX, seconds in DX	
	aam
	add	ax,#0x3030
	xchg	ah,al
	mov	[tim_min],ax	; put characters in buffer
	xchg	ax,dx
	aam
	add	ax,#0x3030
	xchg	ah,al
	mov	[tim_sec],ax	; put characters in buffer

timer8:
	push	ds		;sch-hi
	push	#KEYTABLE+256+mt_t_fg
	push	#5		; len
	push	ds		; cp -hi
	push	#tim_min
	push	word [KEYTABLE+256+mt_t_row]
	push	word [KEYTABLE+256+mt_t_col]
	call	_text
	add	sp,#14
timer99:
	popa
	pop	es
	ret

tim_min: db	0,0
	.ascii	":"
tim_sec: db	0,0

tim_old:  dw	0		; last # seconds
tim_tick: dw	0		; last timer tick value examined

c55:	.word	2197		;was 55, now 54.925*40
c1000:	.word	40000		;was 1000, now 40*1000
c60:	.word	60



; hilite/lowlite
;	enter with:
;		AX = number [0..(nimage-1)] of entry to hilite
;
hilite:
	push	es
	pusha
	mov	[dimage],ax		;remember one hilited
	push	cs
	push	#KEYTABLE+256+mt_h_fg
	jmp	lowlite1

lowlite:
	push	es
  	pusha
	push	cs			; sch hi
	push	#KEYTABLE+256+mt_fg	; sch low

lowlite1:
	cmp	BYTE [abs_cx+1],#0
	je	lowlite9

	mov	bx,ax		;save argument in BX
	mov	al,#0x20	; SP
	mov	cx,[limage]
	inc	cx
	inc	cx
	mov	di,#im_name
	push	cx			; len
	push	ds			; cp hi
	push	di			; cp low

	push	ds
	pop	es
	rep
	  stosb
	imul	si,bx,#id_size
	add	si,#DESCR0
	mov	di,#im_name+1
lowlite2:
	lodsb
	or	al,al
	jz	lowlite3
	stosb
	jmp	lowlite2
lowlite3:

	mov	cx,[KEYTABLE+256+mt_col]
	mov	ax,[KEYTABLE+256+mt_row]
	mov	si,[nrow]
lowlite4:
	cmp	bx,si
	jb	lowlite5
	add	cx,[KEYTABLE+256+mt_xpitch]
	sub	bx,si
	jmp	lowlite4
lowlite5:
#ifdef PIXADDRESS
	shl	bx,#4		;use pixel addressing
#endif
	add	ax,bx
	push	ax
	push	cx
	call	_text
	add	sp,#10
lowlite9:
	add	sp,#4
	popa
	pop	es
	ret


im_name:  .blkb	MAX_IMAGE_NAME+3

	.even
dimage:	dw	0	; default image
#if defined(LCF_VIRTUAL) || defined(LCF_NOKEYBOARD)
vimage:	dw	0	; vmdefault image
#endif
nimage:	dw	0	; number of images
limage:	dw	0	; longest length of image name
nrow:	dw	0	; number of rows of selections
;nrow	equ	KEYTABLE+256+mt_maxcol
;ncol:	dw	0	; number of columns (default=2)
;ncol	equ	KEYTABLE+256+mt_ncol
abs_cx:	dw	0	; upper left of scrolling area

; end of bitmap.S
