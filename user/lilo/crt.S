#if 0
; crt.S  is
Copyright 2000-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

#endif
;

XPITCH  =	MAX_IMAGE_NAME+6
MINROW	=	4
MAX2COL	=	14
MAXTITLE  =	3
MAXCOMMENT  =	3


; menu_setup:
;   main setup menu for LILO boot selection process
;
menu_setup:
	pusha
	call	mn_getcursor
	push	dx		; save cursor position
	call	mn_init
	mov	dx,cx

	cmp	byte [abs_cx+1],#0
	jne	findl0		; skip clearing screen on second time thru
; clear the screen
	xor	cx,cx
	mov	bh,[mn_at_mono]
	mov	al,#0
	call	mn_drawbox

findl0:
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
	mov	bx,#str_title	;
	call	strlen
	mov	bl,[mn_max_row_col]
	sub	bl,al
	shr	bl,#1

	push	bx

	mov	ax,si
	mov	bl,#2		;set for 2 columns
	cmp	al,#MAX2COL
	jle	col1
	inc	bl
col1:	mov	[ncol],bl
	add	al,bl
	dec	al
	div	bl
	cmp	al,#MINROW
	jg	row1
	mov	al,#MINROW
row1:	cbw
	mov	[nrow],ax
;;;	add	ax,#4+4+1
	add	ax,#MAXTITLE+1 +MAXCOMMENT+1 +1
	mov	dh,al		; 
	mov	al,#XPITCH		; standard width
	mul	bl
	mov	dl,al
	mov	cl,[mn_max_row_col]
	sub	cl,dl
	shr	cl,#1
	mov	ch,#1
	mov	al,#0x83
	mov	bh,[mn_at_text]
	call	mn_drawbox
        mov     [area_cx],cx
        mov     [area_dx],dx
	push	dx
	add	dx,cx		; absolute location
	sub	dx,#0x0306
	mov	[timer_dx],dx	; save location of timer
	pop	dx
	add	ch,#2		; title height

	mov	bp,sp
	xchg	dx,(bp)

	mov	dh,ch
	mov	bx,#str_title
	mov	al,[mn_at_title]
	call	mn_wrstra

	pop	dx

	add	ch,#2
	mov	al,#1
	call	mn_hline

	push	cx

	inc	ch
	add	ch,[nrow]
	mov	al,#1
	call	mn_hline
	mov	dx,cx

	push	dx

	add	dx,#0x102
	mov	al,[mn_at_text]
	mov	bx,#str_com1
	test	byte ptr par2_flag2,#FLAG2_UNATTENDED
	jz	mn_attended
	mov	bx,#str_com1u	; unattended
mn_attended:
	call	mn_wrstra
	inc	dh
	mov	bx,#str_com2
	call	mn_wrstra
	inc	dh
	mov	bx,#str_com3
	call	mn_wrstra
	mov	dx,[timer_dx]
	mov	bx,#str_timer
	call	mn_wrstra

	pop	dx
	pop	cx

	sub	dh,ch
	mov	ah,[ncol]
	mov	si,#DESCR0	; get start pointer
	mov	di,[nimage]
	mov	[norigin],cx
vlines:
	add	cl,#3
	mov	al,#1
	call	mn_vline

	push	cx
	push	dx

	mov	dx,cx
	add	dx,#0x102
	mov	cx,[nrow]
	cmp	cx,di
	jb	vl1
	mov	cx,di
vl1:	jcxz	vl3
vl2:	mov	bx,si
	mov	al,[mn_at_text]
	call	mn_wrstra

	push	ax
	push	dx
	sub	dl,#4
	mov	ah,al
	test	word [id_flags](si),#FLAG_TOOBIG	; test for unbootable
	mov	al,#0x55		; 'U' for possibly unbootable
	jnz	vl20
	mov	al,#0x46		; 'F' for fallback
	test	byte [id_flags](si),#FLAG_FALLBACK
	jnz	vl20
	mov	al,#0x4C		; 'L' for lock
	test	byte [id_flags](si),#FLAG_LOCK
#ifdef LCF_VIRTUAL
	jnz	vl20
	mov	al,#0x57		; 'W' for vmWarn
	test	word [id_flags](si),#FLAG_VMWARN
#endif
	jz	vl21
vl20:	call	mn_wrcha
vl21:	
	inc	dl
	test	byte [id_flags](si),#FLAG_PASSWORD	; test for password
	jz	vl23
	mov	al,#0x50		; 'P' for password
	test	byte [id_flags](si),#FLAG_RESTR
	jz	vl22
	mov	al,#0x52		; 'R' for restricted options
vl22:	call	mn_wrcha
vl23:	pop	dx
	pop	ax

	inc	dh
	dec	di
	add	si,#id_size
	loop	vl2
vl3:
	pop	dx
	pop	cx

	add	cl,#XPITCH-3
	dec	ah
	jz	vdone
	mov	al,#2
	call	mn_vline
	jmp	vlines
vdone:
	mov	ax,[dimage]		; usually zero
#if defined(LCF_VIRTUAL) || defined(LCF_NOKEYBOARD)
	test	byte ptr [cmdline],#0xFF
	jnz	vdone3
	mov	ax,[vimage]
vdone3:
#endif
	call	hilite

	pop	dx			; get saved cursor position
	cmp	byte [abs_cx+1],#0
	jne	nohome

	mov	dx,[area_cx]
	add	dx,[area_dx]
	xor	dl,dl
	add	dh,#2
	mov	[abs_cx],dx		; set home cursor position
nohome:	
	call	mn_setcursor

	popa
	ret
; end of menu_setup subroutine

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
	pusha
	mov	cx,[area_cx]
	mov	dx,[area_dx]
	mov	al,#0x80
	mov	bh,[mn_at_mono]
	call	mn_drawbox
	popa
	ret

; menu_form_feed:
;	simulate a FF on the console
;
menu_form_feed:
	pusha
;;	push	ds
;;	push	cs
;;	pop	ds
	mov	cx,[abs_cx]	! get home position
	mov	dx,[mn_max_row_col]
	xor	al,al
	mov	bh,#0x07
	call	mn_drawbox
	mov	dx,cx
	call	mn_setcursor
;;	pop	ds
	popa
	ret

; timer_display:
;	check the timer 'cntdown' and display changes
;
timer_display:
	pusha

	cmp	word [timer_dx],#0	; see if not initialized
	jz	timer99

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
	call	mn_getcursor
	push	dx
	mov	dx,[timer_dx]
	mov	ah,[mn_at_text]
	mov	si,#tim_min
	mov	bx,#tim_old
	mov	cx,#5
timer91:
	lodsb
	cmp	al,(bx)
	je	timer92
	call	mn_wrcha
	mov	(bx),al
timer92:
	inc	bx
	inc	dl
	loop	timer91
	pop	dx
	call	mn_setcursor
timer99:
	popa
	ret

tim_min: db	0,0
	.ascii	":"
tim_sec: db	0,0

tim_old: .ascii	"*****"
tim_tick: dw	0		; last timer tick value examined

c55:	.word	2197		;was 55, now 54.925*40
c1000:	.word	40000		;was 1000, now 40*1000
c60:	.word	60


; hilite/lowlite
;	enter with:
;		AX = number [0..(nimage-1)] of entry to hilite
;
hilite:	push	bx
	mov	[dimage],ax		; remember the latest
	mov	bh,[mn_at_hilite]
	jmp	lowlite1

lowlite:  push	bx
	mov	bh,[mn_at_text]
lowlite1:
	push	cx
	push	dx
	push	ax

	call	mn_getcursor
	push	dx			;save current cursor position

	mov	dx,[norigin]
	add	dx,#0x104
	mov	cx,[limage]
	inc	cx
	inc	cx

	push	bx
	mov	bx,[nrow]
ll1:	cmp	ax,bx
	jb	ll2
	add	dl,#XPITCH		; index by column
	sub	ax,bx
	jmp	ll1
ll2:	add	dh,al
	pop	bx		; restore attribute in BH

ll3:	call	mn_rdcha	; read char and attribute
	mov	ah,bh
	call	mn_wrcha	; write back with new attribute
	inc	dl
	loop	ll3

	pop	dx		; restore cursor
	call	mn_setcursor

	pop	ax
	pop	dx
	pop	cx
	pop	bx
	ret


; title_stuff
;
;
title_stuff:
	cmp	dword (bx),#0x554e454d	; "MENU"
	jne	noschema
	mov	edx,(bx+4)
	mov	[mn_attrib],edx
noschema:
	add	bx,#9		; point at possible title
	mov	al,(bx-1)	; get length stored by installer
	or	al,al
	jz	notitle		; no title if supplied length is 0
	cbw
	xchg	ax,cx		; supplied length to CX
	call	strlen
	cmp	ax,cx
	jne	notitle
	cmp	ax,#str_title_len
	jae	notitle
	push	di
	mov	di,#str_title	;
titlemov:
	mov	al,(bx)
	inc	bx
	seg ds
	  stosb
	or	al,al
	jnz	titlemov

	pop	di
notitle:
	ret


dimage:	dw	0	; default image
#if defined(LCF_VIRTUAL) || defined(LCF_NOKEYBOARD)
vimage:	dw	0	; vmdefault image
#endif
norigin: dw	0	; row/col origin of names on screen
nimage:	dw	0	; number of images
limage:	dw	0	; longest length of image name
nrow:	dw	0	; number of rows of selections
ncol:	dw	0	; number of columns (default=2)
;wcol:	db	0	; width of each column (default=XPITCH=21)
area_cx:  dw    0       ; area of interaction
area_dx:  dw    0       ; area of interaction
abs_cx:	dw	0	; upper left of scrolling area
;abs_dx:	dw	0	; lower right of scrolling area
;       mn_max_row_col is the same as the above (abs_dx)
timer_dx: dw	0	; timer location


str_title:
	.ascii	"LILO"
#ifdef LCF_VERSION
	.ascii	" "	
	.ascii	S(VERSION_MAJOR)
	.ascii	"."
	.ascii	S(VERSION_MINOR)
	.ascii	VERSION_EDIT
#endif
	.ascii	"  Boot Menu"
	.byte	0
	.org	str_title+MAX_MENU_TITLE+1

str_timer:
	.ascii	"--:--"
	db	0

str_title_len	= str_timer-str_title-1

str_com1:
	.ascii	"Hit any key to cancel timeout"
;		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX 00:00"
	db	0
str_com1u:
	.ascii	"Hit any key to restart timeout"
	db	0

str_com2:
	.ascii	"Use "
	db	27		; left-arrow
	db	24,25		; up-arrow, down-arrow
	db	26		; right-arrow
	.ascii	" arrow keys to make selection"
	db	0
str_com3:
	.ascii	"Enter choice & options, hit CR to boot"
	db	0

; end of crt.S
