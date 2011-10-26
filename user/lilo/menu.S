#if 0
; menu.S  is
Copyright 2000-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

#endif
#define PAGE0
;
; mn_init:
;	enter with nothing
;
;	return with:
;		AH = #columns
;		AL = video mode
;		BH = active page
;		CH = rows-1
;		CL = cols-1
;
;	side effects:
;		If video mode 7 (MDA) is detected, the default attributes
;		are modified to those suitable for monochrome
;
mn_init:
	mov	ah,#0x0f
	int	0x10		; AH=cols, AL=mode, BH=page
	mov	ch,#0x18
	cmp	al,#7
	je	mn_imono	; MDA does not use 40:84
	push	ds
	push	#0x40
	pop	ds
	mov	ch,[0x84]	; get rows-1
	pop	ds
mn_imono:
	mov	cl,ah
	dec	cl		; CL=cols-1
#ifndef PAGE0
	mov	[mn_page],bh	; save page
#endif
	mov	[mn_max_row_col],cx	; save max screen coord.
	cmp	al,#7		; test for monochrome
	jne	mn_init9
	push	dword [mn_at_mono]	; move 4 bytes
	pop	dword [mn_attrib]
mn_init9:
	ret

; mn_getcursor:
;	exit with:
;		DX = current cursor position
;
mn_getcursor:
	push	ax
	push	bx
	push	cx
	mov	ah,#3
#ifndef PAGE0
	mov	bh,[mn_page]
#else
	xor	bh,bh
#endif
	int	0x10
	pop	cx
	pop	bx
	pop	ax
	ret

; mn_setcursor:
;
;	enter with:
;		DX = row/col for cursor
;
mn_setcursor:
	push	ax
	push	bx
	mov	ah,#2
#ifndef PAGE0
	mov	bh,[mn_page]
#else
	xor	bh,bh
#endif
	int	0x10
	pop	bx
	pop	ax
	ret

; mn_cursoroff:
;
mn_cursoroff:
	push	dx
	mov	dx,[mn_max_row_col]
	inc	dh
	xor	dl,dl
	call	mn_setcursor
	pop	dx
	ret

; mn_rdcha:  read character and attribute
;	enter with:
;		DX = row/col
;
;	exit with:
;		AH = attribute
;		AL = character
;
mn_rdcha:
	push	bx
	mov	ah,#2		;set cursor position
#ifndef PAGE0
	mov	bh,[mn_page]
#else
	xor	bh,bh
#endif
	int	0x10
	mov	ah,#8		; read char and attr
	int	0x10
	pop	bx
	ret

; mn_wrcha:  write character and attribute
;	enter with:
;		AH = attribute
;		AL = character
;		DX = row/col
;	
mn_wrcha:
	push	cx
	push	bx
	push	ax
	mov	ah,#2
#ifndef PAGE0
	mov	bh,[mn_page]
#else
	xor	bh,bh
#endif
	int	0x10	; set cursor position
	pop	ax
	push	ax
	mov	bl,ah
	mov	cx,#1
	mov	ah,#9
	int	0x10
	pop	ax
	pop	bx
	pop	cx
	ret

; mn_wrstra:  write string with attribute
;	enter with:
;		AL = attribute
;		DS:BX points at string
;		DX = row/col of start
;
mn_wrstra:
	push	ax
	push	bx
	push	dx
	mov	ah,al
mn_wrs1:
	mov	al,(bx)
	inc	bx
	or	al,al
	jz	mn_wrs9
	call	mn_wrcha
	inc	dl
	jmp	mn_wrs1
mn_wrs9:
	pop	dx
	pop	bx
	pop	ax
	ret
	
; mn_drawbox:
;	enter with:
;		AL = 	0 no border
;			1 single border
;			2 double border
;			3 single top/bot, double sides
;			4 double top/bot, single sides
;	   (if hi-bit of AL is set, expand box by 1 in horizontal)
;		BH = attribute for area
;		CX = row/col of upper left
;		DX = delta row/delta col
;
mn_drawbox:
	push	dx
	push	cx
	push	ax
	or	al,al
	jns	mn_dr01
	dec	cl
	inc	dl
	inc	dl
mn_dr01:
	mov	ax,#0x0600
	add	dx,cx
	int	0x10
	pop	ax
	pop	cx
	pop	dx
	test	al,#0x7F
	jz	mn_dr9

	push	ax
	push	si
	and	ax,#0x7F
	mov	si,ax
	shl	si,#3
	lea	si,[mn_box-8](si)

	mov	ah,[mn_at_border]
	xchg	dx,cx

	push	cx

	lodsb
mn_dr1:	call	mn_wrcha
	inc	dl
	dec	cl
	mov	al,(si)
	jnz	mn_dr1

	inc	si
	lodsb
mn_dr2:	call	mn_wrcha
	inc	dh
	dec	ch
	mov	al,(si)
	jnz	mn_dr2

	pop	cx
	push	cx
	inc	si
	lodsb
mn_dr3:	call	mn_wrcha
	dec	dl
	dec	cl
	mov	al,(si)
	jnz	mn_dr3

	inc	si
	lodsb
mn_dr4:	call	mn_wrcha
	dec	dh
	dec	ch
	mov	al,(si)
	jnz	mn_dr4

	pop	cx
	xchg	cx,dx
	
	pop	si
	pop	ax

mn_dr9:	ret

; mn_vline:  vertical line
;
;	enter with:
;		AL = 1 (single line), 2 (double line)
;		CX = row/col to start
;		DH = delta Y
;
mn_vline:
	pusha
	cbw
	mov	si,ax
	mov	bl,[mn_ver-1](si)
	shl	si,#3
	lea	si,[mn_vint-8](si)
	mov	di,#0x100
	xchg	cx,dx
	mov	cl,ch
	jmp	mn_line00	; join common code



; mn_hline:  horizontal line
;
;	enter with:
;		AL = 1 (single line), 2 (double line)
;		CX = row/col to start
;		DL = delta X
;
mn_hline:
	pusha
	cbw
	mov	si,ax
	mov	bl,[mn_hor-1](si)	; BL is char to write
	shl	si,#3
	lea	si,[mn_hint-8](si)	; SI is intersect table
	mov	di,#1
	xchg	cx,dx
; do the beginning of the line
mn_line00:
	call	mn_rdcha
	mov	ah,bl		; AH is char to write
	cmp	al,(si)		; know intersect?
	jne	mn_line01
	mov	ah,[1](si)
mn_line01:
	cmp	al,[4](si)
	jne	mn_line02
	mov	ah,[5](si)
mn_line02:
	mov	al,ah
	mov	ah,[mn_at_border]
	call	mn_wrcha
	add	dx,di
	dec	cl
	jz	mn_line20

mn_line10:		;do the central part of the line
	call	mn_rdcha
	mov	ah,bl
	cmp	al,(si)
	jne	mn_line11
	mov	ah,[2](si)
mn_line11:
	cmp	al,[4](si)
	jne	mn_line12
	mov	ah,[6](si)
mn_line12:
	mov	al,ah
	mov	ah,[mn_at_border]
	call	mn_wrcha
	add	dx,di
	dec	cl
	jnz	mn_line10

mn_line20:		;do the end of the line
	call	mn_rdcha
	mov	ah,bl
	cmp	al,(si)
	jne	mn_line21
	mov	ah,[3](si)
mn_line21:
	cmp	al,[4](si)
	jne	mn_line22
	mov	ah,[7](si)
mn_line22:
	mov	al,ah
	mov	ah,[mn_at_border]
	call	mn_wrcha

	popa
	ret

mn_box:	db	SE,EW,SW,NS,NW,EW,NE,NS
	db	SSEE,EEWW,SSWW,NNSS,NNWW,EEWW,NNEE,NNSS
	db	SSE,EW,SSW,NNSS,NNW,EW,NNE,NNSS
	db	SEE,EEWW,SWW,NS,NWW,EEWW,NEE,NS

mn_hor:	db	EW,EEWW
mn_hint:  db	NS,NSE,NSEW,NSW
	db	NNSS,NNSSE,NNSSEW,NNSSW
	db	NS,NSEE,NSEEWW,NSWW
	db	NNSS,NNSSEE,NNSSEEWW,NNSSWW

mn_ver:	db	NS,NNSS
mn_vint:  db	EW,SEW,NSEW,NEW
	db	EEWW,SEEWW,NSEEWW,NEEWW
	db	EW,SSEW,NNSSEW,NNEW
	db	EEWW,SSEEWW,NNSSEEWW,NNEEWW

mn_attrib:
mn_at_text:	db	0x47
mn_at_hilite:	db	0x71
mn_at_border:	db	0x47
mn_at_title:	db	0x4E

mn_at_mono:	db	0x07,0x70,0x07,0x0F
#ifndef PAGE0
mn_page:	db	0
#endif
mn_max_row_col: dw	0

; end of menu.S

