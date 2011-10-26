/*  display4.S is

 Copyright 2001-2005 John Coffman.
 All rights reserved.

 Licensed under the terms contained in the file 'COPYING' in the 
 source directory.

*/
;
;	Static Name Aliases
;
;;        segment _TEXT PARA class=CODE
	.text

/* the following is set to 1 to test the fallback to TEXT mode */
#define FAIL	0

	.even		; 8

_bmp:   dd      0
_tp:    dd      0
_state: dw    -1
_Mode:  dw      0
_ypitch: dw     0
_shift:	dw	0
_mask:	dd	0
_himask: dd	0
_VesaWindow:	dw	-1
_seg:	dw	0


;
;       get a single byte in AX (zero extended)
;       and increment the HUGE pointer _tp
;
;       c = *tp++;
;
;
        .even		;   8
getbyte:
        lodsb
        push    ax
        cmp     si,#1
        sbb     ax,ax
        and     ax,#0x1000
	add     bp,ax
        mov     ds,bp
        pop     ax
        sub     ah,ah
        ret


        .even		;   4

d4_getrow4:
        pusha
        push    ds

;	rpt = -8                ; bh
;	repeat = -10            ; bl
;	skip = -12              ; dh
;	lp = -4                 ; es:di
;	c = -6
;	npix = DX               ; cx
;	compr = AX
;       tp was _tp              ; ds:si -- HUGE ptr  [bp:si]

	mov	di,#_line	;lp
        push    cs
        pop     es
	seg	cs
          lds     si,[_tp]        ;
        mov     cx,dx           ;npix
	cmp	ax,#1	        ;compr
        mov     bp,ds           ;
	ja	d4_I600
        je      d4_I601
d4_FC581:
        call    getbyte
        push    ax
	sar	ax,#4
        stosb                   ;*lp++
        pop     ax
	dec	cx	;npix
	and	al,#15	;000fH
        stosb                   ;*lp++
	loop	d4_FC581
        jmp     d4_I601
;
; compr == 2
;        
d4_FC590:
	cmp	cx,#0	;npix
	jle	d4_FB591
        call    getbyte
	mov	bh,al   	;rpt
	mov	bl,al   	;repeat
	or	ax,ax
	je	d4_L676
	sub	cx,ax	;npix
        call    getbyte
	jmp	d4_L675
d4_FC594:
        push    ax
	sar	ax,#4
        stosb                   ;*lp++
        pop     ax
	dec	bh	; 2001/06/23
	jz	d4_L676 ; 2001/06/23
        push    ax
	and	al,#15	;000fH
        stosb                   ;*lp++
        pop     ax
	dec	bh	;rpt 2001/06/23
d4_L675:
	or	bh,bh	;rpt
	jne	d4_FC594
d4_L676:
	or	bl,bl   ;repeat
	jne	d4_FC590
d4_FB591:
        jcxz    d4_I600   ;npix
        call    getbyte
	mov	bh,al	;rpt
	sub	cx,ax	;npix
        mov     dh,al
	inc	dh	; 2001/06/23
        and     dh,#2    ;skip
	jmp	d4_L677
d4_FC598:
        call    getbyte
        push    ax
	sar	ax,#4
        stosb                   ;*lp++
        pop     ax
	dec	bh	;rpt 2001/06/23
	jz	d4_L678	; 2001/06/23
	and	al,#15	;000fH
        stosb                   ;*lp++
	dec	bh	;rpt 2001/06/23
d4_L677:
	cmp	bh,#0	;rpt
	jne	d4_FC598
d4_L678:
	or	dh,dh	;skip
	je	d4_I600
        call    getbyte
d4_I600:
	mov	bl,#1	;repeat
	cmp	cx,#0	;npix
	jg	d4_L676
        call    getbyte
        call    getbyte
;;;     jmp     d4_I601

d4_I601:
	seg	cs
          mov     [_tp],si        ;
	seg	cs
	  mov     [_tp+2],ds      ;
        pop     ds
        popa
	ret	


        .even		;   4
d4_char10:
	enter	#6,#0
        pusha
        push    ds

;	buf =  0xA000:DI
;	cgen =  ES:SI
;	bits =  ax on top of stack
;	points	(bp-2)
;	shadow  (bp-4)
;	mask	(bp-6)

;	sch     (bp+4)  (arg);  DS:BX
;	y =     BX	(arg)
;	x =     DX	(arg)
;	c =     AX	(arg)

        push    WORD #0
        pop     ds
        mov	cx,WORD [0x485] ;points
	xor	ah,ah           ;AL is char to put out
	mov	WORD (bp-2),cx	;points
	imul	ax,cx           ;leave DX alone; 386 form of instruction
	mov	si,#268	;010cH	; int 0x43 -> character bitmaps
        add	ax,WORD (si)
        mov	es,WORD (si+2)  ;cgen
        xchg    si,ax           ;cgen

;  call pixadr -----------------------------------
	mov	cx,dx		;x
	and	cx,#7		;mask for shift
	sar	dx,#3		;x
	mov	ax,#0x00FF	;mask

        imul    di,bx,#640/8	; DI = y * _ypitch
	ror	ax,cl		;AL is mask, AH is hi-mask
	add	di,dx		; + x
	mov	WORD (bp-6),ax	;save mask
;-------------------------------------------------
	mov	WORD (bp-4),#0	;shadow
        mov     dx,#0x03CE      ;
	lds	bx,(bp+4)	;sch
d4_FC527:
        seg	es
	  lodsb           ;cgen -> bits
        push    es
	sub	ah,ah
        push    WORD #0xA000
	ror	ax,cl	;rotated bits in AX
        pop     es
	push	ax	;save AX rotated bits

	not	ax
	and	ax,WORD (bp-6)	;mask complement
	push	ax

        mov	ah,BYTE (bx+2)	;sch->bg
        cmp	BYTE (bx),ah	;sch->fg
	pop	ax		; inserted ****
	je	d4_I529

	push	ax		;AH = bits high; AL = bits low
	mov	ah,al		;AH = bits low
	mov	al,#08
        out     dx,ax
	mov	ah,BYTE (bx+2)	;sch->bg
        seg	es
	  and	BYTE (di),ah    ;buf
	pop	ax		; get complemented bits back
	jcxz	d4_I529

	mov	al,#08		;AH = ~bits hi, AL = 8
        out     dx,ax
	mov	al,BYTE (bx+2)	;sch->bg
        seg	es
	  and	BYTE (di+1),al    ;buf
	
d4_I529:	; rotated bits in the stack
        mov	al,BYTE (bx+4)	;sch->sh
        cmp	BYTE (bx),al	;sch->fg
	je	d4_I530
	mov	ax,WORD (bp-4)	;get shadow
	rol	ax,#7		;	
	push	ax
	mov	al,#8
        out     dx,ax
	mov	ah,BYTE (bx+4)	;sch->sh
        seg	es
	  and	BYTE (di),ah
	pop	ax
	jcxz	d4_I530

	xchg	ah,al
	mov	al,#8
        out     dx,ax
	mov	ah,BYTE (bx+4)	;sch->sh
        seg	es
	  and	BYTE (di+1),ah
	
d4_I530:
	pop	ax		;rotated bits
	mov	WORD (bp-4),ax	; save shadow

	push	ax
	mov	ah,al
	mov	al,#8
        out     dx,ax
        mov	al,BYTE (bx)	;sch->fg
        seg	es
	  and	BYTE (di),al
	pop	ax
	jcxz	d4_I531

	mov	al,#8
        out     dx,ax
        mov	al,BYTE (bx)	;sch->fg
        seg	es
	  and	BYTE (di+1),al

d4_I531:
        add     di,#640/8        ;buf
        pop     es
        dec     WORD (bp-2)
        jne     d4_FC527

d4_EX519:
        pop     ds
        popa
	leave
	ret	


        .even		;   4
_text:
        push    bp
        mov     bp,sp
        push    ds

;	sch = 14
;	len = 12
;	cp = 8
;	ypos = 6
;	xpos = 4
        mov     ax,#2
	call	d4_setstate
	mov	cx,WORD (bp+12)	;len
	mov     bx,WORD (bp+6)	;ypos
	mov     dx,WORD (bp+4)	;xpos
#ifndef PIXADDRESS
        shl     bx,#4            ;ypos
        shl     dx,#3            ;xpos
#endif
	lds	si,(bp+8)	;cp
        jcxz    d4_L672
	push	WORD (bp+16)
	push	WORD (bp+14)	;sch
d4_FC544:
        lodsb                   ;*cp
	seg cs
	  cmp	WORD [_Mode],#0x12
	jbe	d4_tVga
	call	d4_char256
	jmp	d4_tCont
d4_tVga:
        call	d4_char10
d4_tCont:
	add	dx,#8	;xpos
	loop	d4_FC544
	add	sp,#4
d4_L672:
        xor     ax,ax
	call	d4_setstate
        pop     ds
	leave	
	ret	

#if 0
        .even		;   4

_setpalette:
	push	bp
	mov	bp,sp
;	blue = 10
;	green = 8
;	red = 6
;	color = 4

	push	bx
	mov	bh,bl
        mov     ax,#0x1000
        int     0x10

	mov	bx,#0x3fff	;00ffH
	mov	al,dh
	mul	bh
	div	bl
	mov	dh,al
	xor	dl,dl

	mov	al,ch
	mul	bh
	div	bl
	mov	ch,al

	mov	al,cl
	mul	bh
	div	bl
	mov	cl,al

	pop	bx		;color
        mov     ax,#0x1010
        int     0x10
	leave	
	ret	
#endif


        .even		;   4
d4_putrow4:
        pusha
        push    ds

;	mask = -2
;	lp = -6
;	tp = -10
;	vp = -14
;	vvp = -18
;	i = -20
;	nn = -22
;	x2 = 8
;	x1 = 6          ; DX
;	y = 4           ; AX
        push    ax      ;y
        push    dx      ;x2-x1+1

;begin pack4
	push	ds
        pop     es
        mov     si,#_line
	mov	di,si	;op = lp
        mov     ah,#640/8        ; npix/8
d4_FC185:
	mov	cx,#8
d4_F187:
	seg	es
	  lodsb
        shr     al,#1
        rcl     bl,#1    ;a
	shr	al,#1
        rcl     bh,#1    ;b
	shr	al,#1
        rcl     dl,#1    ;c
	shr	al,#1
        rcl     dh,#1    ;d
	loop	d4_F187
	mov	al,bl	;a
        stosb
	mov	al,bh	;b
        stosb
	mov	al,dl	;c
        stosb
	mov	al,dh	;d
        stosb
        dec     ah
        jne	d4_FC185
d4_EX175:
; end pack4

        pop     bx
	sar	bx,#3            ;nn
        pop     di              ;y
;;	imul	WORD [_ypitch]
        imul    di,#640/8
        push    WORD #0xA000
        pop     es
	mov	si,#_line	;lp
        mov     ax,#0x0102       ;mask
d4_FC563:
	mov     dx,#964	;03c4H
        out     dx,ax
        push    di
        push    si
        mov     cx,bx           ;nn
        push    ax                      ;mask
d4_FC566:
        lodsb
	seg	es
	  and	BYTE (di),al
	add	si,#3	;tp
	inc	di	;vp
	loop	d4_FC566

        pop     ax              ;mask
        pop     si
        pop     di
        shl     ah,#1
	inc	si      	;lp
	test	ah,#15	        ;000fH
	jne	d4_FC563

        pop     ds
        popa
	ret	

        .even		;   4
d4_setstate:
        push    ds

        push    cs
        pop     ds
#if 0
	pusha
	call	wout
	call	ss1
	.ascii	" = AX; setstate entered"
	.byte	10,0
ss1:	pop	bx
	call	say
;;	call	pause
	popa
#endif
	cmp	WORD [_Mode],#0x12
	ja	d4_SB497		;setstate is a NOP if VESA

;	new = 4
	mov     dx,#974	;03ceH
	cmp	ax,WORD [_state]
	je	d4_SB497
	mov	WORD [_state],ax
	dec	ax
	je	d4_SC502
	dec	ax
	je	d4_SC503

; state 0
        push    dx
	mov     ax,#3842	;0f02H
	mov     dx,#964	;03c4H
        out     dx,ax

        pop     dx
	mov     ax,#5    ;0005H
        out     dx,ax

	mov     ax,#3847	;0f07H
        jmp     d4_L669

; state 1
d4_SC502:
	mov     ax,#2053	;0805H
        jmp     d4_L670

;  state 2
d4_SC503:
	mov     ax,#2565	;0a05H
d4_L670:
        out     dx,ax
	mov     ax,#7
d4_L669:
        out     dx,ax
	mov     ax,#3
        out     dx,ax
	mov     ax,#-248	;ff08H
        out     dx,ax
d4_SB497:
#if 0
	pusha
	call	ss2
	.ascii	"setstate exit"
	.byte	10,0
ss2:	pop	bx
	call	say
;;	call	pause
	popa
#endif
        pop     ds
	ret	

        .even		;   4
;
;  _display4:	display the BITMAP
;
;  Enter with:	ES:BX points to the possible bitmap image
;		DS==CS
;
;  Exit with:
;	Carry Clear	- bitmap was displayed
;	AX = 0
;
;	Carry Set	- error occurred
;	AX = 1		"BM" signature not found
;	AX = 2		not VGA adapter or display
;	AX = 3		not 640x480x16 bitmap
;	AX = 4		no VESA support
;
_display4:
; Line 286
	enter	#22,#0
	push	si
	push	di

;	bits = -2
;	colors = -6
;	i = -8
;	disable = -10
;	color = -14
;	bmfh = -18
;	bmh = -22
;	name = 4
; Line 296
	mov	WORD [_bmp],bx	;store for later
	mov	WORD [_bmp+2],es
;;;	les	bx,[_bmp]
	mov	WORD (bp-18),bx	;bmfh
	mov	WORD (bp-16),es
	seg	es
	  cmp	WORD (bx),#19778	;4d42H
	jne	d4_I573
	seg	es
	  cmp	WORD (bx+14+2),#0	; hi-order part of DWORD
	jne	d4_I573
	seg	es
	  cmp	WORD (bx+14),#40	; Windows/OS2 bitmap header
	je	d4_I574
	seg	es
	  cmp	WORD (bx+14),#12	; OS2 bitmap header
	je	d4_I574
; Line 297
d4_I573:
        mov     ax,#1
        stc
	br	_display4_ret

d4_I574:
	mov	ax,WORD [_bmp]
	mov	dx,WORD [_bmp+2]
	add	ax,#14	;000eH
;;	sbb	cx,cx
;;	and	cx,#0x1000
;;	add	dx,cx
	mov	WORD [_tp],ax
	mov	WORD [_tp+2],dx
	mov	WORD (bp-22),ax	;bmh
	mov	WORD (bp-20),dx
; Line 302
	mov	es,dx
	mov	bx,ax
	seg	es
	  cmp	BYTE (bx),#40		; Windows
	je	d4_I575

;  OS2 bitmaps
	seg	es
	  mov	ax,WORD (bx+8)
        seg	es
	  mul	WORD (bx+10)
	mov	WORD (bp-2),ax	;bits
; Line 305
	mov	cx,ax
	mov	ax,#1
	shl	ax,cl
	cwd	
	mov	WORD (bp-6),ax	;colors
; Line 317
	seg	es
	  cmp	WORD (bx+4),#640	;0280H
	jne	d4_I576
	seg	es
	  cmp	WORD (bx+6),#480	;01e0H
	jne	d4_I576

	cmp	cx,#8	;bits
	je	d4_Vesa_Setup

	cmp	cx,#4	;bits
	jne	d4_I576
	jmp	d4_I575a

; Windows/OS2 bitmaps
d4_I575:
	seg	es
	  mov	ax,WORD (bx+12)
        seg	es
	  mul	WORD (bx+14)
	mov	WORD (bp-2),ax	;bits
; Line 305
	mov	cx,ax
	mov	ax,#1
	shl	ax,cl
	cwd	
	mov	WORD (bp-6),ax	;colors
; Line 317
	seg	es
;;;	  cmp	DWORD (bx+4),#640	;0280H
	  cmp	WORD (bx+4),#640	;0280H
	jne	d4_I576
	seg	es
;;;	  cmp	DWORD (bx+8),#480	;01e0H
	  cmp	WORD (bx+8),#480	;01e0H
	jne	d4_I576

	cmp	cx,#8	;bits
	je	d4_Vesa_Setup

	cmp	cx,#4	;bits
	jne	d4_I576
d4_I575a:
	mov	WORD [_Mode],#18	;0012H
;;	mov	cx,#8
;;	cwd	
;;	idiv	cx
;;	mov	WORD [_ypitch],ax
; Line 318
	br	d4_I577

d4_I576:
; Line 319
        mov     ax,#3
        stc
	br	_display4_ret


d4_Vesa_Setup:
	mov	WORD [_Mode],#0x101	; 640x480x256

	mov	di,#MAP			; ES:DI -> 512 byte buffer
	mov	DWORD (di),#SIG_VBE2	; "VBE2"
	mov	ax,#0x4f00		; get mode information

	push	es
	push	ds
	pop	es			; -> communication area
	int	0x10			; video interrupt
	pop	es
#if FAIL
	xor	ax,ax
#endif
	cmp	ax,#0x004f
	jne	d4_I576_4		; no VESA
	cmp	DWORD (di),#SIG_VESA	; "VESA"
	jne	d4_I576_4

	mov	ax,#0x4f01		; get mode information
	mov	cx,[_Mode]

	push	es
	push	ds
	pop	es			; -> communication area
	int	0x10			; video interrupt
	pop	es

	cmp	ax,#0x004f
;;d4_I576_jne:
	jne	d4_I576_4		; no VESA

	mov	ax,v_BytesPerScanLine(di)
	mov	[_ypitch],ax
	mov	ax,v_WinASegment(di)
	mov	[_seg],ax
	mov	cx,v_WinGranularity(di)
	mov	ax,#9			; shift = 9
d4_J575:
	jcxz	d4_K575
	inc	ax			; shift++
	shr	cx,#1
	jmp	d4_J575
d4_K575:
	mov	[_shift],ax
	xchg	ax,cx			; shift to CX
	mov	eax,#-1
	shl	eax,cl			;
	not	eax
	mov	DWORD [_mask],eax
	not	eax
	and	eax,#0x00FFFFFF
	mov	DWORD [_himask],eax	;
	test	BYTE v_ModeAttributes(di),#1
	jz	d4_I576_4
	mov	al,v_WinAAttributes(di)
	and	al,#05
	cmp	al,#05
	jne	d4_I576_4

;;;	mov	bx,#0x8000
;;;	mov	WORD (bp-10),bx		;disable
;;;	or	bx,[_Mode]
	mov	bx,[_Mode]

	mov	ax,#0x4f02		; set video mode
	int	0x10
	cmp	ax,#0x004f
;;;	jne	d4_I576_4
	je	d4_Line_327

d4_I576_4:
	mov	ax,#4
	stc
	br	_display4_ret


; Line 321
d4_I577:
; Line 322
; Line 323
	mov     bx,#0
	mov     ax,#6656	;1a00H
        int     0x10
#if FAIL
	xor	ax,ax
#endif
	cmp	al,#26	;001aH
	jne	d4_I578
	cmp	bl,#7
	je	d4_I579
	cmp	bl,#8
	je	d4_I579
d4_I578:
        mov     ax,#2
        stc
	br	_display4_ret
; Line 324
d4_I579:
	mov     bx,#49	;0031H
	mov     ax,#4609	;1201H
        int     0x10

;;;	mov	WORD (bp-10),#128	;0080H	;disable
	mov	ax,WORD [_Mode]
;;;	or	al,#128	;0080H

        int     0x10
; Line 327
d4_Line_327:
        mov     dx,#480/16
        mov     bx,#0
        mov     ax,#0x1124               ;set for 8x16 characters
        int     0x10
; Line 331
;;;	cmp	WORD (bp-10),#0	;disable
;;;	je	d4_I580
	mov     bx,#54	;0036H
	mov     ax,#4609	;1201H
        int     0x10
; Line 333
d4_I580:
	les	bx,(bp-22)	;bmh
	seg	es
	  mov	si,WORD (bx)
	add	si,WORD [_tp]

	push	ds

	mov	ds,WORD [_tp+2]
; Line 334
	xor	bx,bx		;i
d4_FC582:
; Line 335
	push	bx

	seg cs
	  cmp	[_Mode],#0x12
	ja	d4_Vesa_Palette

	mov	bh,bl
        mov     ax,#0x1000
        int     0x10

d4_Vesa_Palette:
	mov	bx,#0x3fff	;00ffH

	lodsb
	mul	bh
	div	bl
	mov	cl,al

	lodsb
	mul	bh
	div	bl
	mov	ch,al

	lodsb
	mul	bh
	div	bl
	mov	dh,al
	xor	dl,dl

	pop	bx		;color = i
        mov     ax,#0x1010
        int     0x10

; Line 336
	mov	di,(bp-22)	;bmh
	  cmp	BYTE (di),#12	; test for OS/2 bitmap
	je	d4_F580
	inc	si
d4_F580:
; Line 337
	inc	bx	;WORD (bp-8)	;i
d4_F581:
	cmp	WORD (bp-6),bx	;colors
	jg	d4_FC582

	pop	ds

; Line 339
	les	bx,(bp-18)	;bmfh
	seg	es
	  mov	ax,WORD (bx+10)
	seg	es
	  mov	dx,WORD (bx+12)
	add	ax,WORD [_bmp]
	adc	dx,#0
	shl	dx,#12
	add	dx,WORD [_bmp+2]
	mov	WORD [_tp],ax
	mov	WORD [_tp+2],dx
; Line 340
        xor     ax,ax
	call	d4_setstate
; Line 341
        mov     ax,#1
	call	d4_setstate
; Line 342
	les	bx,(bp-22)	;bmh
;;	seg	es
;;	  mov	ax,WORD (bx+8)		; 480
	mov	ax,#480			; Windows or OS2
;;	seg	es
;;	  mov	dx,WORD (bx+4)		; 640
	mov	dx,#640			; Windows or OS2
	seg	es
	  cmp	BYTE (bx),#13		; OS2
	sbb	cx,cx			; OS2 = -1, Win = 0
	not	cx
	seg	es
	  and	cx,WORD (bx+16)		; compression

	mov	bx,cx			; compression to BX

	mov	si,#d4_getrow4
	mov	di,#d4_putrow4
	cmp	WORD [_Mode],#0x12
	jbe	d4_FC586
	mov	si,#d4_getrow8
	mov	di,#d4_putrow8
d4_FC586:
	dec	ax
        js      d4_FC587
; Line 343
        xchg    ax,bx
;;;	call	d4_getrow4
	call	si		;getrow
; Line 344
        xchg    ax,bx
;;;	call	d4_putrow4
	call	di		;putrow
; Line 345
	jmp	d4_FC586

d4_FC587:
; Line 346
	xor	ax,ax			; restore state
	call	d4_setstate
; Line 348

	mov     bx,#54	;0036H          ;enable refresh
	mov     ax,#4608	;1200H
        int     0x10

        xor     ax,ax           ;clears the carry
_display4_ret:
	pop	di
	pop	si
	leave	
	ret	

        .even		;   4
_done4:
	xor	ax,ax
	call	d4_setstate	;restore state
; Line 356
; enable default palette loading
	mov     bx,#49	;0031H
	mov     ax,#4608	;1200H
        int     0x10
; Line 357
	mov     ax,#0x0003       ; set video mode
        int     0x10
; Line 359
	ret	


; pixadr8 - pixel address in 256 color mode
;
;   Enter with:
;	AX = y
;	BX = x
;
;   Exit with:
;	ES:DI = pointer to byte
;
d4_pixadr8:
	push	ax
	push	cx
	push	dx
	push	ds

	push	cs
	pop	ds

;;	seg cs
	  mul	WORD [_ypitch]
	add	ax,bx
	adc	dx,#0
	mov	di,ax
;;	seg cs
	  mov	cl,[_shift]
;;	seg cs
	  and	di,[_mask]
	shrd	ax,dx,cl
;;	seg cs
	  cmp	ax,[_VesaWindow]
	je	d4p8_1

;;	seg cs
	  mov	[_VesaWindow],ax
	xchg	ax,dx
	push	bx
	xor	cx,cx
	xor	bx,bx
	mov	ax,#0x4f05
	int	0x10
	pop	bx
d4p8_1:
;;	seg cs
	  mov	es,[_seg]

	pop	ds
	pop	dx
	pop	cx
	pop	ax
	ret



; putrow8
;
;   Enter with:
;	AX = y
;	BX = compression
;	DX = npix (640)
;	DS == CS
;
;  Exit with:
;	ES is trashed
;	all other registers preserved
;
d4_putrow8:
	pusha
	mov	si,#_line	; source

	mov	cx,WORD [_mask]	; mask
	xor	bx,bx
	xor	di,di
d4p8_2:
	test	di,cx
	jnz	d4p8_3
	call	d4_pixadr8
d4p8_3:
	inc	bx
	movsb
	cmp	bx,dx
	jb	d4p8_2

	popa
	ret


; getrow8
;
;	AX = compression
;	DX = npix (640)
;	BX = y
;
;
d4_getrow8:
	pusha
	push	ds

	push	cs
	pop	es
	mov	di,#_line		; ES:DI setup
	lds	si,[_tp]		; DS:SI is a HUGE pointer
	mov	bp,ds			; also in BP:SI

	test	ax,ax
	jz	d4_get8_nocompr

; get with compression
;
; DX is npix
; BH is repeat
; BL is skip
; CX is rpt

;      repeat = 1;
	mov	bh,#1

;      while (npix>0) {
	jmp	d4_get8_99
d4_get8_1:

;         while (repeat && npix>0) {
	jmp	d4_get8_30
d4_get8_10:

;            rpt = GETC(infile);
	call	getbyte
	xchg	ax,cx

;            repeat = rpt;
	mov	bh,cl

;            if (repeat) {
	test	bh,bh
	jz	d4_get8_20

;               c = GETC(infile);
	call	getbyte

;               npix -= rpt;
	sub	dx,cx

;               while (rpt>0) {
;                  *lp++ = c;
;                  rpt--;
;               }
	rep
	 stosb

;            }
d4_get8_20:

;         }	/* end while (repeat && npix>0) */
d4_get8_30:
	test	bh,bh		; repeat
	jz	d4_get8_40
	cmp	dx,#0
	jg	d4_get8_10
d4_get8_40:

;         if (npix>0) { /* get some enumerated data */
	cmp	dx,#0
	jle	d4_get8_95

;            rpt = GETC(infile);
	call	getbyte
	xchg	ax,cx

;            npix -= rpt;
	sub	dx,cx

;            skip = (rpt%2 != 0);
	mov	bl,cl

;            while (rpt>0) {
	jcxz	d4_get8_75
d4_get8_70:

;               c = GETC(infile);
	call	getbyte

;               *lp++ = c;
	stosb
;               rpt--;
;            }
	loop	d4_get8_70
d4_get8_75:
;            if (skip) c = GETC(infile);
	shr	bl,#1
	jnc	d4_get8_80
	call	getbyte
d4_get8_80:

;         }
d4_get8_95:

;         repeat = 1;
	mov	bh,#1

;	} /* end while (npix>0) */
d4_get8_99:
	cmp	dx,#0
	jg	d4_get8_1

;      GETC(infile);
;      c=GETC(infile);
	call	getbyte
	call	getbyte

	jmp	d4_get8_exit


; get with no compression
;   really just a super movsb with a huge source pointer

d4_get8_nocompr:
	mov	cx,dx
d4_get8_nloop:
	call	getbyte		; BP==DS is required
	stosb
	loop	d4_get8_nloop

d4_get8_exit:
	seg	cs
          mov     [_tp],si        ;
	seg	cs
	  mov     [_tp+2],ds      ;

	pop	ds
	popa
	ret

; char256
;
;   Enter with:
;	AL	character to display
;	BX	ypos
;	DX	xpos
;	(bp+4)	far pointer to 
;
;   Exit with:
;	ES is trashed
;
;
;   Stack used:
;	bp-2	points
;	bp-4	ypos
;	bp-6	xpos
;	bp-8	bits
;	bp-10	xtem
;
;   Variables:
;	DS:SI	cgen
;	SI	i
;	BX	xtem
;	ES:DI	buf
;
d4_char256:
	enter	#10,#0
	pusha
	push	ds

        push    WORD #0
        pop     ds
;   points = *(short*)0x00000485UL;     /* 40:85 */
        mov	cx,WORD [0x485] ;points
	xor	ah,ah           ;AL is char to put out
	mov	WORD (bp-2),cx	;points
	mov	WORD (bp-4),bx	;ypos
	mov	WORD (bp-6),dx	;xpos

;   cgen = *(char**)(0x43 * 4UL);       /* int 0x43 points to char bitmap */
;   cgen += (unsigned)c * points;
	imul	ax,cx           ;leave DX alone; 386 form of instruction
	mov	si,#268	;010cH	; int 0x43 -> character bitmaps
        add	ax,WORD (si)
        mov	ds,WORD (si+2)  ;cgen
        xchg    si,ax           ;cgen	in DS:SI

;   shadow = 0;
	xor	ch,ch
	les	di,(bp+4)	;sch->
;   fg = sch->fg;
	seg es
	 mov	cl,(di)
;   bg = sch->bg;
	seg es
	  mov	dh,(di+2)
;   sh = sch->sh;
	seg es
	  mov	dl,(di+4)
;
;   while (points--) {
d4_char256_10:
;      int i;
;
;      bits = *cgen++;			;cgen in DS:SI
	lodsb
	mov	WORD (bp-8),ax		;bits
	push	si			; save SI

;      fore = bits;		; fore is BL
	xchg	bx,ax		; fore is BL

;      xtem = x;
	mov	ax,WORD (bp-6)
	mov	WORD (bp-10),ax		;xtem

;      for (i=8; i; i--) {
	mov	si,#8			;i
	xor	di,di			;buf

d4_char256_20:
	seg cs
	  test	di,WORD [_mask]
	jnz	d4_char256_22
	push	bx
	mov	ax,WORD (bp-4)	;ypos
	mov	bx,WORD (bp-10)	;xtem
	call	d4_pixadr8	;buf to ES:DI
	pop	bx
d4_char256_22:

;         int color = 0x400;
	mov	ax,#0x400

;         if (bg != fg) color = bg;
	cmp	dh,cl		;bg:fg
	je	d4_char256_31
	mov	al,dh		;color = bg
	cbw
d4_char256_31:

;         if ( (shadow&0200) && sh != fg) color = sh;
	shl	ch,#1		;shadow
	jnc	d4_char256_33
	cmp	dl,cl		;sh:fg
	je	d4_char256_33
	mov	al,dl		; color = sh
	cbw
d4_char256_33:

;         if ( (fore & 0200) ) color = fg;
	shl	bl,#1
	jnc	d4_char256_35
	mov	al,cl		; color = fg
	cbw

d4_char256_35:

;         buf = pixadr8(xtem++, y);
;         if (color<256) *buf = color;
	inc	ah
	cmp	ah,#1
	ja	d4_char256_39
	seg es
	  mov	BYTE (di),al
d4_char256_39:
	inc	di
	inc	WORD (bp-10)	;xtem

;         shadow <<= 1;
;         fore <<= 1;
;      }
	dec	si		;i
	jnz	d4_char256_20

;      y++;
	inc	WORD (bp-4)	;ypos

;      shadow = bits>>1;
	mov	ch,BYTE (bp-8)
	shr	ch,#1
;   }
	pop	si		;cgen
	dec	WORD (bp-2)
	jnz	d4_char256_10



d4_char256_exit:
	pop	ds
	popa
	leave
	ret


