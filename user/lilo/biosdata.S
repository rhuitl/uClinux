;  biosdata.S  is
;
;  Copyright 2002-2004 John Coffman.
;  All rights reserved.
;
;  Licensed under the terms contained in the file 'COPYING' in the 
;  source directory.
;
;


io_sig:	.long	0		; space for CRC
	.ascii	PROBE_SIGNATURE	; "LiLo"
	.word	PROBE_VERSION	; sanity check
io_lth:	.word	0		; byte count overall
io_good_disk:
	.byte	0	; last good drive (in low byte)
	.byte	BD_GET_VIDEO
	.byte	BD_MAX_FLOPPY
	.byte	BD_MAX_HARD
io_flp:	.word	0
io_hrd:	.word	0
io_pt:	.word	0

#if PROBE_VERSION >= 5
io_eqp:	.word	0
io_vid:	.word	0
#endif

io_l_sig	= *-io_sig

; read partition table of device in DL
;
; save PT
;
io_get_pt:
	push	ds
	push	es

	push	#0
	pop	es
	mov	bx,#BOOTSEG*16+SECTOR_SIZE
	mov	cx,#1
	mov	dh,#0
	mov	ax,#0x201		; read 1 sector
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Read partition table\n"
	.byte	0
	popa
#endif
	call	dsk_do_rw		; make 5 tries
	push	es
	pop	ds

	pop	es
#if  PROBE_VERSION == 3
	lea	si,(bx+PART_TABLE_OFFSET)
	mov	cx,#4*16
#elif  PROBE_VERSION >= 4
	lea	si,(bx+PART_TABLE_OFFSET-8)
	mov	cx,#4*16+8
#endif
	jc	io_get_pt_err
	rep
	  movsb
io_get_pt_ret:
	pop	ds
	ret

io_get_pt_err:
	mov	al,#-1
	rep
	  stosb
	jmp	io_get_pt_ret



; check a hard drive for EDD support
;
;	device code is in DL
;
;
io_do_edd_check:
	push	dx
	mov	ah,#0x41
	mov	bx,#0x55AA
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Check EDD present\n"
	.byte	0
	popa
#endif
	int	0x13

	xchg	al,ah
	lahf
	pop	dx

	stosw
	mov	ax,bx
	stosw
	xchg	ax,cx
	stosw

	jc	io_do_edd_check_ret
	cmp	bx,#0xAA55
	jne	io_do_edd_check_ret
#if PROBE_VERSION < 6
	test	al,#EDD_SUBSET	; test for EDD call supported
	jz	io_do_edd_check_ret
#endif

; get the EDD parameters

	push	dx		; paranoia, protect DL
	push	es		; more paranoia
	push	ds

	push	es
	pop	ds
	mov	si,di		; DS:SI points at return area
	push	di
	mov	ah,#0x48
	mov	word (si),#EDD_LTH	; set max count to return
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get EDD parameters\n"
	.byte	0
	popa
#endif
	int	0x13
	pop	di

	xchg	al,ah
	lahf
	
	add	di,#EDD_LTH
	stosw			; save the return flags

	pop	ds
	pop	es
	pop	dx

io_do_edd_check_ret:
	ret



;
; io_biosdata:	examine hard disk BIOS devices
;		and video state
;
;  Enter with:
;		DS == CS
;		direction flag clear
;
;
;  Exit with:
;		All registers preserved
;		
;		Side effect is to write the low memory disk data area
;
;
;

io_biosdata:
	pusha			;save all registers
	push	es

	push	#PROBESEG	;save area is at 0060:0000 (0x000600)
	pop	es
	mov	di,#io_l_sig	;skip over header area

; get the equipment configuration flags

#if PROBE_VERSION >= 5
	mov	io_eqp,di	;save equipment pointer
	push	dx		; protect this register
#endif
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get equipment configuration\n"
	.byte	0
	popa
#endif
	int	0x11
	stosw

; get the conventional memory size

#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get conventional memory size\n"
	.byte	0
	popa
#endif
	int	0x12
	stosw			; save the number

#if PROBE_VERSION >= 5
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Save boot device code\n"
	.byte	0
	popa
#endif
	pop	ax		; get saved DX register
	stosw			
#endif

; collect the video information

#if PROBE_VERSION >= 5
	mov	io_vid,di	; set the pointer
#endif
#if BD_GET_VIDEO >= 1
	mov	ah,#0x0F	; get video mode
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get video mode\n"
	.byte	0
	popa
#endif
	int	0x10

	push	ds
	push	#0x40
	pop	ds
	mov	bl,[0x84]	; get rows, too
	pop	ds

	stosw			; save AX
	xchg	ax,bx
	stosw			; save BX
	cmp	bl,#7		; is it MDA
	beq	io_floppies	; yup, skip it all
	cmp	bh,#80		; number of columns on screen
	jb	io_floppies1	; probably CGA

#endif
#if BD_GET_VIDEO >= 2
#if 1
	mov	ah,#0x12
	mov	bx,#0xFF10	; get configuration information
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get video configuration\n"
	.byte	0
	popa
#endif
	int	0x10

	stosw			; save AX
	xchg	ax,bx
	stosw			; save BX
	cmp	ah,#1
	ja	io_floppies1

#endif
	mov	ax,#0x1A00	; get display combination code
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get display combination\n"
	.byte	0
	popa
#endif
	int	0x10

	stosw			; save AX
	xchg	ax,bx
	stosw			; save BX
	cmp	bl,#0x1A	; is function supported?
#ifndef BD_VERBOSE
	jne	io_floppies
#else
	bne	io_floppies
io_floppies1	equ	*-3
#endif
	cmp	al,#4
	jb	io_floppies1

#if PROBE_VERSION >= 5

; test to see if registers get trashed (some geforce video bios trashes dx)
	push	ds
	push	es
	push	di

	mov	cx,#0x1234
	mov	dx,#0x5680
	mov	bp,#0x4321

	mov	ax,#0x1200
	mov	bx,#0x0036
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Enable Screen Refresh\n"
	.byte	0
	popa
#endif
	int	0x10		; enable screen refresh

	pop	di
	pop	es
	pop	ds
	stosw			; AX
	xchg	ax,cx
	stosw			; CX
	xchg	ax,dx
	stosw			; DX
	xchg	ax,bp
	stosw			; BP
#endif

#endif  /* BD_GET_VIDEO >= 2 */

#if BD_GET_VIDEO >= 3
	mov	ax,#0x4F00	; check VESA present
; ES:DI is already set
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Check VESA present\n"
	.byte	0
	popa
#endif
	int	0x10

	seg es
	  mov	bx,(di)		; possible "VE"
	seg es
	  mov	cx,(di+2)	; possible "SA"
	stosw			; save AX
	xchg	ax,bx
	stosw			; possible "VE"
	xchg	ax,cx		; possible "SA"
	stosw
	cmp	bx,#0x004F	; good return
	jne	io_floppies
	cmp	cx,#0x4556	; "VE"
	jne	io_floppies
	cmp	ax,#0x4153	; "SA"
	jne	io_floppies
	
	mov	ax,#0x4F01
	mov	cx,#0x0101	; get mode information
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get VESA mode information 1\n"
	.byte	0
	popa
#endif
	int	0x10	

	seg es
	  mov	bx,(di)		; get bits
	stosw			; save AX
	xchg	ax,bx
	stosw			; save bits

	mov	ax,#0x4F01
	mov	cx,#0x0103	; get mode information
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get VESA mode information 3\n"
	.byte	0
	popa
#endif
	int	0x10	

	seg es
	  mov	bx,(di)		; get bits
	stosw			; save AX
	xchg	ax,bx
	stosw			; save bits
#else
	mov	ax,#-1		; flag for VESA not present
	stosw
	stosw
	stosw
;	jmp	io_floppies	; exit to this point
#endif

; now go after the disk drive information

io_floppies:
#ifndef BD_VERBOSE
io_floppies1:
#endif
	mov	cx,#BD_MAX_FLOPPY	;test 4 floppies
	xor	dx,dx
	mov	io_flp,di		;set pointer to floppy info

io_next_drive:
	push	cx

; get the drive type

	mov	ah,#0x15
	push	dx
#ifdef BD_VERBOSE
	pusha
	test	dl,#3		; pause every 4th drive
	jnz	io_no_pause
	call	pause
io_no_pause:
	call	say
	.ascii	"Get drive type "
	.byte	0
	mov	al,dl
	call	bout
	call	say
	.byte	10,0
	popa
#endif
	int	0x13

	xchg	al,ah		;code to AL
	lahf			;flags to AH

	stosw			; save AX
	xchg	ax,dx
	stosw			; save DX (low order)
	xchg	ax,cx
	stosw			; save CX (high order)
	xchg	ax,dx		; restore code to AL
	pop	dx

	jc	io_no_disk	; error means no disk present
	dec	al		; AL==0 means no disk present
	jns	io_get_param	; if S=0, some disk type is present

io_no_disk:
	or	dl,dl
	jns	io_get_param	;do it all on floppies

	pop	cx		;premature loop termination
	jmp	io_loop_end	;skip the rest on fixed disks

io_get_param:

; get drive parameters

	push	dx
	push	es		; supposedly clobbered for floppies only
	push	di		; do not trust anyone

	mov	ah,#0x08
#ifdef BD_VERBOSE
	pusha
	call	say
	.ascii	"Get drive parameters\n"
	.byte	0
	popa
#endif
	int	0x13
	xchg	al,ah
	lahf
	
	mov	bp,di		; save floppy param pointer
	mov	bx,es

	pop	di
	pop	es

	stosw			; save return code & flags
	xchg	ax,cx
	stosw
	xchg	ax,dx
	stosw
	pop	dx

	jc	io_fh_check	; bad return above
;;;	mov	[io_good_disk],dl	; save DL

	cmp	dl,#0x80	; check for first HD
	jne	io_fh_check
	cbw			; former DL has disk count
	pop	cx		; get HD count
	push	ax		; set new HD count

io_fh_check:
	or	dl,dl		; check floppy/hard disk
	js	io_check_edd
	xchg	ax,bp		; was DI
	stosw
	xchg	ax,bx		; was ES
	stosw
	jmp	io_skip_edd

; check EDD extensions present

io_check_edd:

	call	io_do_edd_check

io_skip_edd:

	mov	[io_good_disk],dl	;save last disk checked
	pop	cx
	inc	dl
#ifndef BD_VERBOSE
	loop	io_next_drive
#else
	dec	cx
	bne	io_next_drive
#endif
io_loop_end:
	or	dl,dl		; set the S flag
	push	di		;
	mov	cx,#BD_MAX_HARD	; do not touch flags ***
	mov	dl,#0x80	; do not touch flags ***
#ifndef BD_VERBOSE
	jns	io_next_drive	; do the hard drives if not done
#else
	bpl	io_next_drive
#endif
	pop	word [io_pt]	; save pt pointer
	pop	word [io_hrd]	; save hd pointer

; now save the partition tables
	
io_get: 
	cmp	dl,io_good_disk
	ja	io_got
	call	io_get_pt
	inc	dx
	jmp	io_get
io_got:

io_checksum_it:

; now must record and checksum the results

	mov	io_lth,di		; address of end is overall count

	push	di
	xor	di,di			;move to here
	mov	si,#io_sig		;move from here
	mov	cx,#io_l_sig		;this number of bytes
	rep
	  movsb				;
	pop	di
	mov	si,#4			; skip long at beginning
	sub	di,si
#ifndef BD_VERBOSE
	push    dword #CRC_POLY1
	call	crc32

	seg	es
	mov	[0],eax			; save that crc
#endif

; restore the registers and return

	pop	es
	popa
	ret

; end biosdata.S
