#if 0
;  volume.S  is
Copyright 2003-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

#endif

#ifdef BSS_DATA

#if 0
vtab:	.blkw	MAX_BIOS_DEVICES_asm*2	; volume IDs indexed by
					;  REAL bios device code

rtab:	.blkw	MAX_BIOS_DEVICES_asm*2	; raid offsets indexed the same


devmap:	.blkw	MAX_BIOS_DEVICES+2	; device code map
					; logical -> physical
					; (lo-byte::hi-byte)
#endif

vtab	=	*
	.org	*+MAX_BIOS_DEVICES_asm*4	; volume IDs indexed by
					;  REAL bios device code

rtab	=	*
	.org	*+MAX_BIOS_DEVICES_asm*4	; raid offsets indexed the same


devmap	=	*
	.org	*+MAX_BIOS_DEVICES*2+4	; device code map
					; logical -> physical
					; (lo-byte::hi-byte)

#else

rmask:	.word	0		; physical raid mask

; build_vol_tab	-- Build the table of volume IDs
;			and fill in the device translate table
;
;   Enter with:
;	DS=ES=CS
;
;   Exit with:
;	Nothing
;
;   Side effects:	The volume ID table is built
;			The from:to device translate table is filled in
;
;
build_vol_tab:
	pusha

	xor	cx,cx		; depend on this being preserved
	xor	dx,dx
	xchg	[devmap],dx	; clear our First Stage mapping

	call	is_prev_mapper	; is there a previous mapper
	jz	bvt0

; have previous mapper active

; ****** 22.5.7
	push	di
	or	dx,dx		; any translation?
	jz	bvt003
bvt001:
	seg es
	mov	ax,(di)		; get previous translation
	inc	di
	inc	di
	or	ax,ax
	jz	bvt003
	cmp	al,dh		; does it affect us?
	jne	bvt001
	mov	[init_dx],ah	; update physical device
bvt003:
	pop	di
; ****** 22.5.7

	seg es
	  mov	(di),cx		; sterilize it
bvt0:	
	push	cs
	pop	es		; restore ES

; ****** 22.5.8
	mov	di,#KEYTABLE+256+mt_serial_no
	mov	cx,#MAX_BIOS_DEVICES_asm
	xor	eax,eax
	repe
	  scasd			; scan for any serial nos in table
	je	bvt90		; if none, skip reading vol_ids
				;    as there will be no translations
; ****** 22.5.8


	xor	cx,cx		; start at hard drive 0 (0x80)
	mov	di,#vtab	; place to put IDs
bvt1:
	call	read_vol_id	; get VolumeID in EAX
	stosd			; store in table
	or	eax,eax		; test for zero
	jz	bvt9		; end, or no volume ID

; now see if there will be a translation
	push	di
	push	cx

; ****** 22.5.9
	mov	cx,di		; 4*table count to CX
	mov	di,#vtab
	sub	cx,di		; 4*count
	shr	cx,#2		; table count
	dec	cx
	jz	bvt1.5		; table empty
	repne			; repeat while no match
	  scasd
	jne	bvt1.5

	mov	bx,#msg_dupl	; duplicate message
	call	say
#if !DEBUG_NEW
	call	pause
#endif
	pop	cx
	pop	di

	mov	dword (di-4),#0	; zero the duplicated volumeID
	jmp	bvt9		; skip to next on duplication

bvt1.5:
; ****** 22.5.9
	mov	si,#KEYTABLE+256+mt_serial_no
	mov	cx,#MAX_BIOS_DEVICES_asm
	mov	di,si
bvt2:	jcxz	bvt7
	repne			; repeat while not matching
	  scasd
	jne	bvt7		; jump if no match
#if 0
; print the raw serial_no match
	pushad
	push	eax
	call	dout
	call crlf
	popad
#endif
	lea	dx,(di-4)	; DX is address of match
	sub	dx,si		; DX is 4*index
	shr	dx,#2		; DX is input device #
	pop	bx		; BX is real device #
	push	bx
	cmp	bx,dx		
; ****** 22.5.9
;;;	je	bvt2		; equal means no translation
	je	bvt7		; equal means no translation
; ****** 22.5.9
	mov	dh,bl		;
	or	dx,#0x8080	; make into HD bios codes
#if 0
; print the raw TT entry
	pusha
	mov	ax,dx
	call	wout
	call	crlf
	popa
#endif
	push	si
	mov	bx,#devmap	; scan the device translation table
bvt4:
	mov	si,(bx)		; get from(low):to(high)  pair
	inc	bx
	inc	bx		; bump pointer by 2
	cmp	si,dx		; duplicate?
	je	bvt5

	or	si,si		; not duplicate; at end?
	jnz	bvt4

	mov	(bx-2),dx	; put at end of table
	mov	(bx),si		; and mark new end
bvt5:
	pop	si
; ****** 22.5.9
;;;	jmp	bvt2
; ****** 22.5.9

bvt7:
	pop	cx
	pop	di
bvt9:
	inc	cx
	cmp	cx,#MAX_BIOS_DEVICES_asm
	jb	bvt1

bvt90:
; now build the RAID offset table

	mov	si,#KEYTABLE+256+mt_raid_offset
	mov	dx,[KEYTABLE+256+mt_raid_dev_mask]
	xor	bx,bx		; count thru devices
bvt91:
	xor	eax,eax		; may store 0
	shr	dx,#1		; is it raid?
	jnc	bvt92		; not a raid device

	lodsd			; get raid offset
	push	eax		; save value in stack

	mov	eax,[KEYTABLE+256+mt_serial_no](bx)
	mov	di,#vtab	; physical table address
	mov	cx,#MAX_BIOS_DEVICES_asm
	repne
	  scasd			; scan for a match
	jne	bvt_not_found	; the logical volume is not there	
	lea	di,(di-4-vtab)	; DI is 4*index into table
	mov	cx,di
	shr	cx,#2		; make 0..15
	mov	ax,#1
	shl	ax,cl		; mask bit in right position
	or	[rmask],ax
	pop	dword ptr rtab(di)	; store RAID offset
	jmp	bvt92
bvt_not_found:
	pop	eax		; clean up the stack
bvt92:
	add	bx,#4		;
	cmp	bx,#MAX_BIOS_DEVICES_asm*4
	jb	bvt91

#if DEBUG_NEW
	mov	bx,#msg_voltab
	call	say
	mov	si,#vtab
	mov	di,#rtab
	mov	cx,#MAX_BIOS_DEVICES_asm
;;;	mov	dx,[KEYTABLE+256+mt_raid_dev_mask] ; was logical mask
	mov	dx,[rmask]		; get physical mask value

; truncate all the empty entries from the end of the list
;
bvtA:	mov	bx,cx
	dec	bx
	shl	bx,#2
	cmp	dword ptr (bx+si),#0
	jne	bvtA2
	loop	bvtA		; 22.6.1

bvtA2:	inc	cx

bvtX:
	lodsd			; get volume serial number
	push	eax
	call	dout		; print it
	shr	dx,#1
	mov	bx,#msg_star
	jc	bvtX1
	mov	bx,#msg_nostar
bvtX1:
	call	say
	push	dword (di)
	call	dout
	add	di,#4
	call	crlf
	loop	bvtX		; loop back

	call	crlf

; now the device translate table:

	mov	bx,#msg_tt
	call	say
	mov	si,#devmap
bvtB:	lodsw			; get from,to pair
	push	ax
	call	bout
	mov	bx,#msg_arr
	call	say
	pop	ax	
	xchg	al,ah
	push	ax
	call	bout
	call	crlf
	pop	ax
	or	ax,ax
	jnz	bvtB
	call	pause	
#endif
	popa		; restore all the regs
	ret

msg_dupl:
	.ascii	"O\nError: Duplicated Volume ID\n"
	.byte	0
#if DEBUG_NEW

msg_voltab:
	.ascii	"The physical VolumeID / Raid1-reloc table\n"
	.byte	0
msg_star:	.ascii	" * "
	.byte	0
msg_nostar:	.ascii	"   "
	.byte	0
msg_space = msg_nostar

msg_tt:	.ascii	"The device translate table:\n"
	.byte	0
msg_arr:  .ascii	" -> "
	.byte	0
msg_plus: .ascii	" + "
	.byte	0
msg_rw:	.ascii	"RAID physical write: "
	.byte	0
#endif

#ifdef LCF_READAHEAD
; ****** 22.6.1 begin
;
; enable_readahead	-- Enable readahead on an EDD drive
;
;   Enter with:
;	DL = hard disk BIOS code 
;	ES=DS=CS
;
;   Return:
;	Nothing		-- enable read-ahead, if possible
;
enable_readahead:
	pusha
#if DEBUG_NEW
	push	dx		; save device code
	xchg	ax,dx
	call	bout
	pop	dx		; restore device code
#endif
	mov     bx,#0x55AA      ;magic number
	mov     ah,#0x41        ;function call
	int     0x13
	jc      enrd9
	cmp     bx,#0xAA55      ;magic return
	jne     enrd9
	test    cl,#EDD_SUBSET|EDD_PACKET	; some EDD support?
	jz      enrd9
#if 0
	cmp	ah,#0x21	; EDD version 1.1 or later?
	jb	enrd9
#endif

	mov	ax,#0x4E00	; enable prefetch
	int	0x13
#if DEBUG_NEW
	mov	al,#'-		; '
	jc	enrd8_d
	test	ah,ah		; check return code in AH
	jnz	enrd8_d
	mov	al,#'+		; '
  enrd8_d:
	call	display
#endif

enrd9:
#if DEBUG_NEW
	call	crlf
#endif
	popa
	ret
; ****** 22.6.1 end
#endif


; read_vol_id	-- Read the volume ID off of a drive
;
;   Enter with:
;	CX = drive number to read (hard disk 0..15)
;	ES=DS=CS
;
;   Return:
;	Carry Clear on success
;	EAX = volume ID         (0 means no ID)
;
;	Carry set on error
;	EAX = 0
;
;
read_vol_id:
	push	bx
	push	dx
	push	cx
	push	di

	push	cx
	push	es		; paranoia (floppies touch it)

	mov	ah,#8		; get number of drives in DL
	mov	dl,#0x80
	call	dsk_do_int13	; retry 5 times

	pop	es
	pop	cx		; restore device code

	jc	rvi_9
	cmp	cl,dl
	jae	rvi_9

	mov	dl,cl
	mov	cx,#1
	mov	bx,#Map
	or	dl,#0x80
	mov	dh,ch
; ****** 22.6.1
#ifdef LCF_READAHEAD
	call	enable_readahead
#endif
; ****** 22.6.1
	mov	ax,#0x201	; read
	call	dsk_do_int13
	jc	rvi_9

	seg es
	  mov	eax,(bx+PART_TABLE_OFFSET-6)	; fetch return
	jmp	rvi_exit
rvi_9:
	xor	eax,eax
	stc
rvi_exit:
	pop	di
	pop	cx
	pop	dx
	pop	bx
	ret


; map_device -- Take the logical device code in DL and map it
;		into the physical device code preserving all flags
;	22.5.6	Any RAID relocated device code maps to the boot device code
;
;  Enter with:
;	DL containing logical device code & flags
;	DS register not guaranteed
;
;  Exit with:
;	DL containing physical device code & same flags
;
;
map_device:
	push	si		; save working registers
	push	ax
	push	bx
	mov	si,#devmap	; point at translation table
	mov	bl,dl
	and	bl,#DEV_MASK_asm	; from device code in BL
#if 1
; ****** 22.5.6
	seg cs
	mov	ah,[init_dx]	; get boot device code
	test	dl,#RAID_REL_FLAG
	jnz	bios_tt_match	; it is RAID, go use the boot device code
; ***** 22.5.6
#endif
bios_tt_next:
	seg cs			; DS may be bad
	  lodsw			; get from/to pair
	or	ax,ax		; end of list?
	jz	bios_tt_done
	cmp	al,bl
	jne	bios_tt_next
; got a match
bios_tt_match:
	and	dl,#0xFF-DEV_MASK_asm	; save flags
	or	dl,ah		; put on the TO device code
bios_tt_done:
	pop	bx
	pop	ax
	pop	si
	ret


#if 0

; rev_map_device -- Take the physical device code in DL and map it
;		into the logical device code preserving all flags
;
;  Enter with:
;	DL containing physical device code & flags
;
;  Exit with:
;	DL containing logical device code & same flags
;
;
rev_map_device:
	push	si		; save working registers
	push	ax
	push	bx
	mov	si,#devmap	; point at translation table
	mov	bl,dl
	and	bl,#DEV_MASK_asm	; TO device code in BL
bios_tt_next:
	lodsw			; get from/to pair
	or	ax,ax		; end of list?
	jz	bios_tt_done
	cmp	ah,bl
	jne	bios_tt_next
; got a match
	and	dl,#0xFF-DEV_MASK_asm	; save flags
	or	dl,al		; put on the FROM device code
bios_tt_done:
	pop	bx
	pop	ax
	pop	si
	ret
#endif


; translate -- test for a raid device, and do the offsetting
;
;  Enter with:
;	DI:CX	LBA32 or LINEAR address
;	DL	physical device code & flags (RAID_REL_FLAG is set)
;	AL	sector count
;	ES:BX	buffer pointer for R/W
;
;  Exit with:
;	DI:CX	updated if RAID translation takes place
;	All other registers are unchanged
;
;
translate:
	push	bp
	mov	bp,sp

	cmp	word [rmask],#0		; any translate bits set?
	jnz	trans_1

; this special cases the initial Keytable read, when no setup has been done
	BEG_FS
	SEG_FS
	add	cx,par1_raid_offset+SSDIFF	; ***** RAID ******
	SEG_FS
	adc	di,par1_raid_offset+2+SSDIFF	; ***** RAID ******
	END_FS
	jmp	trans_ret

trans_1:
	push	di
	push	cx	; form  dword (bp-4)

	mov	di,dx		; DI gets full device code
	and	di,#DEV_MASK_asm & 0x7F
#if DEBUG_NEW
	pusha
	cmp	byte ptr [dsk_wrflag],#0
	jz	trans_01
	mov	bx,#msg_rw
	call	say
	mov	ax,di
	or	ax,#0x80
	call	bout
	mov	bx,#msg_space
	call	say
	push	(bp-4+2)
	push	(bp-4)
	call	dout
trans_01:
	popa
#endif
	shl	di,#2	; index into array

	mov	cx,[rtab](di)	; get low relocation value
	mov	di,[rtab+2](di)	; get high relocation value
#if DEBUG_NEW
	pusha
	cmp	byte ptr [dsk_wrflag],#0
	jz	trans_02
	mov	bx,#msg_plus
	call	say
	push	di
	push	cx
	call	dout
	mov	bx,#msg_arr
	call	say
trans_02:
	popa
#endif

	add	(bp-4),cx	; relocate
	adc	(bp-4+2),di	;  **

	pop	cx
	pop	di
#if DEBUG_NEW
	pusha
	cmp	byte ptr [dsk_wrflag],#0
	jz	trans_03
	push	di
	push	cx
	call	dout
	call	crlf
trans_03:
	popa
#endif

trans_ret:
	pop	bp
	ret

#endif	/* BSS_DATA */

/* end  volume.S */
