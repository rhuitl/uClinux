;  chain.S  -  LILO boot chainer 
;
; Copyright 1992-1998 Werner Almesberger.
; Copyright 1999-2004 John Coffman.
; All rights reserved.
;
; Licensed under the terms contained in the file 'COPYING' in the 
; source directory.
;

#define LILO_ASM
#include "lilo.h"
get common.s		/* as86 "include" will bypass the CPP */

; for debugging, set the EBDA size in Kilobytes; e.g., 64
#define EBDA 0

#define REVERSE_DL 1

#if defined(LCF_SOLO_CHAIN) && !defined(DOS_D)

#ifndef DOS_D
#define DOS_D
#endif

#ifndef CHECK
#define CHECK
#endif

#endif		/* LCF_SOLO_CHAIN */


#if VERSION_MINOR >= 50
#define DEBUG_NEW
#endif

	.text

	.globl	_main
	.org	0

_main:	cld			! make sure !!!
	jmp	start

	
	.org	6

	.ascii	"LILO"		! signature

	.word	STAGE_CHAIN
	.word	VERSION

offset:	.word	0

! the byte "drive" is filled in by the installer & updated by the second stage 

drive:	.byte	0			! drive, 0x80, 0x81
	.byte	0			! head, always zero

hint:	.word	drvmap			! pointer to drive map

ptable:	.blkw	0x20			! partition table to preload

devmap:	.word	0,0			! device map filled in by second.S

cmd:	.word	0,0			! command line to pass on

; ES:DI contains a pointer to the command line passed from second-stage

start:
	xor	bx,bx			! set SS:SP to 0:7C00
	mov	ss,bx
	mov	sp,#BOOTSEG*16		! #0x7C00
	mov	bp,sp			! address from BP
#if EBDA
	push	#0x40
	pop	ds
	mov	word ptr [0x13],#640-EBDA	; simulate EBDA in Kilobytes
#endif
	push	cs
	pop	ds

#ifdef DEBUG_NEW
	push	bp

	push	es
	pop	ds
	mov	si,di
	call	say

	push	cs
	pop	ds
	mov	si,#crlf
	call	say

	call	bd1
	.ascii	"Boot drive 0x"
	.byte	0
bd1:	pop	si
	call	say
	mov	al,drive
	call	bout
	mov	si,#crlf
	call	say

	pop	bp
#endif

	mov	al,#0x3D		! '=' sign
	mov	cx,#-1
	repne
	  scasb				! scan for =
srch:	seg es
	  mov	al,(di)
	inc	di
	cmp	al,#0x20		! test for space
	ja	srch
; real command line if AL==space, no command line if NUL
	jb	nocmd
	mov	[cmd],di
	mov	[cmd+2],es
nocmd:

;
; Account for any drive mappings being used by the Second Stage
;
	les	di,[parC_devmap]	! second stage translate table
					! this was set by the second stage loader
#if defined DEBUG_NEW
	mov	ax,es
	call	wout
	mov	al,#0x20
	call	cout
	mov	ax,di
	call	wout
	mov	si,#crlf
	call	say

	mov	bx,di
	call	dump_drvmap
#endif

	call	install_map		! install it

; 
; but first, process the two 0xFFFF drive-map records for "master-boot"
;
	mov	si,#drvmap		! our created drive map
	cmp	WORD (si),#-1		! test for "master-boot"
	jne	noswap
	mov	ah,[drive]		! boot drive
	mov	al,(si+3)		! possible "boot-as="
	cmp	al,#-1			! test for master
	jne	boot_as
! make AL the master drive (0 or 80)
	mov	al,ah
	and	al,#0x80		! AL is master drive 0 or 80
boot_as:
	mov	(si),ax		! 80 -> boot
	xchg	ah,al
	mov	(si+2),ax		! boot -> 80

	cmp	ah,al			! are they the same
	jne	domerge
	add	si,#4			! skip a "no-translation"
	mov	byte (si-1),#-1		! clear any boot-as
noswap:
domerge:

	mov	[devmap],si	! save updated value


;**************************************
	push	ss
	pop	es

	mov	cx,#SECTOR_SIZE/2
mtmp = SETUPSECS-1			! broken math ...
	mov	si,#mtmp*SECTOR_SIZE
#ifdef DEBUG_NEW
	mov	di,#boot_sector
	cmp	si,di
	ja	use_setupsecs_m_1
	mov	si,di
use_setupsecs_m_1:
#endif
	mov	di,bp			! #0x7C00
	rep
	  movsw
#ifdef DOS_D
#ifdef CHECK
	mov	si,#BOOTSEG*16+0x24	; address of first byte to test

	cmp	byte (bp+0x15),#0xf8		; check media descriptor
	jne	ck_failed

	seg	es
	  lodsb
	cmp	al,#0x80		; check range of device codes
	jb	ck_failed
	cmp	al,#0x8f
	ja	ck_failed

	seg	es
	  lodsb
	or	al,al			; check hi-byte is empty
	jnz	ck_failed

	seg	es
	  lodsb
	cmp	al,#0x29		; I do not know what this byte means
	je	ck_okay
	cmp	al,#0x28		; HPFS marker
	jne	ck_failed

ck_okay:
	lea	si,(si+4)		; address of vol label & fs type
	mov	cx,#11			; volume label (11)
ck_next:
	seg	es
	  lodsb
	or	al,al
	js	ck_failed		; not alphabetic if >= 0x80
	jz	ck_loop			; NUL allowed for HPFS
	cmp	al,#0x20
	jb	ck_failed		; not alphabetic if < SPACE
ck_loop:
	loop	ck_next

	mov	cx,#8			; check Filesystem type
ck_fstype:
	seg	es
	  lodsb
	or	al,al			; not alphabetic if >= 0x80
	js	ck_failed
	cmp	al,#0x20		; not alphabetic if < SPACE
	jb	ck_failed
	loop	ck_fstype

#endif
dos4:

	call	revmap1

	mov	(bp+0x24),dx		! fill in 0x24 and 0x25
	mov	si,offset
	mov	edx,ptable+8(si)
	mov	(bp+0x1C),edx

#ifdef DEBUG_NEW
	mov	si,#update
	jmp	ck_say   
ck_failed:
	mov	si,#no_update
ck_say:
	call	say
#else
ck_failed:
#endif

#endif
	mov	cx,#0x20		! move partition table
	mov	si,#ptable
	mov	di,#PART_TABLE
	rep
	movsw
					! mess with the partition table
#if defined(LCF_REWRITE_TABLE) && !defined(LCF_READONLY)
	mov	si,#prtmap		! get partition table change rules
prtclp:	lodsw				! bios == 0 indicates end
	or	al,al
	jz	pmend			! at end -> quit
	cmp	al,cache		! already in cache ?
	je	incache			! yes -> no loading required
	push	ax			! save table data
	call	flush			! flush the cache
	pop	ax
	push	ax
	mov	cache,al		! remember drive in cache
#if 0
	cmp	al,drive		! boot drive ?
#else
	call	revmap1
	cmp	al,dl
#endif
	jne	noc			! no -> load into scratch area
	xor	ax,ax			! load at 0000:0600
	mov	bx,#PARTS_LOAD
	jmp	loadit

pmend:	call	flush			! flush table
	br	nopp			! and proceed

noc:	mov	ax,ds
	mov	bx,#PARTS_SCR		! scratch area	0000:0800
loadit:	mov	es,ax			! set up pointers and remember them
	mov	ces,ax
	mov	cbx,bx
	mov	ax,#0x201		! load partition table, one sector
	mov	dx,cache		! drive from cache (DH = 0)
	mov	cx,#1
#ifdef DEBUG_NEW
	pusha
	mov	al,dl			! dump device code
	call	bout
	mov	si,#msg_load		! say loading
	call	say
	popa
#endif
	int	0x13			! load it
	jc	wrfail			! error -> abort
	pop	ax			! get BIOS and offset
incache:les	bx,cbx			! load pointer
	add	bx,#PART_TABLE_OFFSET	! move to partition table
	add	bl,ah			! offset is always in [0x1be,0x1fd]
	lodsw				! see what we need to do
	seg	es			! match ?
	cmp	byte ptr (bx),al
	jne	nocng			! no -> do not change
	seg	es			! change
	mov	byte ptr (bx),ah
	mov	byte ptr dirty,#1	! mark as dirty
nocng:	br	prtclp			! next one

flush:	test	byte ptr dirty,#1	! dirty ?
	jz	noflush			! no -> do not write
	mov	ax,#0x301		! write one sector
	mov	dx,cache		! get the drive
	or	dl,dl			! nothing cached ?
	jz	noflush			! no -> do not flush
	les	bx,cbx			! reload pointer
#ifdef DEBUG_NEW
	pusha
	mov	al,dl			! dump device code
	call	bout
	mov	si,#msg_write		! say writing
	call	say
	popa
#endif
	int	0x13			! write ...
	jc	wrfail			! argl
noflush:ret
wrfail:	mov	si,#failmsg		! complain
	call	say
#if 0
	mov	ax,#FIRSTSEG		! try to restart LILO
	jmpi	#GO,FIRSTSEG
#else
	xor	dx,dx			! zap the device code
	jmpi	FIRSTSEG*16,0		! try to restart at 0000:7c00
#endif
cache:	.byte	0			! drive, 0 means not cached
	.byte	0			! head, always 0
cbx:	.blkw	1
ces:	.blkw	1
dirty:	.byte	0

#endif

; reverse drive mapping
;	uses AX
;       updates DL
;
revmap1:
	push	si
	mov	dx,drive	; get drive/head pair
	mov	si,#drvmap
rev0:	lodsw			; get to, from pair
	or	ax,ax		; test for end
	jz	rev9		; done
	cmp	ah,dl		; booting from "to"
	jne	rev0		; loop if not
	mov	dl,al		; substitute the "from"
rev9:	pop	si		; restore SI
	ret

nopp:
#if 0
	mov	ax,drvmap		! need to install mapper ?
	or	ax,ax
	jz	noimap			! no -> go on
	call	swap13
noimap:
#else
	mov	di,[devmap]	! get drive map pointer
	cmp	word (di),#0
	je	noimap
	push	cs
	pop	es		; ES:DI points at the current map
	call	install_map
noimap:
#endif


#if REVERSE_DL
	call	revmap1
#else
	mov	dx,drive		! initialize DX (drive and head)
#endif
	mov	si,offset		! DS:SI and ES:SI point to the partition
	add	si,#PART_TABLE
#ifdef DEBUG_NEW
	pusha

	mov	cx,# 4<<4		; delay 4 seconds
	xor	dx,dx
	mov	ah,# 0x86
	int	0x15			! Delay 6 seconds
#ifdef DEBUG_CONTINUE
	jnc	delayed

	mov	si,#msg_cont		! Hit any key ...
	call	say
	xor	ax,ax
	int	0x16	! AH==0, get key
delayed:
#endif

	popa
#endif

	xor	ax,ax			! set DS and ES to zero
	mov	ds,ax
	mov	es,ax
	mov	bx,#BOOTSEG*16
	
;;;;	mov	ss,ax			! on all processors since the 186
	mov	sp,bx			! these instructions are locked
	
#ifdef LCF_COHERENT
	mov	(si),dl			! yes, put it in the partition table
#endif
	mov	bp,si			! BP==SI flags hard disk boot
	push	ax
	push	bx
	seg ss
	cmp	byte ptr (bx+par1_cli),#0xFA	! first.S starts with CLI
	je	try_sig
	cmp	byte ptr (bx+par1_cli),#0xEB	! short jump?
	jne	gotoit
	push	ax
	mov	al,(bx+par1_cli+1)		! get offset
	cbw
	inc	ax
	inc	ax
	add	bx,ax			! test relocated record
	pop	ax
	cmp	byte ptr (bx+par1_cli),#0xFA	! first.S starts with CLI
	jne	gotoit			! not LILO if no CLI
try_sig:
	seg ss
	  cmp	dword ptr (bx+par1_signature),#EX_MAG_HL
	jne	gotoit		! LILO signature required for command line
	seg cs
	  cmp	dword ptr [cmd],#0
	je	gotoit

;  pass on a command line
	seg cs
	  les	bx,[cmd]
	lea	si,(bx-4)
	seg es
	  mov	dword ptr (si),#EX_MAG_HL
	mov	dh,dl
	mov	dl,#EX_DL_MAG
gotoit:
	retf


#if defined(LCF_REWRITE_TABLE) || defined(DEBUG_NEW)

! Display a NUL-terminated string on the console
!	DS:SI points at the string
!
say:	push	ax
	push	bx		! save BX
say_2:	lodsb			! get byte
	or	al,al		! NUL ?
	jz	aret		! yes -> done
	mov	ah,#14		! display, tty-style
	mov	bx,#0007
	int	0x10
	jmp	say_2		! next one
aret:	pop	bx		! restore
	pop	ax
	ret			! done

failmsg:.ascii	"Rewrite error."
	.byte	13,10,0

#endif

;**************************************


; Merge the contents of two drive maps
;
;	First drive map encountered:	DS:SI
;	Second drive map encountered:	ES:DI
;	Output drive map:		DS:BX
;
; The output drive coincides with the First drive map
;
;	Enter with  DS != CS
;
;
;	
drive_map_merge:
	pusha				! save all the registers

;
; this is the guts of the loop to merge the records
;
process:
	lodsw				! get drive mapping
	or	ax,ax
	jz	copy

	push	di
	jmp	nextone1
nextone:
	inc	di
	inc	di
nextone1:
	seg es
	  cmp	word (di),#0
	je	atend

	seg es
	  cmp	(di),ah
	jne	nextone

	seg es
	  mov	ah,(di+1)		! do the translation
	seg es
	  mov	word (di),#-1		! wipe out entry
atend:
	cmp	ah,al			! remove null translation
	je	nostore
	mov	(bx),ax
	inc	bx
	inc	bx
nostore:
	pop	di
	jmp	process

; finished merge, copy the rest from the source
copy:
	seg es
	  mov	ax,(di)			!
	inc	di
	inc	di

	inc	ax
	jz	copy			! it was -1, skip it

	dec	ax
	mov	(bx),ax			! store value or end marker

	jz	alldone			! it was 0, end marker

	inc	bx
	inc	bx
	jmp	copy


alldone:
	popa			! restore all that we saved
	ret

; end of drive_map_merge

;**************************************

; Install a drive swapper with a null drive map
;
;	Enter with:
;		DS == CS, SS == 0000
;
;	Exit with:
;		ES:DI points at the null device map
;
;		EAX is trashed
;		All other registers preserved
;
;
swap13_null:
	push	cx
	push	si
#ifdef DEBUG_NEW
	call	sn11
	.asciz	"Installing Drive Swapper\r\n"
sn11:	pop	si
	call	say
#endif
	seg ss
	  dec	word [0x413]	; allocate 1k
	int	0x12
#if EBDA_EXTRA
	sub	ax,#EBDA_EXTRA	! allocate extra EBDA
#endif
	shl	ax,#10-4	; convert to paragraphs
	mov	es,ax		;
	xor	di,di		; DI = 0
	shl	eax,#16		; EAX is ES:DI
	seg ss
	  xchg	eax,[4*0x13]	; set new int 0x13 vector; get old
	mov	[old13of],eax
	mov	cx,#NEW13B/2	; count of words to move
	mov	si,#new13	; source is DS:SI
	rep
	  movsw			; move in the new drive mapper
	seg es
	  mov	(di),cx		; CX is zero from the move

	pop	si
	pop	cx
	ret

; Install drive mapper map
;
;	The map to use is at  ES:DI
;	If there is an existing drive mapper, the two are merged.
;	If there is no drive mapper, then one is installed.
;
;	Enter with  ES:DI  set to point at the map to install
;		DS == CS
;
;	Exit with  DS=CX
;		All registers are preserved
;

install_map:
	push	es
	pusha		; save all the regs
	mov	bp,sp	; save stack location

#ifdef DEBUG_NEW
	call	im111
	.asciz	"Install Map\r\n"
im111:	pop	si
	call	say
#endif

	seg es
	  cmp	word (di),#0
	je	install_ret	; nothing to do
COUNT	=  DRVMAP_SIZE*2
	mov	cx,#COUNT	; count of words
	sub	sp,#COUNT*2	; now allocate words
	mov	si,di		; ES:SI is now source
	mov	di,sp		; SS:DI is now destination

	push	ds

	push	es
	pop	ds
	push	ss
	pop	es
install_move1:
	lodsw			; get part of a map
	stosw			; store it
	or	ax,ax		; test for null
	jz	install_done1
	loop	install_move1
	jmp	fatal
install_done1:			; the map is at SS:SP
	pop	ds

#ifdef DEBUG_NEW
	mov	bx,sp		; ES==SS
	call	dump_drvmap
#endif

	call	is_prev_mapper	; is there a previous drive swapper
				; sets ES:DI
	jnz	install_skip

	call	swap13_null	; install a new, null drive mapper
				; sets ES:DI to point at  drvmap  in swapper
				; which must be NULL terminated
install_skip:
	mov	si,sp		; SS:SI is place to do the map merge
	push	ss
	pop	ds		; DS:SI is primary map
	mov	bx,si		; DS:BX receives the new map
				; and ES:DI points at the existing map
	call	drive_map_merge

#ifdef DEBUG_NEW
	mov	bx,sp
	push	es

	push	ss
	pop	es
	call	dump_drvmap

	pop	es
#endif
	mov	si,sp		; DS:SI is the source
	mov	cx,#COUNT
	rep
	  movsw

	push	cs
	pop	ds		; restore the DS

install_ret:
	mov	sp,bp	; get ready for pop
	popa
	pop	es
	ret

fatal:	hlt
	jmp	fatal

#ifdef DEBUG_NEW
wout:	push	ax
	xchg	ah,al
	call	bout		! write hi-byte
	pop	ax
bout:	push	ax		! save byte
	shr	al,#4		! display upper nibble
	call	nout
	pop	ax
nout:	and	al,#0x0F	! lower nible only
	daa			! smaller conversion routine
	add	al,#0xF0
	adc	al,#0x40	! AL is hex char [0..9A..F]
cout:
	push	bx
	mov	ah,#14		! display, tty-style
	mov	bx,#0007
	int	0x10
	pop	bx
	ret

msg_new:
	.ascii	"Found v.22 drive swapper"
	.byte	13,10,0
msg_old:
	.ascii	"Found v.21 drive swapper"
	.byte	13,10,0
msg_swap13:
	.ascii	"Drive Mapping"
	.byte	13,10,0
msg_load:
	.ascii	" - PT loaded"
	.byte	13,10,0
msg_write:
	.ascii	" - PT written"
	.byte	13,10,0
no_update:
	.ascii	"NO "
update:
	.ascii	"24-25 update has occurred"
crlf:	.byte	13,10,0

#ifdef DEBUG_CONTINUE
msg_cont: .ascii  "\r\nHit any key to continue ..."
	.byte	0
#endif

#endif	/* DEBUG_NEW */

#if 0
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
#endif

#ifdef DEBUG_NEW
; dump the drive map pointed to by  ES:BX
;	Beware: DS != CS on some calls
;
dump_drvmap:
	pusha
	push	ds

	push	cs
	pop	ds

sw13b:	seg es
	  mov	ax,(bx)		; get drvmap entry
	or	ax,ax
	jz	sw13z
	call	bout
	mov	si,#sw13p
	inc	bx
	call	say
	seg es
	  mov	al,(bx)
	call	bout
	inc	bx
	mov	si,#crlf
	call	say
	jmp	sw13b
sw13z:
	mov	si,#msg_swap13
	call	say

	pop	ds
	popa
	ret
sw13p:	.asciz	" -> "
#endif


#define CHAIN_LOADER
#include "mapper.S"

NEW13B	=   drvmap-new13

#if defined(LCF_REWRITE_TABLE)
prtmap:	.blkw	PRTMAP_SIZE*2+1	! only first word of last entry is read
#endif


#ifdef CHAIN
	.org	*+4
#endif
theend:

#ifdef CHAIN
the_end1	= theend+511
theends	=	the_end1/512
	.org	theends*512-4
	.long	CHAIN		! boot signature check
#endif
	.align	512
boot_sector:
