#if 0
/* second.S  -  LILO second stage boot loader */
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

#endif

/*#define DEBUG*/
#define REG_DUMP 1
/*#define DELL_DIRTY_HACK*/
#define PIXADDRESS
#define MEMORY_CHECK
#define RETAIN
#define DNAME 1

#define LILO_ASM
#include "lilo.h"
get common.s		/* as86 "include" will bypass the CPP */

#define MAP Map
#define MAP2 Map2
#define DFLCMD Dflcmd
#define DESCR Descr
#define KEYTABLE Keytable
#define PARMLINE Parmline

#define DEBUG_INITRD 0

#ifdef DEBUG
#define DEBUG_NEW 1
#else
#if VERSION_MINOR<50
#define DEBUG_NEW 0
#else
#define DEBUG_NEW 1
#ifndef MEMORY_CHECK
#define MEMORY_CHECK
#endif
#endif		/* VERSION_MINOR */
#endif		/* DEBUG */

/* The following is set to 1 to enable map file writing */
#if DEBUG_NEW
# define WR_ENABLE 2
# if VERSION_MINOR>=90
#  undef WR_ENABLE
#  define WR_ENABLE 1
# endif
#else
# define WR_ENABLE 1
#endif


#if DEBUG_NEW==0 && !(WR_ENABLE&1)
#error "Retail version should have WR_ENABLE=1"
#endif

/* if compiling READONLY, then WR_ENABLE should never be used */
#ifdef LCF_READONLY
# undef WR_ENABLE
#endif

#if	! NO_FS
#if DEBUG_NEW
#define CHECK_FS_VERBOSE 0
#define BEG_FS call fs_check
#else
#define BEG_FS
#endif
#define SEG_FS seg fs
#define END_FS
#else
#define BEG_FS db 0x1e,0x2e,0x8e,0x1e,0x02,0x00
/*	push ds; \
	seg cs; \
	mov	ds,firstseg */
#define SEG_FS
#define END_FS pop ds
#endif

/* get rid of the following to revert to old int 0x15/fn 0x88 mem scheme */
#define HIGHMEM_MAX 0x38000000

LOADSEG	= SYSSEG		; max kernel = 1024 sectors

#define UI_MAGIC 0xff		/* take input from keyboard */

#ifdef MENU
STAGE_MENU	=	STAGE_FLAG_MENU
X=MENU
#else
STAGE_MENU	=	0
#endif

#ifdef BITMAP
STAGE_BITMAP	=	STAGE_FLAG_BMP4
X=BITMAP
#else
STAGE_BITMAP	=	0
#endif

#ifdef LCF_NOSERIAL
STAGE_SERIAL	=	0
#else
STAGE_SERIAL	=	STAGE_FLAG_SERIAL
#endif

#ifdef TEXT
X=TEXT
#endif


	.text

	.globl	_main
	.org	0

_main:	jmp	start

#if	NO_FS || DEBUG_NEW
firstseg:	dw	0
# if	DEBUG_NEW
#  define CHECK_FS call fs_check
# else
# define CHECK_FS
# endif
#endif
#ifndef CHECK_FS
# define CHECK_FS
#endif

	.org	6

! Boot device parameters. They are set by the installer.

sig:		.ascii	"LILO"
version:	.word	VERSION
mapstamp:	.long	0

stage:		.word	STAGE_SECOND|STAGE_SERIAL|STAGE_MENU|STAGE_BITMAP

port:	.byte	0		; COM port (0 = unused, 1 = COM1, etc.)
sparam:	.byte	0		; serial port parameters (0 = unused)

timout: .word	0		; input timeout
delay:	.word	0		; boot delay
ms_len:	.word	0		; initial greeting message


kt_cx:	.word	0		; keyboard translation table
kt_dx:	.word	0
kt_al:	.byte	0

flag2:	.byte	0		; second stage specific flags


! GDT for "high" loading

	.align	16

gdt:	; space for BIOS
	.blkb	0x10
	; source
	.word	0xffff		; no limits
	.byte	0
	.word	LOADSEG>>4	; start: 0x10000
	.byte	0x93		; permissions
	.word	0		; padding for 80286 mode :-(
	; destination
	.word	0xffff		; no limits
	.word	0		; start - filled in by user
	.byte	0
	.byte	0x93		; permissions
	.word	0		; padding for 80286 mode :-(
	; space for BIOS
	.blkb	0x10

start:	cld			; only CLD in the code; there is no STD
#if   ! NO_FS
	push	ds
	pop	fs		; address parameters from here
#endif
#if	NO_FS || DEBUG_NEW
	seg	cs
	mov	firstseg,ds	; save DS here
#endif

	seg	cs
	mov	[init_dx],dx	; save DX passed in from first.S

	int	0x12		; get memory available
	CHECK_FS
#if EBDA_EXTRA
	sub	ax,#EBDA_EXTRA	; allocate extra EBDA
#endif
	shl	ax,#6		; convert to paragraphs
	sub	ax,#Dataend/16
	mov	es,ax		; destination address
	push	cs
	pop	ds
	xor	si,si
	xor	di,di
	xor	ax,ax
	mov	cx,#max_secondary/2	; count of words to move
	rep
	  movsw
	add	di,#BSSstart-max_secondary
	mov	cx,#BSSsize/2
	rep
	  stosw
	push	es
	push	#continue
	retf			; branch to continue address
continue:

#ifdef DELL_DIRTY_HACK
;;;	push	dx		; preserve DX (already saved)
	mov	ax,#0x1200	; enable video (VGA)
	mov	bl,#0x36	; (probably a nop on EGA or MDA)
	int	0x10		; video call
	CHECK_FS
;;;	pop	dx		; restore DX on Dell geforce nVidia card
#endif


#ifndef LCF_NOSERIAL
	call	serial_setup	; set up the COM port, if any
#endif

#ifndef LCF_NODRAIN
	mov	cx,#32		; drain type-ahead buffer ?
drkbd:	mov	ah,#1		; is a key pressed ?
	int	0x16
	jz	comcom		; no -> done
	xor	ah,ah		; get the key
	int	0x16
	loop	drkbd
#endif

comcom:
	CHECK_FS
	mov	al,#0x4c	; display an 'L'
	call	display
	push	#0		; get pointer to disk parameter table in DS:SI
	pop	ds
	lds	si,[0x78]	; 0x78 = 4*0x1E
#ifndef LCF_XL_SECS
	cmp	byte ptr (si+4),#9 ; okay ?
	ja	dskok		; yes -> do not patch
#endif
	push	cs		; get pointer to new area in ES:DI
	pop	es
	mov	di,#dskprm
	mov	cx,#6		; copy 12 bytes
	rep
	movsw
	seg	es		; patch number of sectors
#ifndef LCF_XL_SECS
	mov	byte ptr (di-8),#18
#else
	mov	byte ptr (di-8),#LCF_XL_SECS
#endif
	push	#0
	pop	ds
	cli			; paranoia
	mov	[0x78],#dskprm
	mov	[0x7a],es
	sti
dskok:
#ifndef	LCF_NOSERIAL
	seg	cs		; clear the break flag
	mov	byte ptr break,#0
#endif
	call	instto		; get timer interrupt
	CHECK_FS
;;;	jmp	restrt		; get going

! Restart here after a boot error

restrt: mov	bx,cs		; adjust segment registers
	mov	ds,bx
	mov	es,bx

	sub	bx,#MAX_SETUPSECS*0x20+0x20	; segment for setup code &
						;   bootsect
	mov	cx,#INITSEG
	cmp	bx,cx
	jbe	restrt1
	mov	bx,cx		; BX is the smaller segment #
restrt1:
	mov	word ptr [map],#MAP
	mov	[initseg],bx	; set up INITSEG (was 0x9000)
	lea	cx,(bx+0x20)
	mov	[setupseg],cx	; set up SETUPSEG (was 0x9020)
	mov	cx,cs
	sub	cx,bx		; subtract [initseg]
	shl	cx,#4		; get stack size
	mov	ss,bx		; must lock with move to SP below
	mov	sp,cx		; data on the stack)
#if DEBUG_NEW
	pusha

	mov	bx,#msg_where
	call	say
	mov	ax,[initseg]
	call	wout

	mov	ax,[setupseg]
	call	swout

	mov	ax,cs
	call	swout

	mov	ax,ss
	call	swout
	mov	al,#0x3A	; colon
	call	display
	mov	ax,sp
	call	wout

	mov	al,#32		; space
	call	display

	BEG_FS
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF+6]	; DH:DL as passed to first.S
	END_FS
	call	swout

	mov	ax,[init_dx]	; DX into second Stage
	call	swout

#ifdef LCF_NOKEYBOARD
	call	nkbdbg0
	.ascii " flags2="
	.byte	0
nkbdbg0: pop	bx
	call	say
	mov	al,[par2_flag2]
	call	bout
#endif

	call	crlf

#if REG_DUMP
	call	frd0
 .ascii "Registers at startup of first stage loader:\n"
 .ascii " AX   BX   CX   DX   SI   DI   BP   DS   ES\n"
	.byte	0
frd0:	pop	bx
	call	say

	BEG_FS	
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-2-4]	; AX
	call	wout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-8-4]	; BX
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-4-4]	; CX
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-6-4]	; DX
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-14-4]	; SI
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-16-4]	; DI
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-12-4]	; BP
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-18+16]	; DS
	call	swout
	SEG_FS		; external parameters ?
	mov	ax,[EX_OFF-20+16]	; ES
	call	swout
	END_FS

	call	crlf
#endif

	popa
#endif
	cmp	dword [sig],#EX_MAG_HL	; "LILO"
	jne	crshbrn2
	cmp	dword [mcmdbeg+6],#0x4547414d	; "MAGE"  from BOOT_IMAGE
	jne	crshbrn2
	cmp	BYTE [stage],#STAGE_SECOND
#if 1
	jne	crshbrn
	cmp	WORD [version],#VERSION
#endif
crshbrn2: jne	crshbrn
	mov	[cmdbeg],#acmdbeg	; probably unattended boot

	mov	di,#devmap	; place to store the device map
#ifdef LCF_FIRST6
	mov	ah,[init_dx]	; AH is physical device
	BEG_FS
	SEG_FS
	mov	al,[par1_secondary+0+SSDIFF]	; map device logical
	END_FS
#else
	mov	ax,[init_dx]	; AH is flags & device, AL is physical device
	xchg	ah,al
	and	ax,#DEV_MASK_asm<<8 | DEV_MASK_asm	; mask to pure device codes
#endif
	cmp	ah,al
	je	end_tt
#if DEBUG_NEW
	pusha
	call	wout		; TT entry, maybe
	call	crlf
	popa
#endif
	stosw			; set up the translation from map -> boot
end_tt:
	xor	ax,ax
	stosw

ldsc:
	BEG_FS
	SEG_FS
	mov	eax,[par1_mapstamp]
	END_FS
	cmp	eax,[par2_mapstamp]
	jne	timeerr

	call	kt_read		; read the KEYTABLE

	call	build_vol_tab

	mov	bx,#DESCR
	mov	si,#KEYTABLE+256+mt_descr
descr_more:
	lodsw	
	xchg	cx,ax
	lodsw
	xchg	dx,ax
	lodsb
	call	cread
	jc	near fdnok	; error -> retry
	add	bh,#2		; increment address
	cmp	si,#KEYTABLE+256+mt_descr+sa_size*MAX_DESCR_SECS_asm
	jb	descr_more

	mov	si,#DESCR	; compute a checksum of the descriptor table
	mov	di,#SECTOR_SIZE*MAX_DESCR_SECS-4

	push    dword #CRC_POLY1
	call	crc32
	add	di,si
	cmp	eax,dword (di)
	jz	nochkerr


! Timestamp error
timeerr:
	mov	bx,#msg_time
	jmp	zz

! Checksum error
chkerr:
	mov	bx,#msg_chkerr
	jmp	zz		; go wait

crshbrn:
	mov	bx,#msg_sigerr	; signature not found
zz:	call	say
zzz:	hlt			; wait for interrupt
	jmp	zzz		; sit here forever


nochkerr:
#ifdef DEBUG
	pusha
	mov	bx,#nochker_msg
	call	say
	popa
	jmp	nochkerr1
nochker_msg:
	.ascii	"Descriptor checksum okay\n"
	.byte	0
nochkerr1:
#endif
#ifdef LCF_VIRTUAL
; remove those items that have "vmdisable", if virtual boot
	call	vmtest
	jnc	virtual_done
	mov	di,#DESCR0	; point at first descriptor
vir_loop:
	test	byte ptr [id_name](di),#0xFF	; test for NUL name
	jz	virtual_done
	test	word ptr [id_flags](di),#FLAG_VMDISABLE
	jz	vir_skip

	push	di
	lea	si,[id_size](di)
vir_loop1:
	mov	cx,#id_size
	rep
	   movsb
	test	byte ptr [id_name](di),#0xFF
	jnz	vir_loop1

	pop	di
	jmp	vir_loop

vir_skip:
	add	di,#id_size
	jmp	vir_loop

virtual_done:
#endif
#ifdef LCF_NOKEYBOARD
; remove those items that have "nokbdisable", if nokeyboard boot
	call	kbtest
	jc	kbd_done
	mov	di,#DESCR0	; point at first descriptor
kbd_loop:
	test	byte ptr [id_name](di),#0xFF	; test for NUL name
	jz	kbd_done
	test	word ptr [id_flags](di),#FLAG_NOKBDISABLE
	jz	kbd_skip

	push	di
	lea	si,[id_size](di)
kbd_loop1:
	mov	cx,#id_size
	rep
	   movsb
	test	byte ptr [id_name](di),#0xFF
	jnz	kbd_loop1

	pop	di
	jmp	kbd_loop

kbd_skip:
	add	di,#id_size
	jmp	kbd_loop

kbd_done:
#endif

#if defined(MENU) || defined(BITMAP)
	xor	bx,bx		; defaults are all zero
	mov	[dimage],bx	; set default image to boot
	mov	[abs_cx],bx	; upper left of scroll area
				; means screen is not cleared
#endif

	mov	bx,#KEYTABLE+256
	mov	al,(bx+mt_flag)
	BEG_FS
	SEG_FS		; get possible FLAG_NOBD
	or	byte ptr [par1_prompt+SSDIFF],al
	END_FS
#ifdef MENU
	call	title_stuff
#endif
	mov	bx,#DFLCMD
;BEG_FS
;SEG_FS
	mov	cx,mt_dflcmd+KEYTABLE+256		;DFCMD_OFF
;SEG_FS
	mov	dx,mt_dflcmd+2+KEYTABLE+256
;SEG_FS
	mov	al,mt_dflcmd+4+KEYTABLE+256
;END_FS
	call	cread
	jc	fdnok		; error -> retry
	mov	bx,#DFLCMD
	cmp	word ptr (bx),#DC_MAGIC ; okay ?
	jne	bdcmag		; no -> do not write
#ifndef LCF_READONLY
	mov	word ptr (bx),#DC_MGOFF ; erase the magic number
	call	cmd_write	; write out the command line
#if 0
; 22.6.2 -- removed, because this is worse that the first
; command lock bug
	mov	si,#DESCR0
	lea	di,(bx+2)
	mov	cx,#16
	rep
	 movsb
; 22.6.2
#endif

#endif
	jmp	dokay		; continue
bdcmag:	mov	byte ptr (bx+2),#0 ; disable the command line
	jmp	dokay		; go on
fdnok:	
#if     0
        xor	ax,ax		; reset FDC
	mov	dl,al
	int	0x13
#endif
	br	ldsc		; retry

! List all known boot images

list:	mov	byte ptr (bx),#0 ; set EOL marker
	call	crlf
#ifdef MENU
	inc	word [suppress]	; suppress console output
#endif
	mov	si,#DESCR0	; list all images
	mov	cx,#IMAGES
	xor	dl,dl		; DL counts the images
lloop:	testb	(si),#0xff	; done ?
	jz	ldone		; yes
	mov	bx,si		; display the name
	call	say
	add	si,#MAX_IMAGE_NAME+4
	inc	dl		; count the image
	test	dl,#3		; inside line -> go on
	jnz	fill
	call	crlf
	jmp	imgdne		; next image
fill:	push	bx		; fill with spaces
	mov	al,#0x20
	call	display
	pop	bx
	inc	bx
	cmp	bx,si
	jbe	fill
imgdne:	add	si,#id_size-MAX_IMAGE_NAME-4
	loop	lloop		; next image
ldone:	test	dl,#3		; already at BOL ?
	jz	atbol		; yes -> no CRLF
	call	crlf
atbol:	
#ifdef MENU
	dec	word [suppress]
#endif
	br	iloop		; done

! Ready to process user input

dokay:	mov	bx,#ospc	; display 'O '
	call	say
/* ifdef HIGHMEM_MAX */
	xor	eax,eax
	mov	dword ptr [hma],eax
/* #endif */
	mov	ospc,al		; disable the message
	mov	word ptr vgaovr,#VGA_NOCOVR ; disable VGA override
;;	BEG_FS
;;	SEG_FS
	xchg	ax,par2_delay		;DSC_OFF-8+SSDIFF
;;	END_FS
	or	old_del,ax	; remember delay
	mov	nodfl,#iloop	; interactive prompt if falling through
#ifdef LCF_NOKEYBOARD
	call	kbtest		; keyboard present?
#ifndef LCF_NOSERIAL
	jc	kbd_present
; no PC keyboard on the system, is there a serial port in use?
	cmp	byte ptr [par2_port],#0
	jz	skip_prompt	; no serial keyboard either
#else
	jnc	skip_prompt	; skip check for prompt if no keyboard
#endif
kbd_present:
#endif
	BEG_FS
	SEG_FS		; enter boot prompt ?
	test	byte ptr par1_prompt+SSDIFF,#FLAG_PROMPT	;DSC_OFF+15+SSDIFF,#0
	END_FS
	jnz	extp		; yes -> check for external parameters
skip_prompt:
	mov	nodfl,#bfirst	; boot first image if falling through
	call	waitsh		; wait for a shifting key
	jc	iloop		; key pressed -> enter interactive mode

! Check for external parameters

extp:	BEG_FS
	SEG_FS		; external parameters ?
	cmp	byte ptr EX_OFF+6,#EX_DL_MAG
	END_FS
	jne	noex		; no -> go on
	BEG_FS
	SEG_FS
	mov	bl,EX_OFF+7	; get drive
	SEG_FS		; clear flag
	mov	byte ptr EX_OFF+6,bl	; clear flag
	SEG_FS		; load the signature pointer
	les	bx,EX_OFF
	END_FS
	seg	es
	cmp	dword ptr (bx),#EX_MAG_HL	; "LILO"
	jne	noex		; no -> go on
	BEG_FS
	SEG_FS
	mov	si,EX_OFF+4	; pointer to the command line
	END_FS
	seg	es
	cmp	byte ptr (si),#0 ; empty ?
	je	iloop		; yes -> enter interactive mode
	jmp	niloop		; enter non-interactive mode

! No external parameters after timeout -> boot first image

noex:	push	cs		; restore ES
	pop	es
	mov	si,#DFLCMD+2	; default command line ?
	cmp	byte ptr (si),#0
	jne	niloop		; yes -> use it
	mov	ax,nodfl	; no idea how to tell as86 to do jmp (addr) :-(
	jmp	ax		; fall through


; Command input processor

iloop:
#if defined(MENU) || defined(BITMAP)
	call	menu_setup
#endif

#ifndef BITMAP
;;	BEG_FS
;;	SEG_FS		; message disabled ?
	cmp	word ptr par2_msg_len,#0		;MSG_OFF+SSDIFF,#0
;;	END_FS
	je	nomsg		; yes -> skip this
	call	crlf
;BEG_FS
;SEG_FS		; load the message file
	mov	cx,mt_msg+KEYTABLE+256			;MSG_OFF+SSDIFF+2
;SEG_FS
	mov	dx,mt_msg+2+KEYTABLE+256
;SEG_FS
	mov	al,mt_msg+4+KEYTABLE+256
;END_FS
	mov	bx,[map]
	call	sread
	call	loadfile

	xor	bx,bx		; set the terminating NUL and disable further
				; messages
	xchg	bx,par2_msg_len		;MSG_OFF+SSDIFF

	push	#SYSSEG
	pop	ds
	mov	byte ptr (bx),#0
	xor	bx,bx		; display the message
	call	say

	push	cs		; restore segment registers
	pop	ds
#endif

nomsg:	push	cs		; disable external parameters
	pop	es

	mov	cmdbeg,#acmdbeg	; probably unattended boot
	mov	si,#usrinpm	; interactive mode
niloop:				; ES may point to external params
	mov	bx,#msg_p	; display boot prompt
	call	say
	mov	bx,#cmdline	; move cursor to the end of the line
clend:	mov	al,(bx)
	or	al,al		; at end ?
	jz	cledne		; yes -> go on
	push	bx		; display the character
	call	display
	pop	bx
	inc	bx		; next one
	jne	clend
cledne:	mov	byte ptr prechr,#32 ; character before command line is a space

! Input loop

input:	seg	es		; interactive mode ?
	cmp	byte ptr (si),#UI_MAGIC
	je	kbinp		; yes -> get keyboard input
	seg	es		; get non-interactive input
	mov	al,(si)
	inc	si
	jmp	gotinp		; go on
	
tolist:
#ifdef BITMAP
	call	menu_exit
#endif
	br	list		; ...

kbinp:	
	mov	cx,#brto	; get a key
	call	getkey
#ifdef BITMAP
	cmp	byte [abs_cx+1],#0
	je	noNull		; skip cursor keys after Tab
#endif
#if defined(MENU) || defined(BITMAP)
	cmp	al,#0xE0	; extended keyboard
	je	toNull
	or	al,al		;
toNull:	je	near null	; cursor control
#endif
#ifndef MENU
noNull:	or	al,al		; keyboard NUL input?
	je	input		; yes, skip Keyboard NUL
; stored command line NUL is handled differently
#endif
gotinp:	cmp	al,#9		; TAB ?
	je	tolist		; yes -> list images
	cmp	al,#63		; "?" ?
	je	tolist		; yes -> list images
	or	al,al		; NUL ?
	je	nul		; yes -> go on
	cmp	al,#8		; BS ?
	je	todelch		; yes -> erase one character
	cmp	al,#13		; CR ?
	je	cr		; yes -> go on
	cmp	al,#127		; DEL ?
	je	todelch		; yes -> erase one character
	ja	input		; non-printable -> ignore it
	cmp	al,#21		; ^U ?
	je	todell		; yes -> erase the line
	cmp	al,#24		; ^X ?
	je	todell		; yes -> erase the line
	cmp	al,#32		; ignore non-printable characters except space
	jb	input
	ja	noblnk		; no space -> go on
	cmp	(bx-1),al	; second space in a row ?
	je	input		; yes -> ignore it
noblnk:	cmp	bx,#cmdline+CL_LENGTH-1 ; at end of buffer ?
	je	input		; yes -> ignore
	xor	ah,ah		; cmdline is always NUL terminated
	mov	(bx),ax		; store in the buffer
	inc	bx		; increment pointer
	push	bx
	call	display		; echo
#if defined(MENU) || defined(BITMAP)
	push	ax
	call	find_image	; we want the side effect of the hilite
	pop	ax
#endif
	pop	bx
	cmp	bx,#cmdline+1	; first character ?
	jne	input		; no -> next input
#ifdef LCF_IGNORECASE
	call	upcase		; convert to upper case
#endif
	mov	cx,#IMAGES	; check if we have a single-key entry
	mov	di,#DESCR0
	mov	ah,al
sklp:	test	word ptr (di+id_flags),#FLAG_SINGLE ; single-key entry ?
	jz	sknext		; no -> try next
	mov	al,(di)		; get first character
#ifdef LCF_IGNORECASE
	call	upcase		; convert to upper case
#endif
	cmp	al,ah		; do we have a match ?
	jne	sknext		; no -> try next
	cmp	byte ptr (di+1),#0 ; at end ?
	je	cr		; yes -> run it
sknext:	add	di,#id_size	; test next entry
	loop	sklp		; next one
	br	input		; done -> get more input

todelch:br	delch		; ...
todell:	br	delline		; ...

! End of input, process the command line

nul:	push	bx		; automatic boot - wait for timeout
	mov	ax,old_del
	call	waitsh
	pop	bx
	jnc	crnul		; no key pressed -> continue
	mov	bx,#msg_int	; interrupted -> display a message
	call	say
	mov	byte ptr cmdline,#0	; clear the command line
	br	iloop		; return to interactive prompt

cr:
;;22.7	mov	word par2_timeout,#0xffff	; kill timeout
#ifdef LCF_HP_TTRC
	push	ax		; HP TTRC boot fail workaround.
	mov	ax, #3		; 2000/10 <yumoto@jpn.hp.com>
	call	setto		; reload timer
short_wait:
	test	byte ptr timeout,#1 ; timed out ?
	jz	short_wait	; No, remain loop..
	pop	ax
#endif
	mov	cmdbeg,#mcmdbeg ; probably manual boot
crnul:
#ifndef LCF_NOSERIAL
	mov	byte ptr break,#0 ; clear the break flag
#endif
	push	cs		; set ES to CS
	pop	es
	xor	al,al		; mark end
	mov	(bx),al
	mov	si,#cmdline	; copy command line to save buffer
	mov	di,#lkcbuf
	mov	byte ptr dolock,#0 ; disable locking

cpsav:	lodsb			; copy one byte
	stosb
	or	al,al		; at end ?
	jnz	cpsav		; no -> go on

	cmp	bx,#cmdline	; empty line ?
	je	notrspc		; yes -> boot first image
	cmp	byte ptr (bx-1),#32 ; trailing space ?
	jne	notrspc		; no -> go on
	dec	bx		; remove the space
	mov	byte ptr (bx),al
notrspc:mov	si,#cmdline	; scan the command line for "vga=", "kbd=",
	mov	di,si		; "lock" or "mem="
chkvga:

#ifdef LCF_BDATA
vsktnbd:
	cmp	dword ptr (si),#0x64626f6e	; "nobd"
	jne	vsktv
	cmp	byte (si+4),#32			; terminated with SP or NUL?
	jnbe	vsktv
	BEG_FS
	SEG_FS		; enter boot prompt ?
	or	byte ptr par1_prompt+SSDIFF,#FLAG_NOBD	; suppress BIOS data collection
	END_FS
	jmp	vskwd		; skip word
#endif
vsktv:
	cmp	dword ptr (si),#0x3d616776	; "vga="
	jne	vsktk
	call	setvga		; set VGA mode
	jc	near iloop	; error -> get next command
	jmp	vskdb		; proceed by discarding last blank
vsktk:
	cmp	dword ptr (si),#0x3d64626b	; "kbd="
	jne	vsktl
	call	putkbd		; pre-load keyboard buffer
	jmp	vskdb		; proceed by discarding last blank
vsktl:
	cmp	dword ptr (si),#0x6b636f6c	; "lock"
	jne	vsktm
	cmp	byte (si+4),#32		; space?
	jnbe	vsktm
	mov	byte ptr dolock,#1 ; enable locking
vskwd:	add	si,#4		; skip word
vskdb:	dec	di		; discard last blank
	jmp	vsknb		; continue
vsktm:
#if DEBUG_INITRD
	cmp	dword ptr (si),#0x3d647269	; "ird="
#else
	cmp	dword ptr (si),#0x3d6d656d	; "mem="
#endif
	jne	vsknb
	call	getmem		; get the user-provided memory limit
vsknb:
	lodsb			; copy one byte
	stosb
	cmp	al,#32		; space ?
	je	chkvga		; yes -> look for options again
	or	al,al		; at end ?
	jnz	vsknb		; no -> go on
	call	crlf		; write CR/LF
	cmp	di,#cmdline+1	; empty line ?
emptyl:	je	bfirst		; yes -> boot first image
	jmp	bcmd		; boot the specified image

! Find the boot image and start it

bcmd:
	call	find_image
	jc	near boot	; eureka, it was found

	mov	bx,#msg_nf	; not found -> display a message
	call	say
	br	iloop		; get more input

! Delete one character

delch:	cmp	bx,#cmdline	; at the beginning ?
	je	toinput		; yes -> do nothing
	dec	bx		; move the pointer
	push	bx		; display[B BS,SPC,BS
	mov	bx,#bs
	call	say
#if defined(MENU) || defined(BITMAP)
	pop	bx
	push	bx
	mov	byte (bx),#0	; NUL terminate the line
	mov	ax,#cmdline
	sub	ax,bx
	jz	delch6
	call	find_image
	jmp	delch9

delch6:
#if defined(LCF_VIRTUAL) || defined(LCF_NOKEYBOARD)
	mov	ax,[vimage]
#endif
	mov	bx,[dimage]
	cmp	ax,bx
	je	delch9
	xchg	ax,bx
	call	lowlite
	xchg	ax,bx
	call	hilite
delch9:
#endif
	pop	bx
toinput:br	input		; go on

! Delete the entire line

delline:
#if !defined(MENU) && !defined(BITMAP)
	cmp	bx,#cmdline	; done ?
	je	toinput		; yes -> go on
	push	bx		; display BS,SPC,BS
	mov	bx,#bs
	call	say
	pop	bx
	dec	bx		; move the pointer
	jmp	delline		; next one
#else
	call	menu_delline
	push	bx		; delch will do a pop
	xor	ax,ax
	jmp	delch6
#endif

! Boot first after timeout

brto:	call	crlf		; display a CRLF
	jmp	brfrst		; boot

! Boot the first image

bfirst:	mov	byte ptr lkcbuf,#0  ; clear default
	cmp	byte ptr cmdline,#0 ; is there a default ?
	jne	bcmd		; yes -> boot that image
brfrst:	
	mov	bx,#DESCR0	; boot the first image

#if defined(LCF_VIRTUAL) && defined(LCF_NOKEYBOARD)
	xor	ax,ax		; mask = 0
	call	vmtest
	jnc	brfrst0v	; not virtual
	mov	ax,#FLAG_VMDEFAULT
brfrst0v:
	call	kbtest
	jc	brfrst0k
	mov	ax,#FLAG_NOKBDEFAULT
brfrst0k:

	mov	cx,#IMAGES
brfrst1: test	word ptr (bx+id_flags),ax
	jnz	brfrst3
	add	bx,#id_size
	loop	brfrst1 

	mov	bx,#DESCR0	; restore default
brfrst3:
#else
#ifdef LCF_VIRTUAL
	call	vmtest
	jnc	brfrst3		; not virtual, boot BX

	mov	cx,#IMAGES
brfrst1: test	word ptr (bx+id_flags),#FLAG_VMDEFAULT
	jnz	brfrst3
	add	bx,#id_size
	loop	brfrst1 

	mov	bx,#DESCR0	; restore default
brfrst3:
#endif	/* LCF_VIRTUAL */
#ifdef LCF_NOKEYBOARD
	call	kbtest
	jc	brfrst3k		; not virtual, boot BX

	mov	cx,#IMAGES
brfrst1k: test	word ptr (bx+id_flags),#FLAG_NOKBDEFAULT
	jnz	brfrst3k
	add	bx,#id_size
	loop	brfrst1k

	mov	bx,#DESCR0	; restore default
brfrst3k:
#endif	/* LCF_NOKEYBOARD */

#endif /* if !both */

	mov	si,bx		; copy the name to the command line
	mov	di,#cmdline
bfcpl:	lodsb			; copy one character
	mov	(di),al
	inc	di
	or	al,al		; NUL ?
	jnz	bfcpl		; no -> next one

! Boot the image BX points to (with password check)

boot:
	mov	word par2_timeout,#0xffff	; kill timeout  (22.7)
	mov	si,#cmdline	; locate start of options
locopt:	lodsb
	or	al,al		; NUL ?
	je	optfnd		; yes -> no options
	cmp	al,#32		; space ?
	jne	locopt		; no -> continue searching
	cmp	byte ptr (si),#0 ; followed by NUL ?
	jne	optfnd		; no -> go on
	mov	byte ptr (si-1),#0 ; discard trailing space
optfnd:	dec	si		; adjust pointer
	mov	options,si	; store pointer for later use
#ifdef BITMAP
#ifdef RETAIN
	test	word ptr [id_flags](bx),#FLAG_RETAIN	; keep bitmap?
	jz	bmp_terminate
	xor	ax,ax		; time out immediately
	call	waitsh		; check for break (Shift, Alt, ScrollLock,...)
	jnc	bmp_retain
bmp_terminate:
#endif
	call	menu_exit
bmp_retain:
#endif

#ifdef LCF_VIRTUAL
	test	word ptr [id_flags](bx),#FLAG_VMWARN
	jz	boot9
	call	vmtest		; 'vmwarn' there, is it actually virt. boot
	jnc	boot9
; VMWARN set, and is virtual boot, so issue comment
;;	BEG_FS
;;	SEG_FS
	mov	word ptr par2_timeout,#0xffff	; cancel timeout
;;	END_FS

	push	bx		; save image descriptor ptr
	mov	bx,#msg_vmwarn
	call	say
	mov	cx,#vmwto	; timeout exit
	call	getkey

	push	ax
	cmp	al,#0x20	; compare to Space
	jb	boot3		; no echo if ctrl char
	call	display		; echo
boot3:	call	crlf
	pop	ax

	pop	bx		; restore image descriptor ptr
	cmp	al,#0x79	; y is yes
	je	boot9
	cmp	al,#0x59	; Y is yes
	je	boot9

vmwto:
	br	iloop

boot9:
#endif
	test	byte ptr (bx+id_flags),#FLAG_PASSWORD	; use a password
	jz	toboot		; no -> boot
	test	byte ptr (bx+id_flags),#FLAG_RESTR	; restricted ?
	jz	dopw		; no -> get the password
	cmp	byte ptr (si),#0 ; are there any options ?
	jne	dopw		; yes -> password required
toboot:	br	doboot		; ...
dopw:
#if defined(CRC_PASSWORDS) || defined(SHS_PASSWORDS)
	push	bx		; save the image descriptor
;;	BEG_FS
;;	SEG_FS
	mov	word ptr par2_timeout,#0xffff	; cancel timeout
;;	END_FS
	mov	bx,#msg_pw	; display a prompt
	call	say

	push	bp		; save BP
	mov	bp,sp		; save SP in BP
	sub	sp,#CL_LENGTH	; allocate space for PW string
	mov	si,sp		; si points at string
	xor	di,di		; di counts characters
pwloop:
#ifdef DEBUG
	pusha
	mov	ax,si
	call	wout
	mov	al,#32
	call	display
	mov	ax,di
	call	wout
	call	crlf
	popa
#endif
	mov	cx,#pwtime	; get timeout exit
	call	getkey
	
	cmp	al,#13		; CR ?
	je	pwcr		; yes -> handle it
	cmp	al,#21		; ^U ?
	je	pwdell		; yes -> erase line
	cmp	al,#24		; ^X
	je	pwdell
	cmp	al,#8		; BS ?
	je	pwdelch		; yes -> erase one character
	cmp	al,#127		; DEL
	je	pwdelch
	ja	pwloop		; ignore other non-printable characters
	cmp	al,#32
	jb	pwloop

	cmp	di,#CL_LENGTH	; check for buffer overflow
	jae	pwloop		; ingnore further input
	seg	ss
	mov	(si),al		; store char in buffer
	inc 	si
	inc	di
	mov	al,#42		; echo '*'
	call	display
	jmp	pwloop		; loop back for more

pwdelch: or	di,di
	jz	pwloop 
	call	pwbs
	dec	si
	dec	di
	jmp	pwloop

pwdell:	inc	di
pwdel:	dec	di
	jz	pwloop
	call	pwbs
	dec	si
	jmp	pwdel

pwbs:	mov	bx,#bs
	call	say
	ret

pwcr:	
	xor	cx,cx		; signal okay
pwtime:				; CX != 0 if enter here
	inc	cx
	call	crlf

	sub	si,di		; point SI at start of buffer
	push	es		; save ES

#if !defined(SHS_PASSWORDS)
	mov	bx,(bp+2)	; restore image descriptor pointer
	push	ss
	pop	es		; ES:SI points at char string

#if MAX_PW_CRC>=1
	push    dword #CRC_POLY1
	call	crc32
#ifdef DEBUG
	pusha
	push	ax
	mov	ax,di
	call	wout
	mov	al,#32
	call	display
	pop	ax

	push	eax
	call	dout
	call	crlf
	popa
#endif

	cmp	eax,(bx+id_password_crc)
	jne	pwcleanup
#endif

; insert other checks in here
#if MAX_PW_CRC>=2
	push    dword #CRC_POLY2
	call	crc32
	cmp	eax,(bx+id_password_crc+4)
	jne	pwcleanup
#endif

#if MAX_PW_CRC>=3
	push    dword #CRC_POLY3
	call	crc32
	cmp	eax,(bx+id_password_crc+8)
	jne	pwcleanup
#endif

#if MAX_PW_CRC>=4
	push    dword #CRC_POLY4
	call	crc32
	cmp	eax,(bx+id_password_crc+12)
	jne	pwcleanup
#endif

#if MAX_PW_CRC>=5
	push    dword #CRC_POLY5
	call	crc32
	cmp	eax,(bx+id_password_crc+16)
	jne	pwcleanup
#endif
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	dec	cx			; signal all okay
#else		/* SHS_PASSWORDS */
; DI is the count
; SS:SI is the password string
	push	di
	push	si
	call	_shsInit
	call	_shsUpdate
	call	_shsFinal
	mov	bx,(bp+2)	; restore image descriptor pointer
	lea	di,(bx+id_password_crc)
	mov	si,#shs_digest
	mov	cx,#MAX_PW_CRC*4
; ES==DS
	repe
	    cmpsb

	pop	si		; restore buffer ptr
	pop	di		; clear stack
	push	ss
	pop	es		; ES=SS

	je	pwcleanup	; CX will be 0
	inc	cx		; CX is > 0
#endif		/* !defined(SHS_PASSWORDS) */

pwcleanup:
	push	cx
	mov	cx,#CL_LENGTH
	mov	di,si
	xor	ax,ax
	rep			; wipe out password in memory
	    stosb
	pop	cx
	pop	es		; restore the saved ES

	mov	sp,bp
	pop	bp
	pop	bx
	or	cx,cx		; test CX==0 means all okay
	jz	doboot
; fall into pwfail	

#else
	push	bx		; save the image descriptor
	lea	si,(bx+MAX_IMAGE_NAME+1) ; get a pointer to the password string
	mov	bx,#msg_pw	; display a prompt
	call	say
pwagain:xor	cl,cl		; CL counts characters after a mismatch
pwloop:	push	cx		; get a key
	mov	cx,#pwtime
	call	getkey
	pop	cx
	cmp	al,#13		; CR ?
	je	pwcr		; yes -> handle it
	cmp	al,#21		; ^U ?
	je	pwdell		; yes -> erase line
	cmp	al,#24		; ^X
	je	pwdell
	cmp	al,#8		; BS ?
	je	pwdelch		; yes -> erase one character
	cmp	al,#127		; DEL
	je	pwdelch
	ja	pwloop		; ignore other non-printable characters
	cmp	al,#32
	jb	pwloop
	or	cl,cl		; counting bad input ?
	jnz	pwbad		; yes -> do it
	cmp	al,(si)		; correct input ?
	je	pwgood		; yes -> go on
pwbad:	inc	cl		; count error
	jnz	pwgood		; no overflow -> go on
	dec	cl		; adjust it
	jmp	pwcr		; terminate input
pwgood:	inc	si		; good character -> go on
	jmp	pwloop
pwdell:	pop	si		; reset the pointer
	push	si
	add	si,#MAX_IMAGE_NAME+1
	jmp	pwagain		; get password again
pwdelch:pop	bx		; at the beginning of the line ?
	push	bx
	add	bx,#MAX_IMAGE_NAME+1
	cmp	si,bx
	je	pwloop		; yes -> ignore it
	dec	si		; remove one character
	sub	cl,#1
	jnc	pwloop		; no underflow -> go on
	inc	cl		; adjust it
	jmp	pwloop		; next character
pwtime:	pop	cx		; drop CX ...
	mov	cl,#1		; ... and fail
pwcr:	call	crlf
	pop	bx		; restore the image descriptor
	or	cl,cl		; no errors ?
	jnz	pwfail		; no -> fail
	cmp	byte ptr (si),#0 ; at end ?
	je	doboot		; yes -> continue booting
#endif	/* CRC_PASSWORDS */

pwfail:	mov	bx,#msg_pf	; display an error message
	call	say
	br	iloop		; get next input

! Boot the image BX points to

doboot:	mov	byte ptr prechr,#61 ; switch to equal sign
	push	bx		; save image descr
	mov	bx,#msg_l	; say hi
	call	say
	pop	bx		; display the image name
	push	bx
	call	say
	pop	si

	push	si
	add	si,#id_start	; form address
	
;  Now load the kernel sectors
	xor	ax,ax
	mov	word ptr (gdt+0x1b),ax ; set GDT to "load low"
	mov	byte ptr (gdt+0x1f),al
	mov	moff,ax		; map is not loaded yet

	lodsw			; address of the first map sector
	xchg	cx,ax
	lodsw
	xchg	dx,ax
        lodsb

	push	si		; save SI

#ifdef DEBUG
        push    ax              ;
	mov bx,#step0
	call say
        pop     ax              ;
#endif
	mov	bx,[map]		; load the first map sector
	call	sread
#ifdef DEBUG
	mov bx,#step0b
	call say
#endif
	mov	bx,#DFLCMD	; load the default command line
;BEG_FS
;SEG_FS
	mov	cx,mt_dflcmd+KEYTABLE+256
;SEG_FS
	mov	dx,mt_dflcmd+2+KEYTABLE+256
;SEG_FS
	mov	al,mt_dflcmd+4+KEYTABLE+256
;END_FS
	call	cread
	push	word ptr (DFLCMD) ; push magic number
	mov	bx,#DFLCMD	; load the fallback sector
	call	load1
	pop	ax		; valid magic number ?
#ifndef LCF_READONLY
	cmp	ax,#DC_MAGIC
	je	dclok		; yes -> can write
	cmp	ax,#DC_MGOFF
	jne	nofbck		; invalid -> must not write
dclok:	mov	bx,#DFLCMD	; fallback data present ?
	cmp	word ptr (bx),#DC_MAGIC
	jne	nofbck		; no -> go on
	call	cmd_write	; write out the command line
nofbck:
#endif
#ifdef DEBUG
	mov bx,#step1
	call say
#endif
	mov	bx,#DFLCMD	; load the options sector
	call	load1
	mov	si,cmdbeg	; copy non-options part of command line
	mov	di,#PARMLINE
	mov	cx,#CL_LENGTH-1	; max number of characters to copy

cpnocl:	
#if DNAME
	cmp	si,#cmdline
#else
	cmp	si,options	; at beginning of options ?
#endif
	je	cpnodn		; yes -> go on
	movsb			; copy one byte
	loop	cpnocl		; next one
	jmp	cpovfl		; signal overflow

cpnodn:	
#if DNAME
	pop	ax		; get saved pointer
	pop	si		; get saved descriptor
	push	si
	push	ax
cpdname:
	lodsb
	or	al,al
	jz	cpdname9
	stosb
	dec	cx
	jmp	cpdname
cpdname9:	
#endif
	mov	si,#DFLCMD	; constant options ?
	cmp	byte ptr (si),#0
	je	nocopt		; no -> go on
	mov	al,#32		; add a space
	stosb
	dec	cx		; count character
	jz	cpovfl
cpcodsp:
#if DEBUG_INITRD
	cmp	dword ptr (si),#0x3d647269	; "ird="
#else
	cmp	dword ptr (si),#0x3d6d656d	; "mem="
#endif
	jne	cpnotmem
	call	getmem		; get the user-provided memory limit
cpnotmem:
	lodsb			; fetch next byte
	cmp	al,#32		; space ?
	je	cpcodsp		; yes -> discard it
cpcolp:	or	al,al		; NUL ?
	jz	cpcodn		; yes -> done
	stosb			; store byte
	dec	cx		; count character
	jz	cpovfl
	cmp	al,#32		; a space ?
	je	cpcodsp		; yes -> discard next
	lodsb			; get next byte
	jmp	cpcolp

cpcodn:	seg	es
	cmp	byte ptr (di-1),#32 ; last was space ?
	jne	nocopt		; no -> go on
	dec	di		; discard it
	inc	cx		; **
nocopt:	mov	si,options	; append variable options
cpvalp:	lodsb			; copy one byte
	stosb
	or	al,al		; NUL ?
	jz	cpdone		; done?
	loop	cpvalp		; count and loop back
cpovfl:	mov	(di),cl		; CX is zero
#if DEBUG_NEW
	dec	cx		; count 1 more character
#endif
cpdone:


#if DEBUG_NEW
	push	cx
	mov	bx,#msg_pl	; parameter line message
	call	say
	pop	cx
	mov	ax,#CL_LENGTH-1
	sub	ax,cx
	call	wout
	call	crlf
#endif

#ifdef DEBUG
	mov bx,#step2
	call say
#endif
	mov	es,[initseg]	; load the original boot sector
	xor	bx,bx		; load now
	call	load1
	pop	si		; restore SI
	lodsw			; get flags bit map
	xchg	bx,ax		; move to BX
	lodsw			; copy parameters ... VGA mode ... (done)
	cmp	word ptr vgaovr,#VGA_NOCOVR ; VGA mode not overridden on
				; command line ?
	je	vganorm		; no -> go on
	mov	ax,vgaovr	; use that value
	jmp	vgaset
vganorm:test	bx,#FLAG_VGA
	jz	novga
vgaset:	seg	es
	 mov	[VGA_SET],ax	; magic offset in the boot sector
novga:	push	bx		; use flags (BX) later
	test	bx,#FLAG_LOCK	; ... lock target ?
	jnz	lockit		; yup -> do it
	cmp	byte ptr dolock,#0 ; did user ask to lock new target ?
	je	nolock		; no -> go on
lockit:
#ifndef LCF_READONLY
	mov	bx,#lkwbuf	; save the command line
	mov	word (bx),#DC_MAGIC	;
	push	es
	push	si

        push    ds                      ;
        pop     es                      ;
	call	cmd_write		; write out the command line

	pop	si
	pop	es
#endif
nolock:
#ifdef DEBUG
	mov bx,#step3
	call say
#endif
	xor	cx,cx
	seg	es
	  add	cl,[VSS_NUM]
;;;	or	cx,cx
	jnz	lsetup
	mov	cl,#SETUPSECS	; default is to load four sectors
lsetup:	
	mov	es,[setupseg]	; load the setup codes

#ifdef MEMORY_CHECK
	mov	ax,cx		; number of sectors to AX
	shl	ax,#5		; convert to paragraphs (9-4)
	mov	bx,es
	add	bx,ax
	add	bx,#STACK>>4	; allow for stack space in paragraphs
	mov	ax,cs		;
	cmp	bx,ax
	jbe	enough_mem
	mov	bx,#msg_mem	; we are very short on memory
	call	say

enough_mem:
#endif

	xor	bx,bx		; other operating system)
lsloop:	push	cx
	call	loadopt
	pop	cx
	loop	lsloop
#ifdef DEBUG
	mov bx,#step4
	call say
#endif
	pop	bx		; get flags
	test	bx,#FLAG_MODKRN	; "modern" kernel ?
	jz	loadlow		; no -> avoid all patching and such
	seg	es		; set loader version
	mov	byte ptr (16),#LOADER_VERSION

	test	bx,#FLAG_LOADHI	; load kernel high
	jz	nohigh
	
	seg	es
	mov	ax,word ptr (20+1) ; get start address  00 1000 00
	mov	(gdt+0x1b),ax
	seg	es
	mov	al,byte ptr (20+3) ; get hi-byte of address
	mov	(gdt+0x1f),al
nohigh:

	seg	es		; version >= 1 ?
	cmp	word ptr (6),#NEW_HDR_VERSION
	jbe	noheap		; no -> do not patch heap
	mov	ax,cs
	sub	ax,[initseg]	; find no. of paragraphs available
	shl	ax,4
	add	ax,#SLA_SIZE_DYN
	seg	es
	mov	word ptr (36),ax
	seg	es		; patch flags
	or	byte ptr (17),#LFLAG_USE_HEAP
noheap:
	pop	si		; restore pointer to DESCR to load

	push	[gdt+0x1b]
	mov	al,[gdt+0x1f]
	push	ax

	call	load_initrd	; load the initrd & patch header

	pop	ax
	mov	[gdt+0x1f],al
	pop	bx
	mov	[gdt+0x1b],bx

	cbw
	or	ax,bx		; load low ?

	je	loadlow		; yes -> do it
	xor	ax,ax		; GDT is already set up ...
	mov	es,ax
	mov	bx,#gdt
#if DEBUG_NEW
	push	bx
	mov	bx,#msg_high
	call	say
	pop	bx
#endif
	call	lfile		; load the system ...
	jmp	launch2		; ... and run it
loadlow:
#if DEBUG_NEW
	push	bx
	mov	bx,#msg_low
	call	say
	pop	bx
#endif
	call	loadfile	; load the system
launch2:

	jmp	launch		; go !

loadfile:
	push	#SYSSEG		; load a file at SYSSEG:0000
	pop	es
	xor	bx,bx
lfile:	call	load
	jmp	lfile

! Load one sector. Issue an error at EOF.

load1:	call	loadit		; load the sector
	mov	bx,#msg_eof	; we only get here at EOF
	call	say
	br	restrt

loadit:	call	load		; load it
	pop	ax		; drop return address of load1
	ret

! Load one sector. Start the system at EOF.

loadopt:call	loadit		; load the sector
	jmp	launch		; go

! Load one sequence of sectors. Leave outer function at EOF.

load:	push	es		; save ES:BX
	push	bx
lfetch:	mov	si,moff		; get map offset
	mov	bx,[map]
	mov	cx,(bx+si)	; get address
	mov	dx,(bx+si+2)
	mov	al,(bx+si+4)
	or	cx,cx		; at EOF ?
	jnz	noteof		; no -> go on
	or	dx,dx
	jnz	noteof
	pop	bx		; restore ES:BX
	pop	es
	pop	ax		; pop return address
	ret			; return to outer function
noteof:	add	si,#sa_size	; increment pointer
	mov	moff,si
	cmp	si,#SECTOR_SIZE - sa_size + 1		; page end ?
	jb	near doload

	mov	moff,#0		; reset pointer
	push	cs		; adjust ES
	pop	es

        mov     bl,hinib        ; this might get clobbered
        push    bx              ; so save it
	mov	bx,[map]		; load map page
	call	sread
        pop     ax              ; restore the hi-nibble
	mov     hinib,al        ; 

	mov	al,#0x2e	; print a dot
	call	display
	jmp	lfetch		; try again

! Start the kernel

launch:
; terminate emulation if CD boot
	test	byte ptr [par2_flag2],#FLAG2_EL_TORITO	; a CD?
	jz	not_el_torito
	mov	si,#Map		; empty command packet
	mov	byte ptr (si),#0x13	; size of command packet
	mov	ax,#0x4b00	; terminate emulation
;;;;	mov	dl,al		; DL is 0
	mov	dl,[init_dx]	; terminate boot device
	int	0x13
not_el_torito:
#ifdef MENU
	call	menu_exit	; make the menu area vanish
#endif
	call	crlf		; display a CRLF

/* 'outb' was removed in 22.5.5; but the HW stop is required by some BIOSs */
	mov	dx,#0x3f2	; stop the floppy motor
	xor	ax,ax
	out	dx,al		; outb
	mov	dl,al
	int	0x13		; reset the FDC  (AH=0)

	mov	es,[initseg]	; adjust segment registers
	mov	di,#PARMLINE	; set parameter line offset
	mov	ax,cs		; find where we are loaded
	sub	ax,[initseg]	; find no. of paragraphs available
	shl	ax,4		; convert para. to bytes
	add	di,ax
	seg	es
	cmp	dword ptr CL_HEADER_ID,#0x53726448	; "HdrS" (reversed)
	je	chkver		; go check header version
mbchain:

! it must be the chain loader

#ifdef LCF_BDATA
	BEG_FS
	SEG_FS			; suppress BIOS data collection
	or	byte ptr par1_prompt+SSDIFF,#FLAG_NOBD	; suppress BIOS data collection
	END_FS
#endif
			; ES:DI will point at param line (chain.b)
	push	ds		; save DS
	mov	ds,[setupseg]	; point at chain loader(?) header
; DS points at chain loader
	cmp	dword [parC_signature],#EX_MAG_HL ;
	jne	not_chain
	cmp	word [parC_stage],#STAGE_CHAIN
	jne	not_chain
	cmp	word [parC_version],#VERSION
	jne	not_chain
	mov	dx,[parC_drive]	; get drive
;;;	call	map_device	; map drive -- uses CS to address "devmap"
	mov	[parC_drive],dl	; store mapped drive
	mov	[parC_devmap],#devmap	; save our drive mapping
	mov	[parC_devmap+2],cs	; our DS register
not_chain:
	pop	ds
	BEG_FS
	SEG_FS
	mov	dx,[EX_OFF+6]	; pass DX from first stage
	END_FS
#if DEBUG_NEW
	mov	bx,#nohdrs
	call	say
	jmp	cl_wait
#else
	br	start_setup2
#endif

chkver:
	mov	bh,[gdt+0x1f]		; check for kernel/initrd conflict
	shl	ebx,#8
	mov	bx,[gdt+0x1b]		; form kernel final load address
	shl	ebx,#8
	mov	eax,[rdbeg]		; initrd beg address (0 if none)
	or	eax,eax
	jz	no_overwrite
	sub	eax,ebx
	jae	no_overwrite
	mov	bx,#msg_confl
	br	zz

no_overwrite:
#if DEBUG_NEW
	mov	bx,#hdr1
	call	say
	seg	es
	mov	ax,CL_HDRS_VERSION
	call	wout
	mov	bx,#hdr2
	call	say
	push	di
#endif
	seg	es
	cmp	word ptr CL_HDRS_VERSION,#NEW_VERSION  ; check for
				; new cmdline protocol
	jb	protocol201

! and now the new protocol

	mov	ax,es		; form long address
	movzx	edx,ax		; zero extend segment part to EDX
	movzx	edi,di		; zero extend offset
	shl	edx,4		; make segment into address
	add	edx,edi		; form long absolute address
	seg	es
	mov	CL_POINTER,edx	; and pass the address
#if DEBUG_NEW
	push	edx		
	call	dout
	jmp	cl_wait
#else
	jmp	start_setup
#endif

! the old command line passing protocol

protocol201:
	seg	es
	mov	CL_MAGIC_ADDR,#CL_MAGIC ; set magic number
	seg	es
	mov	word ptr CL_OFFSET,di
#if DEBUG_NEW
	mov	ax,es
	call	wout
	mov	al,#0x3A	; issue colon    
	call	display
	mov	ax,di
	call	wout
cl_wait:
	mov	bx,#hdr4
	call	say
	pop	bx
	push	ds
	push	es
	pop	ds
	call	strlen
	pop	ds
	call	wout

	call	crlf
	call	crlf
	jmp	start_setup

#endif
start_setup:			; kernel boot comes here
#if DEBUG_NEW
	mov	bx,#msg_real
#ifdef LCF_VIRTUAL
	call	vmtest
	jnc	boot_real_msg_v
	mov	bx,#msg_virtual
boot_real_msg_v:
#endif
#ifdef LCF_NOKEYBOARD
	call	kbtest
	jc	boot_real_msg_k
	mov	bx,#msg_no_keyboard
boot_real_msg_k:
#endif
	call	say
#endif
#ifdef LCF_BDATA
	mov	bx,#msg_bc
	call	say
	BEG_FS
	SEG_FS		; suppress BIOS data collection?
	test	byte ptr par1_prompt+SSDIFF,#FLAG_NOBD	; suppress?
	END_FS
	jz	start_setup3
	mov	bx,#msg_by
	call	say
	jmp	start_setup2
start_setup3:

#ifndef LCF_READONLY
	or	byte ptr [KEYTABLE+256+mt_flag],#FLAG_NOBD	; suppress
#if DEBUG_NEW
	call	crlf
#endif
	call	kt_write
#endif

#if DEBUG_NEW
;;;	call	pause
	mov	ah,#2		; get keyboard flags
	int	0x16
	and	al,#0x70	; Caps, Num, Scroll Lock flags
	cmp	al,#0x70
	je	near zzz	; fail with all 3 on
#endif

	BEG_FS
	SEG_FS
	mov	dx,[EX_OFF+6]	; pass in DX from first stage
	END_FS

	push	es		; save ES
	call	is_prev_mapper	; is there a previous mapper
	jz	no_remove
	seg es
	  mov	word (di),#0	; sterilize it
no_remove:
	pop	es		; and restore ES

	call	io_biosdata

	mov	bx,#msg_s
	call	say
#ifndef LCF_READONLY
; if the BIOS data collection was successful, do not suppress it on future boots
	and	byte ptr [KEYTABLE+256+mt_flag],#~FLAG_NOBD	;  no suppress
	call	kt_write
#endif
#endif	/* ifdef LCF_BDATA */

start_setup2:			; chain loader boot comes here
#if DEBUG_NEW
	call	pause		; last chance to use the timer
#else
	mov	ax,#1500/55	; about 1.5 second
	call	setto		; set timeout
vpaus1:	test	byte ptr timeout,#-1
	jz	vpaus1
#endif
	call	remto		; free timer interrupt

	push	es		; is initseg
	pop	ds		; DS = 0x9000 (initseg)
#if 0
	push	es
	pop	fs
	push	es
	pop	gs
#endif

	add	sp,#SETUP_STACK_DYN	; increase stack size over this code
if ~*&1					; align to an odd memory location
	nop
endif
	jmpi	0,SETUPSEG		; segment part is a variable
setupseg	=	*-2		;   setupseg is filled in now
initseg:	.word	INITSEG


! Load one sector (called from load)

doload:	pop	bx		; restore ES:BX
	pop	es

! Load a sequence of sectors, possibly moving into "high memory" (> 1 MB)
! afterwards.

xread:	push	ax		; ES == 0 ?
	mov	ax,es
	or	ax,ax
	pop	ax
	jz	rdhigh		; yes -> read into high memory
#ifdef DEBUG
	br	sread
#else
	jmp	sread
#endif
rdhigh:	push	bx		; okay - DS:BX points to GDT in this case
	mov	bx,#LOADSEG	; adjust ES:BX
	mov	es,bx
	xor	bx,bx
	call	sread		; load the sector(s)
        mov     tempal,al
	pop	bx		; get pointer to GDT
	push	ax		; just in case ...
	push	cx
	push	si
	mov	si,bx		; turn ES:SI into pointer to GDT
	push	ds
	pop	es
	xor	cx,cx		; number of words to move
	mov	ch,tempal
#ifdef DEBUG
	push	si
	push	bx
	push	cx
	mov	al,(si+0x14)
	call	bout
	mov	ax,(si+0x12)
	call	wout
	mov	bx,#mov_ar
	call	say
	mov	ah,(si+0x1f)
	mov	al,(si+0x1c)
	call	wout
	mov	ax,(si+0x1a)
	call	wout
	mov	bx,#mov_sz
	call	say
	pop	ax
	push	ax
	call	wout
	call	crlf
	pop	cx
	pop	bx
	pop	si
#endif
	push	[gdt+0x1e]
	push	bx		; do the transfer. (save BX, CX and SI because
	push	cx		; we are paranoid)
	push	si
	mov	ah,#0x87	; Move Extended Memory Block
	int	0x15
	pop	si
	pop	cx
	pop	bx
	jc	badmov		; failed ...
	pop	ax		; check the GDT
	cmp	ah,[gdt+0x1f]	; catch a BIOS that does not handle 386
				; addresses (>16Mb)
	jne	badmov+1	; AH error code will be hi byte of address
	shr	cx,#8-1		; convert words to bytes/256
	sub	ax,ax		; put ES back to 0
	add	(si+0x1b),cx
	adc	(si+0x1f),al
	mov	es,ax		; put ES back to 0
	pop	si
	pop	cx
	pop	ax
	ret			; done

badmov:	pop	bx		; discard GDT
	push	ax		; save the error code
	mov	bx,#msg_bm	; tell the user ...
	jmp	reset		; (standard procedure calls say & bout)

! Load a sequence of sectors

sread:	push	bx		; save registers
	push	cx
	push	dx
	call	cread
	mov	di,ax		; save AL return count
	jc	rerror		; error -> complain
	pop	dx		; restore registers
	pop	cx
rokay:	pop	bx
        shl     ax,8            ; convert sectors to bytes
        add     ah,ah
	jc	dowrap		; loaded an entire segment -> advance ES
	add	bx,ax		; move BX
	jnc	nowrap		; same segment -> go on
dowrap:	mov	ax,es		; move ES
	add	ax,#0x1000
	mov	es,ax
nowrap:
	mov	ax,di		; restore the block count in AL
aret:	ret			; done

! Read error - try a second time and give up if that fails too

rerror:
	push	ax
	mov	bx,#msg_re	; say something
reset:	call	say
	pop	ax		; display the error code
	mov	al,ah
	call	bout
	call	crlf		; a CR/LF
	mov	moff,#0		; restore initial state
#if DEBUG_NEW
	pop	ax
	call	swout		; DX
	pop	ax
	call	swout		; CX
	pop	ax
	call	swout		; BX
	call	crlf
#endif
	br	restrt

! Convert character in AL to upper case

upcase:	cmp	al,#0x61	; lower case character ? ('a')
	jb	nolower		; no -> go on
	cmp	al,#0x7a	; 'z'
	ja	nolower
	sub	al,#0x20	; convert to upper case
nolower:ret			; done

pause:
#if !DEBUG_NEW
	pusha
	mov	ax,#3200/55	; delay 3+ seconds
	call	setto
delay1:	test	byte ptr timeout,#-1
	jz	delay1
	popa
#else
	pusha
	mov	ah,#0x86	; delay in microseconds
	mov	cx,#5<<4	; 3 seconds; forget DX
	int	0x15
	popa
#endif
	ret



#if DEBUG_NEW

!  display a double word, pushed into the stack

dout:	push	bp
	mov	bp,sp
	push	ax

	mov	ax,(bp+6)	; get high order
	call	wout
	mov	ax,(bp+4)	; get low order
	call 	wout

	pop	ax
	leave
	ret	4

! display a space, followed by a word in AX

swout:	push	ax
	mov	al,#32
	call	display
	pop	ax
; and fall into  wout

! Display a hexadecimal word/byte/nibble

wout:	push	ax
	xchg	al,ah
	call	bout
	pop	ax
; must fall into  bout
#endif

bout:	push	ax		; save byte
	shr	al,#4		; display upper nibble
	call	nout
	pop	ax
nout:	and	al,#0x0F	; lower nible only
	daa			; smaller conversion routine
	add	al,#0xF0
	adc	al,#0x40	; AL is hex char [0..9A..F]
	jmp	display		; display it

! part of the 'say' routine
! actual entry point is below at 'say:'

say_loop:
	cmp	al,#10		; \n ?
	jne	nonl		; no -> go on
	mov	al,#13		; display a CRLF
	call	display
	mov	al,#10
nonl:
	cmp	al,#12		; ^L ?
	jne	nocls		; no -> go on
#ifdef MENU
	call	menu_form_feed	; simulate a FF
#else
#ifdef BITMAP
	cmp	BYTE [abs_cx+1],#0	; graphic screen on?
	jne	tosnext
#endif
	push	bx
	mov	ah,#0xf		; clear the local screen
	int	0x10
	xor	ah,ah
	int	0x10
	pop	bx
#endif
tosnext: jmp	snext		; next character
nocls:	call	display		; display, tty-style
snext:
	inc	bx		; next one
! fall into  say   		; process next character

! Display a NUL-terminated string on the console

say:	mov	al,(bx)		; get byte
	or	al,al		; NUL ?
	jnz	say_loop	; not the end
	ret


! Display CR/LF

crlf:	mov	al,#13		; CR
	call	display
	mov	al,#10		; LF
;;;	jmp	display
; fall into  display

! Display one character on the console

display:
	push	bx		; save BX

#ifndef LCF_NOSERIAL
	call	serdisp
#endif
#if defined(MENU) || defined(BITMAP)
	seg	cs
	cmp	word [suppress],#0
	jnz	dispret

#ifdef MENU
	push	ds

	push	cs
	pop	ds

	push	dx

	cmp	byte [abs_cx+1],#0	; is special scrolling in effect?
	je	goshowit	; jump if no special handling
	call	mn_getcursor	; get cursor pos. in DX
	
	cmp	al,#8		; is it BS
	jne	scroll1
	or	dl,dl		; at col. 0?
	jne	goshowit
; must simulate a BS
	mov	dl,[mn_max_row_col]	; move to EOL
	mov	al,#0x0a	; change to LF
	dec	dh		; back up first of two lines
	jmp	scroll_set	; set new cursor pos. & ring BEL

scroll1:
	cmp	al,#0x0a	; test for LF / NL
	jne	scroll2
	cmp	dh,[mn_max_row_col+1]  ; bottom row
	jae	scrollit
scroll2:
	cmp	al,#0x20	; printing char?
	jb	goshowit
	cmp	dx,[mn_max_row_col]	; bottom corner
	jne	goshowit

scrollit:
	pusha
	mov	ax,#0x601	; scroll up 1 line
	mov	bh,[mn_at_mono]
	mov	cx,[abs_cx]
	mov	dx,[mn_max_row_col]
	int	0x10		; do the scroll
	popa
scroll_set:
	dec	dh
	call	mn_setcursor	; set cursor up 1 row
goshowit:
	pop	dx

	pop	ds
#endif
#endif
#ifndef LCF_NOVGA
;;;	xor	bh,bh		; display on screen
	mov	bx,#7		; set color for TEXT interface
	mov	ah,#14
	int	0x10
#endif
dispret:
	pop	bx		; restore BX
	ret


#ifndef LCF_NOSERIAL
serdisp:push	dx		; wait for space in the send buffer
	seg	cs
	mov	dx,slbase
	or	dx,dx
	jz	serret
	add	dx,#5
	push	ax
serwait:in	al,dx
	test	al,#0x10	; break -> set break flag
	jz	nobrk
	seg	cs
	mov	byte ptr break,#1
nobrk:	test	al,#0x20	; ready to send ?
	jz	serwait		; no -> wait
	sub	dx,#5		; send the character
	pop	ax
	out	dx,al
serret:	pop	dx		; done
	ret
#endif

! Get a key (CX = timeout exit)

getkey: ;; BEG_FS
;;	SEG_FS		; set the timeout
	mov	ax,par2_timeout		;DSC_OFF-10+SSDIFF
;;	END_FS
	call	setto
gwtkey:	mov	ah,#1		; is a key pressed ?
	int	0x16
	jnz	gotkey		; yes -> get it
#ifndef LCF_NOSERIAL
	mov	dx,slbase	; using a serial port ?
	or	dx,dx
	jz	gnokey		; no -> wait
	add	dx,#5		; character ready ?
	in	al,dx
	test	al,#1
	jz	gnokey		; no -> wait
	sub	dx,#5		; get it
	in	al,dx
	and	al,#0x7f	; strip 8th bit
	jnz	gotch		; ignore NULs
#endif
gnokey:	
#if defined(MENU) || defined(BITMAP)
#ifdef BITMAP
	cmp	byte [abs_cx+1],#0
	je	no_timer_display
#endif
	call	timer_display
no_timer_display:
#endif
	test	byte ptr timeout,#1 ; timed out ?
	jz	gwtkey		; no -> wait
	pop	ax		; discard return address
	jmp	cx		; jump to timeout handler
gotkey:	xor	ah,ah		; read a key
	int	0x16
	push	bx		; keyboard translation (preserve BX)
	mov	bx,#KEYTABLE
	xlatb
	pop	bx
gotch:
#ifdef LCF_ONE_SHOT
	BEG_FS
	SEG_FS		; always enter prompt ?
	test	byte ptr par1_prompt+SSDIFF,#FLAG_PROMPT
	END_FS
	jz	noosht		; yes -> do not disable timeout
#endif
;			disable timeout
	test	byte ptr par2_flag2,#FLAG2_UNATTENDED
	jnz	nocancel
	mov	word ptr par2_timeout,#0xffff
nocancel:
noosht:
	ret			; done

! Shift wait loop (AX = timeout, returns CY set if interrupred)

waitsh:	call	setto		; set timeout
actlp:	mov	ah,#2		; get shift keys
	int	0x16
#if defined(LCF_VIRTUAL) && DEBUG_NEW
	and	al,#0x1f	; anything set ? (except NumLock or CapsLock)
#else
	and	al,#0x5f	; anything set ? (except NumLock)
#endif
	jnz	shpress		; yes -> return with CY set
; 22.7.1 begin
	mov	ah,#1		; get status
	int	0x16
	jnz	shpress		; key pressed
; 22.7.1 end
#ifndef LCF_NOSERIAL
	mov	dx,slbase	; using a serial port ?
	or	dx,dx
	jz	acnosp		; no -> go on
	cmp	byte ptr break,#0 ; break received ?
	jnz	shpress		; yes -> return with CY set
	add	dx,#5		; check for pending break
	in	al,dx
	test	al,#0x10
	jnz	shpress		; break received -> return with CY set
#endif
acnosp:	test	byte ptr timeout,#1 ; timed out ?
	jz	actlp		; no -> wait
	clc			; clear carry
	ret			; done
shpress:stc			; set carry
	ret			; done

! Timeout handling

instto:	push	ds		; install the timeout handler
	push	#0
	pop	ds

	cli			; no interrupts
	mov	eax,[0x1c*4]	; get the old vector
	seg	cs
	mov	[int1c_l],eax	; save H & L parts
	mov	[0x1c*4],#tick	; install new vector
	mov	[0x1c*4+2],cs
	sti			; done
	pop	ds
	ret

remto:	push	es		; remove the interrupt handler
	push	#0
	pop	es

	mov	eax,[int1c_l]	; restore the old vector
	seg	es
	mov	[0x1c*4],eax	; **
	pop	es
	ret

! AX = ticks, 0xffff = no timeout

setto:	or	ax,ax		; time out immediately ?
	jz	toimmed		; yes -> do it
	cli			; set timeout value
	mov	cntdown,ax
	mov	byte ptr timeout,#0 ; clear timed-out flag
	sti			; done
	ret
toimmed:mov	byte ptr timeout,#0xff ; set the timed-out flag
	ret			; done

tick:	pushf			; save flags
	seg	cs		; no timeout ?
	cmp	word ptr cntdown,#0xffff
	je	notzro		; yes -> go on
	seg	cs		; decrement counter
	dec	word ptr cntdown
	jnz	notzro		; not zero -> go on
	seg	cs		; set timeout flag
	mov	byte ptr timeout,#0xff
notzro:
	seg	cs
	push	dword [int1c_l]
	iret			; continue with old interrupt

kt_set:
;;	BEG_FS
;;	SEG_FS		; load the keyboard translation table
	mov	cx,par2_keytab		;MSG_OFF+SSDIFF+7
;;	SEG_FS
	mov	dx,par2_keytab+2		;MSG_OFF+SSDIFF+9
;;	SEG_FS
	mov	al,par2_keytab+4		;MSG_OFF+SSDIFF+11
;;	END_FS
	mov	bx,#KEYTABLE
	ret

#ifndef LCF_READONLY

! Sector write; used for the keytable only

kt_write:
	push	es
	push	ds
	pop	es
	call	kt_set		; set for KEYTABLE i/o

	BEG_FS
	SEG_FS		; BIOS data collection worked before?
	test	byte ptr par1_prompt+SSDIFF,#FLAG_BD_OKAY
	END_FS
	jnz	kt_nowrite

	test	byte ptr [par2_flag2],#FLAG2_EL_TORITO	; a CD?
	jnz	kt_nowrite

	call	cwrite
kt_nowrite:
	pop	es
	ret

! Sector write; used for the stored command line only

cmd_write:	
;BEG_FS
;SEG_FS
	mov	cx,mt_dflcmd+KEYTABLE+256
;SEG_FS
	mov	dx,mt_dflcmd+2+KEYTABLE+256
;SEG_FS
	mov	al,mt_dflcmd+4+KEYTABLE+256
;END_FS
; fall into cwrite
;
;  General sector write
;
cwrite:
#ifdef FLAG_RAID_NOWRITE
	BEG_FS
	SEG_FS
	test	byte ptr par1_prompt+SSDIFF,#FLAG_RAID_NOWRITE ; no writes?
	END_FS
	jnz	cwok		; jump if no writing allowed
#endif
	BEG_FS
	SEG_FS
	test	byte ptr par1_prompt+SSDIFF,#FLAG_RAID	; is it a RAID write
	END_FS
	jnz	cmd_raid_wrt

        mov     byte ptr (dsk_wrflag),#WR_ENABLE      ; flag write operation
        call    cread
        mov     byte ptr (dsk_wrflag),#0        ; flag read operation

	jnc	cwok		; no error - return
cnok:
	pusha
	cmp	ah,#3		; write protect error
	je	cnok3
	push	ax		; save error code in AH
	mov	bx,#msg_wrerr
	call	say
	pop	ax
	mov	al,ah		; error code
	call	bout
	call	crlf		; leave space
	jmp	cnok5
cnok3:
	mov	bx,#msg_wrerr3	; write protect
	call	say
cnok5:
	popa
        stc                     ; flag error  JRC
cwok:
#if DEBUG_NEW
	pushf
	call	pause
	popf
#endif
	ret			; done

cmd_raid_wrt:
	test	dl,#RAID_REL_FLAG	; relocation called for?
	jnz	crw1
	mov	ah,#0x99		; flag error
	jmp	cnok
crw1:
	push	si
	mov	si,[rmask]		; get raid physical device mask
cwrm = LINEAR_FLAG|LBA32_FLAG|LBA32_NOCOUNT|RAID_REL_FLAG|0X80
	and	dl,#cwrm		; save flags, set device to 80

cwr2:	shr	si,#1
	jnc	cwr3
	pusha
        mov     byte ptr (dsk_wrflag),#WR_ENABLE      ; flag write operation
        call    cread_physical		; read the PHYSICAL device #
        mov     byte ptr (dsk_wrflag),#0        ; flag read operation
	popa

cwr3:	inc	dx
	or	si,si		; clears the carry
	jnz	cwr2

	pop	si
;;;	clc			; signal no error
	jmp	cwok

cwr_cnt:	.byte	0	; device code count
cwr_flags:	.byte	0	; saved flags

#endif

kt_read:		; KEYTABLE read
	call	kt_set		; set for KEYTABLE i/o
	call	cread
	jc	keyerr
	mov	si,#KEYTABLE	; compute a checksum of the keytable
	mov	di,#SECTOR_SIZE - 8	; skip the last 4+4 bytes
	push    dword #CRC_POLY1
	call	crc32
	add	di,si
	cmp	eax,dword (di)
	jz	nokeyerr

! Checksum error
keyerr:
	mov	bx,#msg_chkkey
	br	zz		; go wait
nokeyerr:
	ret

! Sector read
!  enter with AL, CX, DX, ES, BX set for read
!  trashes CX and DI
!
cread:			; entry point for mapped device r/w
	call	map_device	; DL (logical) -> DL (physical)

cread_physical:		; same entry, device is not mapped

        test    dl,#LINEAR_FLAG|LBA32_FLAG
        jnz     use_linear

        push    ax              ;save the count
	mov	ah,#2		;read command
        call    dsk_do_rw       ; int 0x13 with retries
        pop     cx              ;Carry Set means error on read
        mov     al,cl           ;count in AL, error code in AH
        ret

use_linear:
        mov     ah,hinib        ;will be zero for LINEAR
        xchg    al,dh           ;AX is possible address 
	test	dl,#LBA32_FLAG	;test for LBA32/LINEAR	*****
	jz	lnread		;pure LINEAR		*****
        test    dl,#LBA32_NOCOUNT
        jz      lnread
        mov     ah,dh           ;former count is really hi-nibble
        mov     hinib,ah
        mov     dh,#1           ;set count to 1
lnread:
        xchg    di,ax           ;hi-address to DI
        mov     al,dh           ;count to AL

	test	dl,#RAID_REL_FLAG		; ******
	jz	ln_do_read			; ******

	call	translate		; in volume.S

ln_do_read:
        call    lba_read
        mov     al,cl           ;count returned in AL, error code in AH
        ret                     ;Carry Set means error on read

#ifdef LCF_VIRTUAL
; vmtest -- return Carry=1 if in virtual (VMware) mode
;	    return Carry=0 if in real mode
;
vmtest:
#ifndef LCF_SUSPEND
	pushad			; save all extended registers
	smsw	ax
	rcr	al,1		; PE bit in AL to Carry
	jc	vm_ret		; exit if virtual mode
#if DEBUG_NEW
	mov	ah,#2		; get keyboard flags
	int	0x16
	and	al,#0x50	; Caps, Scroll Lock flags
	cmp	al,#0x40
	je	vm_vir		; Caps only means virtual boot simulated
#endif
;
;  If no vmdefault, vmdisable, or vmwarn keywords were used, then we do not
;  care about virtual mode.  Do not touch the hardware, and always return
;  Carry=0.
;
	test	byte ptr [par2_flag2],#FLAG2_VIRTUAL	; any vmXXX keywords?
	jz	vm_ret		; TEST clears the carry, always
;
;  VMware(R) test for virtual mode
;
	mov	eax,#0x564D5868	; EAX: in = 'VMXh'   out = version
	xor	ebx,ebx		; EBX:               out = 'VMXh' under vmware
	mov	edi,eax
	mov	dx,#0x5658	;  DX: in = 'VX'
	mov	ecx,#10		; ECX: in = VMXGetVersion
	in	eax,dx
	cmp	ebx,edi		; test for vmware
	clc			; NOT vmware if Carry==0
	jne	vm_ret		; not vmware

	inc	eax		; carry is not affected by INC
	jz	vm_ret		; invalid version number == 0xFFFFFFFF

vm_vir:
	stc			; signal virtual mode

vm_ret:	popad		; restore all the extended registers
	ret

#else	/* LCF_SUSPEND changes the interpretation of "virtual" */
	pusha
	push	es
	test	byte ptr [vm_cache],#0xFF	; test cached value
	jnz	vm_ret

	mov	byte ptr [vm_cache],#2		; not virtual

	push	ds
	pop	es		; ES:BX
	mov	bx,#MAP		; use this buffer
	mov	cx,#1		; sector 1
	mov	dx,#0x80	; dos C: drive
	mov	al,cl		; 1 sector
	call	cread		;
	jc	vm_ret		; not virtual if error

	mov	cx,#PARTITION_ENTRIES		; count 4 PT entries
	lea	bx,[PART_TABLE_OFFSET](bx)	; first partition entry
vm_pt1:
	test	byte ptr (bx),#0x80		; active
	jz	vm_pt2
	cmp	byte ptr (bx+4),#LCF_SUSPEND	; suspend partition
	jne	vm_pt2
	mov	byte ptr [vm_cache],#1		; suspend is active
vm_pt2:
	lea	bx,[PARTITION_ENTRY](bx)	; bump pointer
	loop	vm_pt1

vm_ret:
	mov	al,[vm_cache]		; get cached value
	shr	al,#1
	pop	es
	popa
	ret

vm_cache:
	.byte	0		; 0=unknown, 1=virtual, 2=non-virtual

#endif	/* LCF_SUSPEND */
#endif	/* LCF_VIRTUAL */


#if LCF_NOKEYBOARD
; kbtest -- return Carry=1 if IBM PC/AT keyboard is present
;	 -- return Carry=0 if no IBM keyboard is present
;
kbtest:
	push	ax
;
;  If neither nokbdefault nor nokbdisable was used, we do not touch
;  the keyboard hardware.  Always report Carry=1 (keyboard present).
;
	test	byte ptr [par2_flag2],#FLAG2_NOKBD
	jz	kbtest8

#if DEBUG_NEW
	pusha
	mov	bx,#msg_kbtest
	call	say		; tell about keyboard test
	popa
#endif
    /* mardy */
	cli			; added 5/17/2006
	mov	al,#0xee	; echo command
	out	#0x60,al
wait_kbd_ctrl_ready:
	in	al,#0x64
	and	al,#0x01
	jz	wait_kbd_ctrl_ready  ; read status port while it is not ready
	in	al,#0x60
	sti			; added 5/17/2006
	xor	al,#0xee	; XOR clears the carry
	jne	kbtest9
		; if we got the same byte, the keyboard is attached
    /* mardy */
#if DEBUG_NEW
	mov	ah,#2		; get keyboard flags
	int	0x16
	and	al,#0x20	; Num Lock flag
	jz	kbtest9		; AND cleared the carry
#endif
kbtest8:
	stc		; flag keyboard present
kbtest9:
	pop	ax
	ret
#endif	/* LCF_NOKEYBOARD */


#if 1
; crc32 -- calculate CRC-32 checksum
;
;	call:
;		push	dword #POLYNOMIAL
;
;		ES:SI	char string pointer
;		DI	count of characters
;
;		call	crc32
;
;    CRC-32 is returned in EAX  or  DX:AX
;		the arguments are popped from the stack
;
crc32:
		push	bp
		mov	bp,sp

		push	si
		push	di
		push	bx
		push	cx

		xor	eax,eax		; initialize CRC
		dec	eax		; EAX = 0xFFFFFFFF
		inc	di
crc32a:
		dec	di
		jz	crc32d
		mov	cx,#8		; count 8 bits
		seg es
		mov	bl,(si)		; get next character
		inc	si
crc32b:		shl	bx,#1		; get hi bit of char in BH
		shl	eax,#1		; shift hi bit out of CRC
		adc	bh,#0		; add carry to BH
		shr	bh,#1		; put bit in carry
		jnc	crc32c		; skip the xor
		xor	eax,(bp+4)	; xor in the polynomial
crc32c:
		loop	crc32b		; loop back for 8 bits
		jmp	crc32a

crc32d:		
		not	eax		; finialize CRC

		pop	cx
		pop	bx
		pop	di
		pop	si
		
		leave
		ret	4
#endif
/* ifdef HIGHMEM_MAX */
; enter with BX == Ramdisk size (in 4k pages)
;
rd_setup:
	push	bx		; save Ramdisk size in pages
	mov	eax,[hma]	; user specified?
	or	eax,eax
#ifdef LCF_INITRDLOW
	jnz	rd_have_hma
#else		/* ifndef LCF_INITRDLOW */
	jnz	near rd_have_hma
	BEG_FS
	SEG_FS
	test	byte ptr par1_prompt+SSDIFF,#FLAG_LARGEMEM
	END_FS
	jz	near no_e801

; try the E820 memory map first
	xor	edx,edx			; flag nothing found
	xor	esi,esi			; flag size==0
	xor	ebx,ebx
	jmp	e8go
e8go2:	or	ebx,ebx			; test for end
	jz	e8go5
e8go:	push	edx			; save best prospect
	mov	eax,#0xe820
	mov	edx,#0x534d4150	;'SMAP'
	mov	ecx,#20
	mov	di,#memmap
	int	0x15			; get memory map
	pop	edx			; restore what we have found so far
	jc	no_e820
	cmp	eax,#0x534d4150	;'SMAP'
	jne	no_e820
	cmp	ecx,#20
	jne	no_e820
#if 0
	mov	eax,memmap	; get start
	mov	ecx,memmap+4	; get high part
	cmp	word memmap+16,#1	; available?
	jne	e8no1			; go on to next
	or	ecx,ecx
	jnz	e8go2
	cmp	eax,#0x100000	; compare to 1Mb
	ja	e8go2
	add	eax,memmap+8	; get final address
	adc	ecx,memmap+12	;
	shrd	eax,ecx,#10	; convert to 1k blocks (legacy)
	cmp	eax,#4*1024	; compare to 4Mb
	jb	no_e820
	xchg	eax,edx		; save in edx
	jmp	e8go2

e8no1:	shrd	eax,ecx,#10	; convert to 1k blocks
	cmp	eax,#1024	; compare to 1Mb
	jb	e8go2		; loop if too small
	cmp	eax,edx		; check against HMA
	jae	e8go2
	xchg	eax,edx		; compensate for buggy BIOS
	jmp	e8go2		; remember in EDX & loop
#else
	cmp	word memmap+16,#1	; available?
	jne	e8go2
	mov	eax,memmap+4	; hi part of start
	shrd	memmap,eax,#10	; convert start to 1k
	mov	eax,memmap+12	; hi part of size
	shrd	memmap+8,eax,#10 ; convert to 1k
	cmp	dword memmap,#1024	; below 1M
	jb	e8go2		; below 1M, no interest
	cmp	esi,memmap+8	; check size
	ja	e8go2		; want largest
	mov	edx,memmap	; start (in 1k)
	mov	esi,memmap+8	; size (in 1k)
	add	edx,esi		; HMA in 1k
	jmp	e8go2
#endif
e8go5:	or	edx,edx		; find anything?
	jz	no_e820
	xchg	eax,edx
	jmp	rd_have_hma
no_e820:
; above failed, try the older E801 block count interface
	xor	cx,cx		; some BIOSs are buggy
	xor	dx,dx
	mov	ax,#0xe801	; call
	stc
	int	0x15
	jc	no_e801
	or	cx,cx
	jz	e801cx
	mov	ax,cx
e801cx:	or	dx,dx
	jz	e801dx
	mov	bx,dx
e801dx:	
	movzx	ebx,bx
	movzx	eax,ax
	shl	ebx,#6		; convert 64k to 1k
	mov	ecx,#16*1024
	cmp	eax,ebx		; compare sizes
	ja	e801eax
	add	ebx,ecx		; add in 16M
	mov	eax,ebx		; and use this value
	jmp	rd_have_hma
e801eax:
	add	eax,#1024	; add 1M
	cmp	eax,ecx		; is it 16M
	jne	rd_have_hma
	add	eax,ebx		; add in ebx
	jmp	rd_have_hma
#endif	/* ifndef LCF_INITRDLOW */
no_e801:
; above two methods failed, try the old 0x88 function
	mov	ah,#0x88	; get count of extended memory blocks
	int	0x15
	movzx	eax,ax		; extend to dword
	add	eax,#1024	; add in base 1M
;
rd_have_hma:	; have the HMA / 1k in EAX
#if DEBUG_NEW
	push	eax
	shl	eax,10		; convert to address
	push	eax
	call	crlf
	call	dout		; pops its argument
	mov	bx,#msg_hma
	call	say
	pop	eax
#endif
	mov	ebx,#15*1024	; 15Mb
	cmp	eax,ebx		; compare to 15M
	jbe	rd_use_eax	; use lower value
	BEG_FS
	SEG_FS
	test	byte ptr par1_prompt+SSDIFF,#FLAG_LARGEMEM
	END_FS
	jnz	large_okay
	xchg	eax,ebx		; limit to 15Mb
large_okay:
	mov	ebx,#HIGHMEM_MAX/1024
#ifdef NEW3_HDR_VERSION
	push	ds
	mov	ds,[initseg]	; load the original boot sector
	cmp	word ptr [CL_HDRS_VERSION],#NEW3_HDR_VERSION
	jb	not203
	mov	ebx,[CL_RAMDISK_MAX]
#if DEBUG_NEW
	pop	cx
	push	cx
	mov	ds,cx
	pushad
	push	ebx
	mov	bx,#hdr3
	call	say
	call	dout
	call	crlf
	popad
#endif
	dec	ebx
	shr	ebx,#10		; divide by 1024
	inc	ebx
not203:
	pop	ds
#endif	/* ifdef NEW3_HDR_VERSION */
	cmp	eax,ebx
	jb	rd_use_eax
;;;rd_use_smaller:
	xchg	eax,ebx		; must use the smaller
rd_use_eax:
	pop	bx		; get size in pages
	shr	eax,2		; convert to pages
	movzx	ebx,bx		; zero high part of size
	sub	eax,ebx		; start address of ramdisk to EAX
#if DEBUG_INITRD
	cmp	dword ptr [hma],#0x180000/1024 ; 1.5Mb
	jb	drd_use_eax
	cmp	dword ptr [hma],#0xF00000/1024	; 15Mb
	jae	drd_use_eax
	mov	eax,[hma]	; HMA is initrd start
	shr	eax,2
drd_use_eax:
#endif
#if 0
	cmp	eax,#256	; we probably need more than 1M for the
	ja	rd_okay		;   kernel to be useful ...
	mov	bx,#msg_rd	; complain
;;;	call	say		; is at zz
	br	zz	 	; and halt 
#else
	cmp	eax,#4*256	; Ramdisk loaded below 4Mb
	jae	rd_okay		;   kernel to be useful ...
	mov	bx,#msg_rd4M	; complain
	call	say		; is at zz
#endif
rd_okay:
	shl	eax,4		; shift (12-8) -> 4
	mov	[rdbeg+1],ax	; set up beginning address
	mov	[gdt+0x1b],ax	; set the GDT for the moves
	shr	eax,16		; get hi-byte of address
	mov	[rdbeg+3],al	; set rest of address
	mov	[gdt+0x1f],al	; and in the GDT, too
	ret
/* endif / ifdef HIGHMEM_MAX */


/* enter with SI pointing to DESCRIPTOR 
	DS = CS
	ES unknown
	SI - points at the descriptor
*/
load_initrd:
	push	[map]
	push	[moff]
	mov	word ptr [map],#MAP2
	push	ds
	pop	es
	mov	ax,(si+id_flags)	; get FLAG_TOOBIG, if any
#if FLAG_LARGEMEM!=FLAG_TOOBIG
# error "FLAG_LARGEMEM and FLAG_TOOBIG must be equal"
#endif
	and	al,#FLAG_TOOBIG		; separate flag
	BEG_FS
	SEG_FS
	or	byte ptr par1_prompt+SSDIFF, al	; set FLAG_LARGEMEM
	END_FS
	add	si,#id_rd_size	; point at ramdisk size long
! take care of the RAM disk first
	xor	eax,eax
	mov	(rdbeg),eax	; clear address
	lodsd
	mov	(rdszl),eax	; set rdszl+rdszh
	add	eax,#4095	; round up &
	shr	eax,#12		; convert to pages
	xchg	bx,ax		; copy to BX
	lodsw			; address of the first map sector
	xchg	cx,ax
	lodsw
	xchg	dx,ax
        lodsb                   
	or	bx,bx		; no RAM disk ?
	jz	noramd		; yes -> skip it 2

	push	si		; save SI, ES, and BX (RD size)
	push	es
	push	bx
	mov	bx,[map]		; load the first map sector
	call	sread
	mov	moff,#0
#ifdef DEBUG
	mov bx,#stepa
	call say
#endif
/* ifdef HIGHMEM_MAX */
	pop	bx
	call	rd_setup
/* endif */
	cmp	dword ptr (rdbeg),#0
	je	nordpt		; no -> no need to patch header for that
; setrdp:
#if DEBUG_NEW
	push	dword (rdbeg)	; print RAM disk address
	mov	bx,#msg_rd2
	call	say
	call	dout
	call	crlf
#endif
	mov	es,[setupseg]	; load the setup codes
	mov	eax,(rdbeg)	; get RAM disk start address
	seg	es
	mov	(24),eax	; store in header
	mov	eax,rdszl
	seg	es
	mov	(28),eax	; set RAM disk size
nordpt:	
	push	#0		; ES=0 is our secret code to load via GDT
	pop	es
	mov	bx,#gdt
	call	lfile		; load it
#if 1
	mov	al,#0x20	; print a space
	call	display
#endif
	pop	es		; restore ES and SI
	pop	si
noramd:
	pop	[moff]
	pop	[map]
	ret

#ifndef LCF_NOSERIAL
serLI:	.byte	13,10,0x4c,0x49		; cr,lf,"LI"

BAUD_BASE = 115200			; divisor == 1
divisor:
	.byte	BAUD_BASE / 19200	; must be same as bsect.c table
	.byte	BAUD_BASE / 38400
	.byte	BAUD_BASE / 57600
	.byte	BAUD_BASE / 115200
	.byte	BAUD_BASE / 2400
	.byte	BAUD_BASE / 2400
	.byte	BAUD_BASE / 2400
	.byte	BAUD_BASE / 2400

; serial_setup -- do the setup for the serial line communications
;
;	No registers are saved
;
serial_setup:
;;	BEG_FS
;;	SEG_FS
	mov	dx,par2_port	; use a COM port ?
			; watch out, loads par2_ser_param
;;	END_FS
	dec	dl
	js	nocom		; no -> go on
	xor	ax,ax		; initialize the serial port
	xchg	al,dh

	push	ax
	push	dx

;;;	or	al,#0x06	; stop bits = 2, nbits = 7 or 8
				; this OR is not needed yet (21.7)
	int	0x14		; Communications Port INIT

	push	#0x40
	pop	ds

	pop	bx		; was DX

	shl	bx,#1
	mov	dx,(bx)		; get the port address from the BIOS

	seg	cs		; keep it
	mov	slbase,dx

	pop	bx		; special baud rate test -- was AX

	test	bl,#0x04		; stop bits == 2?
	cli			; do not disturb any code below
	jz	stdbps		; standard BPS

	shr	bx,#5		; index divisor array
	seg	cs
	mov	bl,divisor(bx)

spcbps:				; CLI: do not disturb ...
	push	dx		; save base address
	add	dx,#3		; enable divisor latch access
	in	al,dx
	or	al,#0x80
	out	dx,al
	pop	dx		; set new divisor
	push	dx
	xchg	ax,bx
	out	dx,al
	inc	dx
	mov	al,ah
	out	dx,al
	inc	dx		; disable divisor latch access
	inc	dx
	xchg	ax,bx
	and	al,#0x7f
	out	dx,al
	pop	dx		; restore base address

stdbps: 			; CLI: redundant if fell in from above
	push	dx
	add	dx,#4		; address Modem Control Reg.
#if 0
	in	al,dx
	or	al,#3		; turn on DTR and RTS
#else
	mov	al,#3		; turn on DTR and RTS
#endif
	out	dx,al
	pop	dx
	sti			; done
	
	mov	cx,#32		; drain the queue (if any)
drain:	in	al,dx
	loop	drain
	add	dx,#5		; clear the status register
	in	al,dx

    ; send "\r\nLI" to the serial port

	mov	si,#serLI
	mov	cx,#4
ser1:	seg	cs
	lodsb
	call	serdisp
	loop	ser1

nocom:
	ret

#endif		/* LCF_NOSERIAL */



#ifdef SHS_PASSWORDS
#include "shs3.S"
#endif
#include "read.S"
#include "volume.S"
#define SECOND_STAGE_LOADER
#include "mapper.S"
#undef SECOND_STAGE_LOADER
#ifdef LCF_BDATA
#include "bdata.h"
#include "biosdata.S"
#endif
#if defined(MENU) || defined(BITMAP) || DEBUG_NEW
#include "strlen.S"
#endif
#ifdef MENU
#include "graph.S"
#include "menu.S"
#include "crt.S"
#endif
#ifdef BITMAP
#include "bitmap.S"
#include "vesainfo.h"
#include "display4.S"
#endif

! Put tokens into keyboard buffer

putkbd:	add	si,#4		; skip over "kbd="
	push	es
	xor	ax,ax		; set ES to zero
	mov	es,ax
pknext:	lodsb			; get next byte
	or	al,al		; NUL ?
	jz	pkdone		; yes -> done
	cmp	al,#32		; blank ?
	jne	pkrd		; no -> read scan code
pkdone:	dec	si		; return last character
	pop	es		; done
	ret
pkrd:	xor	cx,cx		; clear accumulator
pkrdlp:	cmp	al,#97		; lower case character ?
	jb	pknol		; no -> go on
	sub	al,#32		; make upper case
pknol:	sub	al,#48		; normalize
	cmp	al,#10		; >"9" ?
	jb	pkok		; no -> okay
	cmp	al,#17		; <"A" ?
	jb	pksyn		; yes -> syntax error
	sub	al,#7		; adjust
	cmp	al,#16		; >"F" ?
	jae	pksyn		; yes -> syntax error
pkok:	shl	cx,1		; shift CX
	jc	pksyn		; carry means trouble
	shl	cx,1
	jc	pksyn
	shl	cx,1
	jc	pksyn
	shl	cx,1
	jc	pksyn
	add	cl,al		; put in lowest nibble
	lodsb			; get next byte
	or	al,al		; NUL ?
	jz	pkend		; yes -> at end
	cmp	al,#32		; space ?
	je	pkend		; yes -> at end
	cmp	al,#44		; comma ?
	je	pkmore		; yes -> end of token
	jmp	pkrdlp		; token continues
pksyn:	mov	bx,#msg_pks	; complain
	call	say
pkfls:	lodsb			; flush to end of option
	or	al,al
	jz	pkdone
	cmp	al,#32
	je	pkdone
	jmp	pkfls
pkend:	call	pkput		; store token
	jmp	pkdone		; ... and return
pkmore:	call	pkput		; store token
	jmp	pknext		; handle next token
pkput:	seg	es		; get buffer pointer
	mov	bx,[KBEND]
	mov	dx,bx
	add	dx,#2		; increment it
	cmp	dx,#KBHIGH	; (wrap around end)
	jb	pknadj
	mov	dx,#KBLOW
pknadj: seg	es		; buffer full ?
	cmp	dx,[KBBEG]
	je	pkfull		; yes -> error
	seg	es		; store scan code
	mov	(bx+0x400),cx
	seg	es		; store new pointer
	mov	[KBEND],dx
	ret			; done
pkfull:	mov	bx,#msg_pkf	; complain
	call	say
	pop	ax		; discard return address
	jmp	pkfls		; abort

! Set VGA mode

setvga:	add	si,#4		; skip over "vga="
	push	si		; save SI
	mov	bx,#vgatab	; scan VGA table
svgatb:	pop	si		; get pointer to option value
	push	si
	mov	cx,(bx)		; get VGA code
	or	cx,cx		; at end ?
	jz	vganum		; yes -> must be numeric
	inc	bx		; compare the strings
	inc	bx
vgacmp:	lodsb
	call	upcase		; (case-insensitive)
	mov	ah,(bx)
	inc	bx
	or	ah,ah		; at end ?
	jnz	vgamore		; no -> go on
	or	al,al		; at end of line ?
	jz	vgafnd		; yes -> found it
	cmp	al,#32		; space ?
	je	vgafnd		; yes -> found it
	jmp	svgatb		; try next entry otherwise
vgamore:cmp	al,ah
	je	vgacmp		; equal -> next character
vgaskp:	mov	al,(bx)		; skip to end of reference string
	inc	bx
	or	al,al
	jnz	vgaskp
	jmp	svgatb		; try next entry
vgafnd:	pop	ax		; drop SI

vgaput:	dec	si		; read last character again
vgaput1: mov	vgaovr,cx	; set VGA mode
	clc			; okay, done
	ret

vganum:	pop	si		; get SI
#if 1
	call	strtoul
	jc	vgaerr
	mov	cx,ax
	or	dx,dx
	jnz	vgaerr
	jmp	vgaput1
#else
	xor	cx,cx
	mov	ah,cl
	test	byte ptr (si),#0xff ; no value ?
	jz	vgaerr		; yes -> error
vgadig:	lodsb			; get the next character
	or	al,al		; at end ?
	jz	vgaput		; yes -> done
	cmp	al,#32
	je	vgaput
	cmp	al,#48		; is it a digit ?  (0x30=48="0")
	jb	vgaerr		; no -> error
	cmp	al,#57		; 57=0x39="9"
	ja	vgaerr
	sub	al,#48		; cx = cx*10+al-'0'
	imul	cx,#10
	add	cx,ax
	jnc	vgadig		; next one
#endif

vgaerr:	mov	bx,#msg_v	; display an error message
	call	say
/* ifdef HIGHMEM_MAX */
	xor	eax,eax
	mov	dword ptr [hma],eax
/* endif */
	stc			; return an error
	ret

vgatab:
#ifdef NORMAL_VGA
	.word	ASK_VGA
	.ascii	"ASK"
	.byte	0
	.word	EXTENDED_VGA
	.ascii	"EXTENDED"
	.byte	0
	.word	EXTENDED_VGA
	.ascii	"EXT"
	.byte	0
	.word	NORMAL_VGA
	.ascii	"NORMAL"
	.byte	0
#endif
	.word	0


! get numeric string suffixed with "KkMmGg"
! updates SI

get_K:
	push	cx		; save CX

	call	strtoull	; get number in DX:AX
	jc	gmthis2		; signal conversion error

	mov	bl,(si)		; get next character
	or	bl,#0x20	; convert to lower case
	cmp	bl,#0x6b	; 'K' or 'k' ?
	je	gmthis		; yes -> do not change
#if 1
	mov	cx,#20		; divide or multiply by 2^20
	cmp	bl,#0x67	; 'G' or 'g' ?
	je	gmmul
#endif
	mov	cx,#10		; divide or multiply by 2^10
	cmp	bl,#0x6d	; 'M' or 'm' ?
	je	gmmul

! no Suffix
	dec	si		; will increment later
	
gmdivl:
	shr	eax,cl		; shift by CL
	jmp	gmthis		; done
gmmul:
gmmull:
	shl	eax,1		; shift by 1 each time
	jc	gmvbig		; very big if overflow
	loop	gmmull		; ten times

! exit with no error

gmthis:
	inc	si
	clc			; signal no error
gmthis2:
	mov	bl,(si)		; next character to BL
#if 0
	jc	gmdebug1
	pushad
	push	eax
	call	dout
	mov	bx,#msg_gk
	call	say
	popad
gmdebug1:
#endif
	pop	cx		; restore register
	ret

gmvbig:
	mov	eax,#HIGHMEM_MAX/1024
	jmp	gmthis


! Set memory limit

getmem:
	push	si		; save SI for copying
	add	si,#4		; advance to number?
	call	get_K
	jc	gmcopy		; error, just copy it

	cmp	bl,#0x40	; is it '@'
	jne	gm22
! <size>@<start> format (2.4 kernels)
	push	eax		; save size
	inc	si		; skip '@'
	call	get_K
	pop	edx		; restore size
	jc	memerr
	cmp	eax,#1024	; start : 1meg
	ja	gmcopy		; just copy if above
	add	eax,edx		; EAX = hma/1024
	cmp	eax,#2048	; high : 2meg
	jbe	gmcopy
gm22:
	or	bl,#0x20
	cmp	bl,#0x20	; NUL or SPACE
#if 0
	jne	memerr
#else
	jne	gmcopy		; allow <size>#<start> and <size>$<start>
#endif
	cmp	dword ptr [hma],#0	; set already?
	jne	gmnocopy
	mov	dword ptr [hma],eax	; set it	
gmcopy:	pop	si
gmret:	ret
gmnocopy:  pop	bx
	ret


memerr:
	mov	bx,#msg_me	; numeric conversion error
	call	say
	br	restrt

strtoull:			; numeric conversion to EAX
	call	strtoul
	push	dx
	push	ax
	pop	eax
	ret

strtoul:          /* string to unsigned long in DX:AX */
	xor     ax,ax
	xor     dx,dx
	mov     cx,#10          ; default radix is decimal
	cmp	byte ptr (si),#0x39
	ja	s2lbad		; error if > '9'
	cmp     byte ptr (si),#0x30        ; == '0'?
	jb	s2lbad		; error if < '0'
	jne     s2lnext
	inc     si
	dec     cx
	dec     cx              ; assume octal : CX = 8
	
	cmp     byte ptr (si),#0x58        ; == 'X'?
	je      s2lhex
	cmp     byte ptr (si),#0x78        ; == 'x'?
	jne     s2lnext
s2lhex: add	cx,cx		; it is hexadecimal
	inc     si
s2lnext:
        xor     bx,bx
        mov     bl,(si)         ; get next character

	or	bl,#0x20	; convert to lower case
	sub     bl,#0x30        ; - '0'
	jb      s2ldone
	cmp     bl,cl           ; compare to radix
	jb      s2lmul
	add     bl,#0x30-0x61+10
	cmp     bl,cl           ; compare to radix
	jnb     s2ldone
s2lmul:
        push    dx              ; save high order
	mul     cx              ; multiply by radix
	add     ax,bx
	adc     dx,#0           ; carry possible only in radix 10
	pop     bx
	push    dx
	xchg    ax,bx
	mul     cx
	or      dx,dx
	jnz	s2lbad
	pop     dx
	add     dx,ax
	jc      s2lbad
	xchg    ax,bx
	inc     si
	jmp     s2lnext

s2lbad:	
	stc
	ret
	
s2ldone:
	clc 
	ret

/* new 22.7 */
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
;		(fuzzy selection or exact selection)
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
	
	mov	cx,#IMAGES	; test all names
	mov	si,#DESCR0
	xor	bx,bx		; clear BX
	push	si

fi_nextn:
	mov	di,#cmdline
	test	byte ptr (si),#0xFF	; null descriptor at end
	jz	fi_nomore

fi_nextc:
	mov	al,(si)		; get next character in descr
	inc	si
#ifdef LCF_IGNORECASE
	call	upcase
#endif
	mov	ah,al
	mov	al,(di)		; get next char in cmdline
	inc	di
#ifdef LCF_IGNORECASE
	call	upcase
#endif
	or	al,al		; NUL in command line
	je	fi_pmat
	cmp	al,#32		; SPACE in command line
	jne	fi_cmp

; have partial match, set BX conditionally
fi_pmat:
	or	ah,ah		; NUL in descriptor name
	jz	fi_found	; EXACT match found

	test	byte ptr par2_flag2,#FLAG2_UNATTENDED	; (22.7)
	jnz	fi_skipn	; no partial match if unattended

	or	bx,bx
	jnz	fi_skipn	; already set
	pop	bx
	push	bx
	jmp	fi_skipn	; go to next

fi_cmp:
	cmp	al,ah		; character equal ?
	je	fi_nextc	; compare next character

; advance to next descriptor
fi_skipn:
	pop	si
	add	si,#id_size	; test next name
	push	si
	loop	fi_nextn

fi_nomore:
	pop	si
	or	bx,bx		; fuzzy match?
	jnz	fi_fuzzy

#if defined(MENU) || defined(BITMAP)
	mov	ax,[dimage]
	call	lowlite		; no match, nothing hi-lited
;;;	mov	word [dimage],#0
#endif
	xor	ax,ax		; clears the carry
fi_exit:
	pop	di
	pop	si
	pop	cx
	ret
	
fi_found:
	pop	bx		; BX is matched descriptor
fi_fuzzy:
	mov	ax,bx
	sub	ax,#DESCR0
	mov	cl,#id_size
	div	cl
	cbw
#if defined(MENU) || defined(BITMAP)
	mov	di,[dimage]
	mov	[dimage],ax
	cmp	byte [abs_cx+1],#0	; see if menu is displayed
	je	fi_nochange
	cmp	ax,di
	je	fi_nochange2
	xchg	ax,di
	call	lowlite
	xchg	ax,di
fi_nochange2:
	call	hilite
fi_nochange:
#endif
	stc
	jmp	fi_exit
/* end new 22.7 */

#if DEBUG_NEW
; check that nobody has changed the FS register
fs_check:
	push	ax
	mov	ax,fs
	seg cs
	cmp	ax,[firstseg]
	je	fs_check_okay
; oops, somebody changed it !!!
	pop	ax	; restore
	pop	ax	; get return
	push	cs
	pop	ds
	sub	ax,#3	; length of call
	call    wout
	mov	bx,#msg_fs_changed
	br	zz
fs_check_okay:
#if CHECK_FS_VERBOSE
	pusha
	mov	bp,sp
	mov	ax,16+2(bp)
	sub	ax,#3
	call	wout
	mov	bx,#msg_fs_okay
	push	ds
	push	cs
	pop	ds
	call	say
	pop	ds
	popa
#endif
fs_check_ret:
	pop	ax
	ret
msg_fs_changed:
	.ascii	" <- loc where FS is clobbered\n"
	.byte	0
#if CHECK_FS_VERBOSE
msg_fs_okay:
	.ascii	" <- FS okay\n"
	.byte	0
#endif
#endif

! Some messages

msg_p:	.ascii	"boot: "
	.byte	0

msg_l:	.ascii	"Loading "
	.byte	0

msg_bc:	.ascii	"BIOS data check "
	.byte	0

msg_s:	.ascii	"successful\n"
	.byte	0

msg_by:	.ascii	"bypassed\n"
	.byte	0

msg_re:	.byte	10
	.ascii	"Error 0x"
	.byte	0

msg_nf:	.ascii	"No such image. [Tab] shows a list."
	.byte	10,0

msg_time:
	.ascii	"O - Timestamp mismatch\n"
	.byte	0

msg_chkerr:
	.ascii	"O - Descriptor checksum error\n"
	.byte	0

msg_chkkey:
	.ascii	"O - Keytable read/checksum error\n"
	.byte	0

msg_confl:
	.ascii	"Kernel and Initrd memory conflict\n"
	.byte	0

msg_sigerr:
	.ascii	"O - Signature not found\n"
	.byte	0

msg_me: .byte	10
	.ascii	"vga/mem=  requires a numeric value"
	.byte	10,0

msg_wrerr:	.ascii	"\nMap file write; BIOS error code = 0x"
	.byte	0

msg_wrerr3:	.ascii	"\nMap file: WRITE PROTECT\n"
	.byte	0

#ifdef MEMORY_CHECK
msg_mem: .ascii	"EBDA is big; kernel setup stack overlaps LILO second stage"
	.byte	10,0
#endif

#ifdef LCF_VIRTUAL
msg_vmwarn:
	.ascii	"WARNING:  Booting in Virtual environment\n"
	.ascii	"Do you wish to continue? [y/n] "
	.byte	0
#endif

#if DEBUG_NEW
sdx:	.ascii	" DX="
	.byte	0

msg_pl:	.ascii	"\nParameter line = "
	.byte	0
#ifdef LCF_NOKEYBOARD
msg_kbtest:
	.ascii	"**PC/AT Keyboard test**\n"
	.byte	0
#endif

#if defined(LCF_VIRTUAL) || defined(LCF_NOKEYBOARD)
msg_real:
	.ascii	"Performing REAL MODE boot\n"
	.byte	0

#ifdef LCF_VIRTUAL
msg_virtual:
	.ascii	"Performing VIRTUAL MODE boot\n"
	.byte	0
#endif
#ifdef LCF_NOKEYBOARD
msg_no_keyboard:
	.ascii	"Performing NO KEYBOARD DEFAULT boot\n"
	.byte	0
#endif
#endif

msg_where:
	.ascii	"\nINIT SETUP CODE SS:SP  EX_OFF_DX 2ndDX\n"
	.byte	0

msg_low: .ascii	" low"
	.byte	0

msg_high:  .ascii " high"
	.byte	0

hdr1:	.ascii	"\nHeader 0x"
	.byte	0

hdr2:	.ascii	" cmdline at "
	.byte	0

hdr4:	.ascii	"   length = 0x"
	.byte	0

hdr3:	.ascii	"\nRamdisk_max "
	.byte	0

nohdrs:	.ascii	"\nNo cmdline passed"
	.byte	0

msg_rd2: .byte	10
	.ascii	"RAM disk loaded at: "
	.byte	0

msg_hma: .ascii	" is the HMA\n"
	.byte	0

msg_gk:	.ascii	" returned by 'get_K'\n"
	.byte	0

#endif

msg_int:.byte	10
	.ascii	"*Interrupted*"
	.byte	10,0

msg_eof:.byte	10
	.ascii	"Unexpected EOF"
	.byte	10,0

msg_pw:	.ascii	"Password: "
	.byte	0

msg_pf:	.ascii	"Sorry."
	.byte	10,0

msg_v:	.byte	10
	.ascii	"Valid vga values are ASK, NORMAL, EXTENDED or a "
	.ascii	"decimal number."
	.byte	10,0

msg_pks:.byte	10
	.ascii	"Invalid hexadecimal number. - Ignoring remaining items."
	.byte	10,0

msg_pkf:.byte	10
	.ascii	"Keyboard buffer is full. - Ignoring remaining items."
	.byte	10,0

msg_bm:	.byte	10
	.ascii	"Block move error 0x"
	.byte	0

#if 0
msg_rd:	.byte	10
	.ascii	"Not enough memory for RAM disk"
	.byte	10,0
#else
msg_rd4M: .byte	10
	.ascii	"Initial ramdisk loads below 4Mb; "
	.ascii	"kernel overwrite is possible."
	.byte	10,0
#endif

ospc:	.ascii	"O"
#ifdef LCF_BEEP
	.byte	7
#endif
#ifdef LCF_VERSION
	.ascii	" "	
	.ascii	S(VERSION_MAJOR)
	.ascii	"."
	.ascii	S(VERSION_MINOR)
	.ascii	VERSION_EDIT
#endif
	.byte	32,0

bs:	.byte	8,32,8,0

#ifdef DEBUG
stepa:	.ascii	" RAM disk,"
	.byte	0
step0:	.ascii	" map page,"
	.byte	0
step0b:	.ascii	" fallback,"
	.byte	0
step1:	.ascii	" options,"
	.byte	0
step1b:	.ascii	" fallback,"
	.byte	0
step2:	.ascii	" boot,"
	.byte	0
step3:	.ascii	" setup,"
	.byte	0
step4:	.ascii	" system "
	.byte	0

sax:	.ascii	"AX="
	.byte	0
sbx:	.ascii	" BX="
	.byte	0
scx:	.ascii	" CX="
	.byte	0
ses:	.ascii	" ES="
	.byte	0
sdone:	.byte	10
	.byte	0

mov_ar:	.ascii	" -> "
	.byte	0
mov_sz:	.ascii	", words "
	.byte	0
#endif

	.even

init_dx:	.word	0

#if defined(MENU) || defined(BITMAP)
suppress:.word	0		; suppress console output (MUST be word)
#endif
hinib:  .byte   0               ; hi-nibble of address
tempal:	.byte	0
moff:	.word	0		; map offset
map:	.word	MAP		; map to use

cntdown:.word	0		; count-down
timeout:.byte	0		; timed out

dolock:	.byte	0

int1c_l:.word	0		; old timer interrupt
int1c_h:.word	0

old_del:.word	0		; delay before booting

nodfl:	.word	0		; action if no defaults are present

#ifndef LCF_NOSERIAL
slbase:	.word	0		; serial port base (or 0 if unused)
break:	.byte	0		; break received flag
#endif

usrinpm:.byte	UI_MAGIC

cmdbeg:	.word	0
options:.word	0

rdbeg:	.word	0,0		; RAM dist begin address (dword)

rdszl:	.word	0		; RAM disk size
rdszh:	.word	0

vgaovr:	.word	0		; VGA mode overwrite

/* ifdef HIGHMEM_MAX */
hma:	.word	0,0		; Highest Memory Address
memmap:	.word	0,0,0,0,0,0,0,0,0,0
/* endif */
dskprm:	.word	0,0,0,0,0,0

	.even			; control alignment from here down
acmdbeg:.ascii	"auto "
mcmdbeg:.ascii	"BOOT_IMAGE"
prechr:	.byte	32		; space: guard double blank supression
				; equal sign: variable assignment
cmdline:.byte	0

#ifdef BITMAP
_line	=	cmdline+CL_LENGTH		; must be 640 bytes long
#endif
	.org	*+4
theend:

lkwbuf	=	cmdline+CL_LENGTH+2	; this is a word
lkcbuf	=	lkwbuf+2
theend2 =	lkcbuf+CL_LENGTH	; lkcbuf is 256

the_end1	= theend+511
theends	=	the_end1/512
	.org	theends*512-4
	.long	X
	.align	512
max_secondary:

#if 0
/* the older version 21 layout */
Map		=	max_secondary + SECTOR_SIZE
Dflcmd		=	Map + SECTOR_SIZE
Map2		=	Dflcmd
Descr		=	Dflcmd + SECTOR_SIZE
Keytable	=	Descr + SECTOR_SIZE*MAX_DESCR_SECS_asm
ParmBSS		=	Keytable + SECTOR_SIZE
#else
/* a possible 22.5.6 layout puts the descriptors last */
Map		=	max_secondary + SECTOR_SIZE
Dflcmd		=	Map + SECTOR_SIZE
Map2		=	Dflcmd
Keytable	=	Dflcmd + SECTOR_SIZE
Descr		=	Keytable + SECTOR_SIZE
ParmBSS		=	Descr + SECTOR_SIZE*MAX_DESCR_SECS_asm
#endif

#if COMMAND_LINE_SIZE > 256
BSSstart	=	ParmBSS
Parmline	=	BSSstart + SECTOR_SIZE
#else
Parmline	=	ParmBSS
BSSstart	=	Parmline + CL_LENGTH
#endif

!************************************
!  BSS data:
!     moved from  volume.S 

#define BSS_DATA
	.org	BSSstart
#include "volume.S"
#ifdef SHS_PASSWORDS
#include "shs3.S"
#endif

	.align	512
BSSend	=	*
BSSsize		=	BSSend-BSSstart


Dataend		=	Parmline + SECTOR_SIZE

	.org	max_secondary



#if 0
DESCR0 = DESCR+2
#else
DESCR0 = DESCR
#endif
