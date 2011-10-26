#if 0
;  first.S  -  LILO first stage boot loader with LBA32 support */
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

#endif
#define LILO_ASM
#include "lilo.h"
get common.s		/* as86 "include" will bypass the CPP */

#define DEBUG 0

#if VERSION_MINOR>=50
# define DEBUG_NEW

# undef VIDEO_ENABLE
# define VIDEO_ENABLE 3

# define VALIDATE !DEBUG	/* adds 0Dh bytes */
# define SECOND_CHECK !DEBUG	/* adds  5h bytes */
# define CYL1023 DEBUG		/* subs  8h bytes */
# define GEOMETRIC !DEBUG	/* adds  1h byte  */

# if DEBUG
#  define DEBUG_LARGE
# endif
#else

# define VALIDATE 1		/* adds 0Dh bytes */
# define SECOND_CHECK 1		/* adds  5h bytes */
# define CYL1023 0		/* subs  8h bytes */
# define GEOMETRIC 1		/* adds  1h byte  */
#endif


!  VIDEO_ENABLE	for those systems that disable the video on boot
!	= 0		first stage does not enable video
!	= 1		use get vid mode/set vid mode to enable
!	= 2		use VGA enable call to enable video
!			(cannot use, as code gets too big)
!	= 3		use direct mode set (mode 3, CGA, EGA, VGA)
!	= 7		use direct mode set (mode 7, MDA)
!
#ifndef VIDEO_ENABLE
# if VALIDATE==0
#  define VIDEO_ENABLE 2
# else
#  define VIDEO_ENABLE 2
# endif
#endif

! do not change the following -- it must correspond to the code in bsect.c
#define RELOCATABLE -1


	.text

	.globl	_main

	.org	0

zero:
_main:	cli			! NT 4 blows up if this is missing
	jmp	start

stage:	.byte	STAGE_FIRST
	.org	4
reloc:
#if RELOCATABLE
	.word	theend-zero	! size of the code & params
#else
	.word	0		! no size indication
#endif
	.org	6

! Boot device parameters. They are set by the installer.

sig:	.ascii	"LILO"
vers:	.word	VERSION
mapstamp: .long 0		! map timestamp

length	=  *-sig		! for the stage 1 vs stage 2 comparison

raid:	.long	0		! raid sector offset
tstamp:	.long	0		! timestamp
map_serial_no:	.long	0	! volume S/N containing map file
prompt:	.word	0		! indicates whether to always enter prompt
				! contains many other flags, too

d_dev:	.byte	0x80		! map file device code
d_flag:	.byte	0		! disk addressing flags
d_addr:	.long	0		! disk addr of second stage index sector


edd_packet	=  0
;;;	.word	16		! size of packet
;;;	.word	1		! count of bytes to read

edd_addr	=  4
;;;	.word	map2		! where to read
;;;	.word	*-*		! segment where to read

edd_d_addr	=  8
;;;	.long	1		! low address or CX,DX (geometric)
				! start at sector 1 for search in geo mode

;;;	.long	0		! hi address

#if 0
!  These locations are referenced as EX_OFF 
!					(they used to be at CODE_START_1)
ext_si:	.word	0		! external interface
ext_es:	.word	0		! these locations are referenced in second.S
ext_bx:	.word	0		! do not disturb the ordering
ext_dl:	.byte	0		! second.S will check this magic number
ext_dh:	.byte	0		! not referenced, but must align stack
ext_stack:
#endif
	
/***************************************************/
!	The following instruction MUST be
!	first instruction after the CLI/JMP short
!	at the start of the file; otherwise
!	the boot sector relocation fails.
!
start:
	mov	ax,#BOOTSEG	! use DS,ES,SS = 0x07C0
/***************************************************/

	mov	ss,ax
	mov	sp,#SETUP_STACKSIZE	! set the stack for First Stage
	sti			! now it is safe

	push	dx		! set ext_dl (and ext_dh, which is not used)
	push	bx		! WATCH the order of pushes
	push	es		! set ext_es
	push	si		! set ext_si

#ifdef DEBUG_NEW
	push	ds
	push	es	! just not enough space with debug turned on
#endif

#define JRC_DS_EQ_SS

	cld			! do not forget to do this !!!
	mov	ds,ax		! address data area
	xor	bp,bp		! shorted addressing

#if VIDEO_ENABLE
! a BIOS has been found where the video interrupt (0x10) trashes DX
!   so, we had better be very paranoid about DX
!
# if VIDEO_ENABLE==2
	pusha			! protect DX
# endif
# if VIDEO_ENABLE > 2
	mov	ax,#VIDEO_ENABLE	! set video mode 3 or 7
# elif VIDEO_ENABLE==1
	mov	ah,#15		! get video mode
	int	0x10
	cbw
# else  /* VIDEO_ENABLE==2 */
	mov	ax,#0x1200	! enable video (VGA)
	mov	bl,#0x36	! (probably a nop on EGA or MDA)
# endif
	int	0x10		! video call
# if VIDEO_ENABLE==2
	popa			! restore DX
# endif
#endif

#if (VIDEO_ENABLE&1) == 0
	mov	al,#0x0d	! gimme a CR ...
	call	display
; the suspect call for trashing DX on one BIOS:
	mov	al,#0x0a	! ... an LF ...
	call	display
#endif

#if defined(DEBUG_NEW)
	mov	ah,dl
	call	bout		! code in AH
#endif
	mov	al,#0x4c	! ... an 'L' ...
	call	display

lagain:
	pusha			! preserve all the registers for restart

	push	ds
	pop	es		! use buffer at end of boot sector

	cmp	dl,#EX_DL_MAG	! possible boot command line (chain.S)
	jne	boot_in_dl
	mov	dl,dh		! code passed in DH instead
boot_in_dl:

	mov	bx,#map2	! buffer for volume search
	mov	dh,[d_dev](bp)  ! map device to DH

#if VALIDATE
	mov	ax,dx		! copy device code to AL
	and	ah,#0x80	! AH = 00 or 80
	xor	al,ah		! hi-bits must be the same
	js	use_installed
	cmp	al,#MAX_BIOS_DEVICES	! limit the device code
	jae	use_installed	! jump if DL is not valid
#endif

! map is on boot device for RAID1, and if so marked; viz.,

	test	byte ptr [prompt](bp),#FLAG_MAP_ON_BOOT
	jnz	use_boot	! as passed in from BIOS or MBR loader

use_installed:
	mov	dl,dh		! device code to DL
	mov	esi,[map_serial_no](bp)	! to search for
	or	esi,esi
	jz	done_search

	push	dx		! save flags

	mov	ah,#8		! get number of hard disks
	mov	dl,#0x80
	push	bx		! paranoia
	int	0x13
	pop	bx
	jc	error

	movzx	cx,dl		! extend to word in CX

#if GEOMETRIC
	mov	dx,#0x80-1	! device 80, flags=0
#else
	mov	dx,#LBA32_FLAG*256+0x80-1	! device 80, flags=LBA32
#endif

vagain:
	inc	dx
	xor	eax,eax
#if GEOMETRIC
	inc	ax		! geometric addressing
#endif
	call	disk_read	! read 

	cmp	esi,[PART_TABLE_OFFSET-6](bx)
	je	vol_found
	loop	vagain

	pop	dx		! restore specified BIOS code
				! AX and DX are identical at this point

vol_found:
		! uses value in DX, stack may have extra value

done_search:	
use_boot:
	push	bx		! save map2 for later

	mov	dh,[d_flag](bp)	! get device flags to DH
	mov	si,#d_addr
	call	pread		! increments BX

	mov	ah,#0x99	! possible error code
	cmp	dword (bx-4),#EX_MAG_HL	! "LILO"
	jne	error

	pop	si		! point at #map2

#if 1
	push	#SETUP_STACKSIZE/16 + BOOTSEG + SECTOR_SIZE/16*2
	pop	es
#else
	mov	ax,ds		! get segment
	add	ax,#SETUP_STACKSIZE/16    !   + SECTOR_SIZE/16*2
	mov	es,ax
#endif
	xor	bx,bx

sload:
	call	pread		! read using map at DS:SI
	jnz	sload		! into memory at ES:BX (auto increment)

! Verify second stage loader signature
	
	mov	si,#sig		! pointer to signature area
	mov	di,si
	mov	cx,#length	! number of bytes to compare
	mov	ah,#0x9A	! possible error code
	repe
	  cmpsb			! check Signature 1 & 2
	jne	error	! check Signature 2

#if SECOND_CHECK
/* it would be nice to re-incorporate this check */
	mov	al,#STAGE_SECOND	! do not touch AH (error code)
	scasb
	jne	error
#endif

! Start the second stage loader     DS=location of Params

	push	es		! segment of second stage
	push	bp		! BP==0

	mov	al,#0x49	! display an 'I'
	call	display

	retf			! Jump to ES:BP




disk_error2:
	mov	ah,#0x40	; signal seek error

! no return from error
error:

#ifndef LCF_NO1STDIAG
        mov	al,#32          ! display a space
	call	display0

	call	bout
#endif

#ifndef DEBUG_LARGE
	dec	byte [zero](bp)		!  CLI == 0xFA == 250
	jz	zzz

#ifndef DEBUG_NEW
	mov	sp,#SETUP_STACKSIZE-4*2-8*2	! set the stack for First Stage
#else
	mov	sp,#SETUP_STACKSIZE-4*2-2*2-8*2	! set the stack for First Stage
#endif
	popa				! restore registers for restart
	jmp	near lagain		! redo from start
#endif


zzz:
#ifndef DEBUG_NEW
	hlt
#endif
	jmp	zzz		! spin; wait for Ctrl-Alt-Del




! packet read routine

disk_read:
#ifndef JRC_DS_EQ_SS
	push	ds
#endif
	pusha

#ifndef JRC_DS_EQ_SS
	push	ss
	pop	ds
#endif

	push	bp		! BP==0
	push	bp		! BP==0

	push	eax		! low order disk address
#ifdef DEBUG_LARGE
	xchg	ax,dx
	call	wout
	xchg	ax,dx
	call	dout		! print out disk address
#endif
	push	es		! memory segment ES
	push	bx		! memory offset BX
	push	#1		! sector count
	push	#16		! size of packet = 16 bytes
	mov	si,sp		! address of packet  DS:SI

	push	bx

	test	dh,#LINEAR_FLAG|LBA32_FLAG
	jz	disk_geometric
	
	test	dh,#LBA32_FLAG
	jz	disk_convert	; it must be LINEAR

	mov	bx,#0x55AA	;magic number
	mov	ah,#0x41
	int	0x13
	jc	disk_convert
	cmp	bx,#0xAA55	;changed?
	jne	disk_convert
	test	cl,#EDD_PACKET	;EDD packet calls supported
	jnz	disk_edd

disk_convert:
	push	dx
	push	es		! protect on floppies
	mov	ah,#8		! get geometry
	int	0x13
	pop	es
disk_error3:			! transfer through on CF=1
	jc	error		! disk_error12

#if !CYL1023
	push	cx
	shr	cl,#6		;;;;
	xchg	cl,ch	   ;CX is max cylinder number
	mov	di,cx	   ;DI saves it
	pop	cx
#endif
	shr	dx,#8
	xchg	ax,dx		;AX <- DX
	inc	ax		;AX is number of heads (256 allowed)

; compensate for Davide BIOS bug
	dec	cx		; 1..63 -> 0..62;  0->63
	and	cx,#0x003f	;CX is number of sectors
	inc	cx		; allow Sectors==0 to mean 64

	mul	cx		; kills DX also
	xchg	ax,bx	   	;save in BX

	mov	ax,[edd_d_addr](si)	;low part of address
	mov	dx,[edd_d_addr+2](si)	;hi part of address

	cmp	dx,bx
	jae	disk_error2	;prevent division error

	div	bx		;AX is cyl, DX is head/sect
#if CYL1023
	cmp	ax,#1023
#else
	cmp	ax,di
#endif
	ja	disk_error2	;cyl is too big

	shl	ah,#6		; save hi 2 bits
	xchg	al,ah
	xchg	ax,dx
	div	cl		;AH = sec-1, AL = head
	or	dl,ah	   ;form Cyl/Sec
	mov	cx,dx
	inc	cx		; sector is 1 based

	pop	dx		! restore device code
	mov	dh,al		! set head#
	jmp	disk_read2



disk_edd:
	mov	ah,#0x42
disk_int13:
	pop	bx

	mov	bp,#5
disk_retry:
	pusha
	int	0x13
#if 0
	stc
	mov	ah,#0x9C
#endif
	jnc	disk_okay

	dec	bp		! does not alter CF, already 0
	jz	disk_error3	! go to "jc" with CF=1 & ZF=1

	xor	ax,ax		! reset the disk controller
	int	0x13
	popa			! reset AX,BX,CX,DX,SI
	dec	bp		! fix up BP count
	jmp	disk_retry


disk_geometric:
	push	eax
	pop	cx
	pop	ax
	mov	dh,ah

disk_read2:
	mov	ax,#0x201	;read, count of 1
	jmp	disk_int13


disk_okay:
; the pusha block is implicitly removed below
;;;	mov	(si+2*16-1),ah	! set error code
;   the error code is never checked
	lea	sp,(si+16)	! do not touch carry; 
	popa
#ifndef JRC_DS_EQ_SS
	pop	ds
#endif
	ret



! Pointer Read -- read using pointer in DS:SI

pread:
	lodsd			! get address
	or	eax,eax
	jz	done
	add	eax,[raid](bp)	! reloc is 0 on non-raid
	call	disk_read	

	add	bh,#SECTOR_SIZE/256    	! next sector
done:
	ret




#if !defined(LCF_NO1STDIAG) || defined(DEBUG_NEW)
bout:	rol     ax,#4		! bring hi-nibble to position
	call	nout
	rol     ax,#4		! bring lo-nibble to position
nout:	and	al,#0x0F	! display one nibble
	daa			! shorter conversion routine
	add	al,#0xF0
	adc	al,#0x40	! is now a hex char 0..9A..F
#endif
; display - write byte in AL to console
;	preserves all register contents
; 
display0:
#ifndef LCF_NOVGA
display:
#endif
	pusha		! make sure no register is changed
	mov	bx,#7		!  BH=0, BL=07
	mov	ah,#14
	int	0x10
	popa		! restore all the registers
#ifdef LCF_NOVGA
display:
#endif
	ret

#ifdef DEBUG_LARGE

dout:	pushad
	ror	eax,#16
	call	wout
	ror	eax,#16
	call	wout
	mov	al,#0x20	! space
	call	display
	popad
	ret

wout:	push	ax
	call	bout	! put out AH
	pop	ax
	push	ax
	xchg	al,ah
	call	bout	! put out AL (now in AH)
	pop	ax
	ret
#endif

theend:

!
!   If 'first' loads as the MBR, then there must be space for the partition
!   table.  If 'first' loads as the boot record of some partition, then
!   the space reserved below is not used.  But we must reserve the area
!   as a hedge against the first case.
!
!
	.org	MAX_BOOT_SIZE	!
	.word	0,0,0,0		! space for NT, DRDOS, and LiLO volume S/N

!	.org	0x1be		! spot for the partition table
p_table:
	.blkb	16
	.blkb	16
	.blkb	16
	.blkb	16
#ifdef FIRST
	.org	*-2
	.long	FIRST		! boot block check
#else
	.word	0xAA55		! boot block signature
#endif

! Better be exactly 0x200

map2	equ	*		! addressed as ES:[map2]
