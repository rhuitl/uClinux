;  mbr.S -- Master Boot Record to boot first partition marked active
;
; Copyright 2002-2004 John Coffman.
; All rights reserved.
;
; Licensed under the terms contained in the file 'COPYING' in the 
; source directory.
;

/* set to 1 for debugging output */
#define DEBUG 0

#define SEARCH 1		/* turn on search for device code */
#define CYL1023 0		/* 1==compare to 1023 / 0==fn8 cyl #    */
#define PASS_PARAMS 1		/* 1==pass lilo parameters */
#define BYPASS18 0		/* bypass int 18h exit */

#ifdef MBX
# define EXT_PART 1		/* search extended partitions, too */
/*# define VIDEO_ENABLE		/ we just have no space for this */
# define VIDEO_ENABLE		/* we now do have space for this */
#else
# define EXT_PART 0		/* search primary partition only */
# define VIDEO_ENABLE
#endif

DELAY	= 12			/* tenths of a second */

#if DEBUG
STEP	= 1			/* delay is in seconds if DEBUG */
# ifdef VIDEO_ENABLE
/*#  undef VIDEO_ENABLE*/
# endif
#else
STEP	= 10			/* delay is in deciseconds if not DEBUG */
#endif

#define LILO_ASM
#include "lilo.h"


	.text

	.globl	_main

	.org	PARTS_LOAD

zero:
_main:	cli			! NT 4 blows up if this is missing
	jmp	start

#if EXT_PART
stage:	.byte	STAGE_MBR2	! search extended partitions, too
#else
stage:	.byte	STAGE_MBR	! search primary parition only
#endif

	.org	PARTS_LOAD+6
sig:	.ascii	"LILO"		! signature
vers:	.word	VERSION

! the disk I/O packet	DS:SI uses it
packet:	.word	16		! size of packet
	.word	1		! count of sectors to transfer
addr:	.word	BOOTSEG*16	! address offset to transfer to
	.word	0		! address segment to transfer to
daddr:	.long	0		! low order disk address
	.long	0		! high order disk address
! end of packet


	
#if DEBUG
#if !SEARCH
dout:	push	ax		! save low half
	shr	eax,#16
	call	wout		! put out high word
	pop	ax
wout:	push	ax
	xchg	ah,al		! put out AH first
	call	bout
	pop	ax		! restore AL
#endif
bout:	push	ax		! convert & output hex byte in AL
	shr	al,#4		! high nibble
	call	nout
	pop	ax		! low nibble
nout:	and	al,#0x0F	! write the nibble in low half of AL
	daa			! convert to upper case hex character
	add	al,#0xF0	! **
	adc	al,#0x40	! **
cout:	push	bx		! write character to the console
	mov	ah,#0x0E	! video BIOS function 14
	mov	bh,#0
	int	0x10		! video interrupt
	pop	bx
	ret
#endif

say:	pop	si		! get CS:SI pointer to character string
say1:	lodsb			! but DS==CS, so this works
	or	al,al		! NUL terminated?
	jz	say9
#if DEBUG
	call	cout
#else
	mov	ah,#0x0E	! in-line character write routine
	mov	bx,#07		! write to page 0
	int	0x10		! video interrupt
#endif
	jmp	say1
say9:
#if DEBUG
	jmp	si		! return from "say:"
#endif
stop:
#if DEBUG
	hlt			! wait for interrupt
	jmp	stop		! loop back after interrupt
#else
#if BYPASS18
	xor	eax,eax		! EXPERIMENTAL code
	mov	[daddr],eax	! zero the disk address
	inc	dx		! try the next device code
	call	disk_read	! read sector 0
	jmpi	(addr)
#else
	mov	cx,#DELAY*16/STEP  ! delay DELAY/10 seconds, DX doesn't matter

	mov	ah,#0x86
	int	0x15		! delay call

	int	0x18		! exit to BIOS

#endif	/* BYPASS18 */
#endif	/* DEBUG */

start:
	xor	ax,ax			! all addressing from 0000:0000
	mov	ss,ax			! set up the stack
	mov	sp,#BOOTSEG*16		! #0x7C00
	sti				! enable interrupts
#if PASS_PARAMS
	mov	cx,sp
	push	es
	push	bx
	push	si
	push	dx
	mov	si,cx
#else
	mov	si,sp			! from here 0000:7C000
#endif
	cld				! clear direction flag (UP)
	mov	ds,ax			! DS=0
	mov	es,ax			! ES=0
	mov	di,#PARTS_LOAD		! move to here 0000:0600
	mov	cx,#SECTOR_SIZE/2	! one sector worth
	rep
	  movsw				! move words
	jmpi	go,0			! intersegment jump 0:go
go:
#ifdef VIDEO_ENABLE
	pusha			! certain video cards trash DX
#if 0
	mov	al,[0x449]		! get video mode
	cbw
#else
	mov	ax,#0x1200	! enable video (VGA)
	mov	bl,#0x36	! (probably a nop on EGA or MDA)
#endif
	int	0x10		! 

	popa			! DX must be protected from rogue video cards
#endif

#if SEARCH
	mov	edi,[serial_no]		! serial number to look for
	or	edi,edi
	jz	use_boot

	mov	ah,#8		! get number of hard drives
	mov	dl,#0x80
	int	0x13
	movzx	cx,dl

	xchg	ax,dx		! save device code in AX
	mov	dx,#0x80	! device 80

vagain:
	call	disk_read	

	cmp	edi,[BOOTSEG*16+PART_TABLE_OFFSET-6]
	je	vol_found
	inc	dx		! try next device
	loop	vagain

	xchg	ax,dx		! try what we were passed

vol_found:
use_boot:

#endif

#if DEBUG
	call	say			! debugging dump of DL
	.ascii	"DL="
	.byte	0
	mov	ax,dx
	call	bout			! write the byte in AL
#if !SEARCH
	mov	al,#0x20
	call	cout
	mov	eax,[serial_no]		! serial number to look for
	call	dout
#endif
	call	say
	.byte	13,10,0
#endif	
	mov	si,#p_table		! scan the partition table 
#if EXT_PART
	xor	edi,edi			! BASE = 0
#endif
	mov	cx,#4			! 4 entries
find_active:
#if EXT_PART
	call	is_ext			! test for extended
#endif
	test	byte ptr (si),#0x80	! test hi-bit
	mov	bp,si			! save possible ptr
	js	one_found		! found Active if sign bit set
	add	si,#16			! move to next entry
	loop	find_active		! & loop back

#if EXT_PART
/* no primary partition was marked active */
	xchg	edi,ebp			! EBP = base, EDI = second
	xor	edi,edi

/* extended partitions exist, search them */
ext_search:
	add	edi,ebp			! second += base
	mov	[daddr],edi
	call	disk_read
	mov	si,#BOOTSEG*16+PART_TABLE_OFFSET	! pt[0]
	test	byte ptr (si),#0x80	! test hi-bit
	js	boot_si			! one to boot if set
	add	si,#16			! pt[1]
	call	is_ext			! will set EDI
	jz	ext_search
#endif

	call	say			! comment & quit
#if DEBUG
	.ascii	"nPa"
#else
	.ascii	"No partition active"
#endif
	.byte	13,10,0
#if DEBUG
stop1:	br	stop
#endif


#if !EXT_PART
find_more:				! check for more that one partition
#if EXT_PART
	call	is_ext			! continue check for extended part.
#endif
	test	byte ptr (si),#0x80	! with active bit set
	jns	one_found
	call	say			! oops, a second partition is active
#if DEBUG
	.ascii	"iPT"
#else
	.ascii	"Invalid PT"
#endif
	.byte	13,10,0			! comment & quit
#if DEBUG
	jmp	stop1
#endif

one_found:				! one partition is active
	add	si,#16			! go on & test others
	loop	find_more		! continue the loop

; BP points at the only active partition

	mov	si,bp		; now SI points at active partition
#else
one_found:
#endif	/* !EXT_PART */

boot_si:
	mov	eax,(si+8)	; get partition start
#if EXT_PART
	add	[daddr],eax	; set disk address
#else
	mov	[daddr],eax	; set disk address
#endif
	call	disk_read	; read sector

boot_it:
;;;	seg	es			! DS==ES, so don't need prefix
	cmp	word ptr [BOOTSEG*16+BOOT_SIG_OFFSET],#0xAA55	! look for boot signature
	jne	no_boot			! not bootable if no sig.

#ifdef LCF_COHERENT
	mov	(si),dl		; move into partition table
#endif
	xor	ax,ax		; signal no disk error
#if DEBUG
	pusha
	call	say
	.ascii	"B:"
	.byte	13,10,0

	mov	cx,#DELAY*16/STEP/2  ! delay DELAY/10 seconds, DX doesn't matter

	mov	ah,#0x86
	int	0x15		! delay call
	popa
#endif
#if PASS_PARAMS
	pop	ax		! check for possible params
	cmp	al,#0xFE	!
	jne	no_params
	mov	ah,dl
	pop	si
	pop	bx
	pop	es
	xchg	ax,dx
no_params:
#endif
	jmpi	(addr)


no_boot: call	say
#if DEBUG
	.ascii	"nBs"
#else
#if EXT_PART
;;;	.ascii	"No 0xAA55 in partition"
	.ascii	"No boot sig. in partition"
#else
	.ascii	"No boot signature in partition"
#endif
#endif
	.byte	13,10,0
#if DEBUG
	jmp	stop1
#endif

! packet read routine
disk_read:
	pusha
	mov	bp,#12		! retry count

disk_retry:
	mov	si,#packet
	mov	bx,#0x55AA	;magic number
	mov	ah,#0x41
	int	0x13
	jc	disk_convert
	cmp	bx,#0xAA55	;changed?
	jne	disk_convert
	test	cl,#EDD_PACKET	;EDD packet calls supported
	jz	disk_convert

	mov	ah,#0x42
	jmp	disk_int13


disk_convert:
	push	dx
	mov	ah,#8		! get geometry
	int	0x13
	jc	disk_error12

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

	and	cx,#0x003f	;CX is number of sectors
	mul	cx		; kills DX also
	xchg	ax,bx	   	;save in BX

	mov	ax,[daddr]	;low part of address
	mov	dx,[daddr+2]	;hi part of address
	
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
	mov	ax,#0x201	;read, count of 1

disk_int13:
	les	bx,[addr-packet](si)	! for both reads
	int	0x13
	jc	disk_error1
disk_ret:
	popa
	ret


disk_error2:
	mov	ah,#0x40	; signal seek error
disk_error12:
	pop	dx
disk_error1:
	dec	bp
	jz	disk_error0

;;	mov	ah,#0x0D	! reset fixed disk controller
	xor	ah,ah
	int	0x13
	jmp	disk_retry

disk_error0:
disk_error:
#if DEBUG
	xchg	al,ah		; error code to AL
	call	bout
	call	say
	.ascii	"=dRe"
#else
	call	say		; something is wrong with the disk read
	.ascii	"Disk read error"
#endif
	.byte	13,10,0
#if DEBUG
	br	stop
#endif



#if EXT_PART
/* return ZF=1 if SI -> extended partition and set EDI */
is_ext:
	mov	al,(si+4)		; get partition type
	cmp	al,#PART_DOS_EXTD
	jz	is_extd
	cmp	al,#PART_WIN_EXTD_LBA
	jz	is_extd
	cmp	al,#PART_LINUX_EXTD
	jnz	is_extr
is_extd:
	mov	edi,(si+8)		; get start to edi
is_extr:
	ret
#endif

theend1:	/* better be at or below 07B6 */

	.org	PARTS_LOAD+MAX_BOOT_SIZE
	.word	0
serial_no:	.blkb	4	! volume serial number
	.blkb	2

!!!	.org	0x1be		! spot for the partition table
p_table:
	.blkb	16		! the partition table is filled in
	.blkb	16		! when this Master Boot Record is installed
	.blkb	16		! just leave space
	.blkb	16		! here
#if defined MBX
	.org	*-2
	.long	MBX		! boot block signature check
#elif defined MBR
	.org	*-2
	.long	MBR		! boot block signature check
#else
	.word	0xAA55		! boot block signature goes here
#endif

theend:	! must be 0000:0800
