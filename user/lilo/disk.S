/*
; disk.S -- inquire of BIOS and display disk parameters
;
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/
#define DEBUG 0
#define DELL_DIRTY_HACK


SYSSEG	=  0x1000	; DEF_SYSSEG
SETUPSEG = 0x9020	; DEF_SETUPSEG


		.text
#if 1
.globl	_main
_main:
#endif
		.globl	zero
zero:

; we want this to look like a bootable kernel image
; so we include the following header
;
		jmp	begin
		.ascii	"HdrS"		; Signature for Setup header
		.word	0x0201		; header format version number
		.word	0,0		; realmode switch, SETUPSEG
		.word	SYSSEG		; SYSSEG -- load at 1000:0000
		.word	id_string
		.byte	0		; type of loader
		.byte	0		; flags 0=load low
		.word	0x200		; move size
		dd	0x1000		; load us here
		dd	0		; ramdisk image
		.word	bs_helper,SETUPSEG	; kludge???
		.word	modelist+1024	; heap end pointer
;----------end of header------------
		
begin:
                mov     ax,cs
		cli                     ;make purists happy
                mov     ss,ax
                mov     sp,#0x7FFE
		sti                     ; ***
                call    start           ;do not separate from the instruction below
start:          pop     bx              ;this MUST immediately follow the 'call'
                sub     bx,#start-zero
                lea     bp,zero
                sub     bx,bp           ;BX=100h under DOS, BX=0h under BIOS
                mov     cl,#4
                sar     bx,cl
                add     ax,bx
                mov     ds,ax
		mov	dx_save,dx	;save DX we received
                cld
#ifdef DELL_DIRTY_HACK
		mov	ah,#15		; get video mode
		int	0x10
		cbw
		int	0x10		; set video mode
#endif
                call    say
                .ascii	"\n>>>> Disk Detection and Parameter Display <<<<\n"
                .ascii  "Version 1.6, Copyright (C) 1999-2005  John Coffman.\n"
                .ascii  "Re-use and redistribution rights set forth"
                .ascii  " in the file \"COPYING\".\n\n"
		.byte	0

                cmp     magic,#0xAA55
                je      sane            ;check that we got the DS set right
                call    say
                .ascii	"\n\nCS/DS sanity check failed.\n"
		.byte   0
hlti:           hlt
                jmp      hlti
;;;	nop	;spacer

magic:          .word      0xAA55
dx_save:	.word	0

sane:
#if 0
                xor     ax,ax
                mov     dl,al
                int     0x13
                mov     ah,#8
                int     0x13
#endif              
                smsw    ax
                test    al,#1
                jnz     v86mode
                br      realmode
v86mode:
                call    say
                .ascii  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                .ascii  "!!! ***  Warning:  DOS is not running in REAL mode  *** !!!\n"
                .ascii  "!!! ***     Reported results may not be accurate    *** !!!\n"
                .ascii	"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
		.byte	0

		call	pause

realmode:
                call    say
                .ascii	"There "
		.byte	0
                int     0x11            ; get equipment configuration
                test    al,#1
                mov     ah,#-1
                jz      noflop
                shl     ax,1
                shl     ax,1
                and     ah,#3
                jz      flop1
noflop:         call    say
                .ascii  "are "
		.byte	0
                jmp     flop2
flop1:          call    say
                .ascii  "is "
		.byte	0
flop2:          inc     ah
                mov     nflop,ah
                mov     al,ah
                add     al,#0x30
                call    putc
                call    say
                .ascii  " floppy drive"
		.byte	0
                mov     al,#'s
                dec     ah
                jz      flop3
                call    putc
flop3:          inc     ah
                call    say
                .ascii  " with BIOS support.\n"
		.byte	0

; now probe for floppy drives

                mov     dl,#-1

fprobe:         mov     ah,#8
                inc     dl
                push    dx
                xor     cx,cx
                int     0x13
                pop     dx
                jc      fstop
                or      cx,cx
                jnz     fprobe

fstop:
                mov     ah,nflop
                cmp     ah,dl
                je      fdisplay
                call    say
                .ascii  "But probing has found "
		.byte	0
                mov     al,dl
                add     al,#'0
                call    putc
                call    say
                .ascii  "!!!\n"
		.byte	0
                cmp     ah,dl
                jae     fdisplay
                xchg    ah,dl

fdisplay:
                mov     dl,#0            ;start with drive 0x00
                xor     cx,cx
                mov     cl,ah
                jcxz    floppy1

floppy:         call    drive
                inc     dl
                loop    floppy
floppy1:
                mov     al,#10
                call    putc

		call	say
		.ascii	"There is "
		.byte	0
		int	0x12		;get amount of low memory
;;;	  mov ax,#640 ;debug
		xor	dx,dx
		call	print
		call	say
		.ascii	"K of low memory"
		.byte	0
		mov	bx,#640
		sub	bx,ax
		jnz	ebda1
		call	say
		.ascii	" with no EBDA."
		.byte	0
		br	ebda2

ebda1:		push	ax
		mov	ax,bx
		xor	bx,bx
		call	say
		.ascii	".    EBDA size = "
		.byte	0
		call	dec3
		call	say
		.ascii	"K   EBDA starts at 0x"
		.byte	0
		pop	ax
		mov	cl,#6
		shl	ax,cl
		call	wout
		call	say
		.ascii	"0"
		.byte	0
ebda2:
		call	say
		.ascii	"\n"
		.byte	0

; post-floppy pause
		call	pause

                mov     ah,#0
                mov     dl,#0x80
                int     0x13
                mov     ah,#8
                int     0x13
                mov     ah,#0
                jc      nohard
                mov     ah,dl
nohard:         mov     nhard,ah
                call    say
                .ascii  "There "
		.byte	0
                dec     ah
                jz      hard1
                call    say
                .ascii  "are "
		.byte	0
                jmp     hard2
hard1:          call    say
                .ascii  "is "
		.byte	0
hard2:          inc     ah
                mov     al,ah
                add     al,#'0
                call    putc
                call    say
                .ascii  " hard drive"
		.byte	0
                mov     al,#'s
                dec     ah
                jz      hard3
                call    putc
hard3:          inc     ah
                call    say
                .ascii  " with BIOS support.\n"
		.byte	0

; probe for hard drives

                mov     dl,#0x80-1

hprobe:         mov     ah,#8
                inc     dl
                push    dx
                xor     cx,cx
                int     0x13
                pop     dx
                jc      hstop
                or      cx,cx
                jnz     hprobe

hstop:
                and     dl,#0x7f
                mov     ah,nhard
                cmp     ah,dl
                je      hdisplay
                call    say
                .ascii  "But probing has found "
		.byte	0
                mov     al,dl
                add     al,#'0
                call    putc
                call    say
                .ascii  "!!!\n"
		.byte	0
                cmp     ah,dl
                jae     hdisplay
                xchg    ah,dl

hdisplay:




                mov     dl,#0x80         ;start with drive 0x80
                xor     cx,cx
                mov     cl,ah
                jcxz    hdd1
hard:           call    drive
                inc     dl
                loop    hard
hdd1:
                test    byte ptr bigflag,#0xFF
                jz      hdd2
                br      big
hdd2:           test    byte ptr bigcyl,#0xFF
                jz      hdd3
                br      big2
hdd3:                
                call    say
                .ascii  "\nEither your BIOS does not support EDD"
		.ascii	" packet calls, or you have no large\n"
                .ascii  "disks.  You do not need to use LILO with"
		.ascii  " the 'lba32' global option (or '-L'\n"
                .ascii  "switch).\n"
		.byte	0
                br	exit


big:
                call    say
                .ascii  "\nYou have "
		.byte	0
                cmp     byte bigflag,#1
                je      noS
                call    say
                .ascii  "disks"
		.byte	0
                jmp     goOn
noS:            call    say
                .ascii  "a disk"
		.byte	0
goOn:           call    say
                .ascii  " bigger than 8.4Gb"
		.byte	0
big1c:          call    say
                .ascii  " with Enhanced BIOS support.\n"
                .ascii  "Using LILO with the 'lba32' global option"
		.ascii  " (or '-L' switch) is recommended.\n"
		.byte	0
                br	exit

big2:
                call    say
                .ascii  "\nYou have "
		.byte	0
                cmp     byte bigcyl,#1
                je      big2a
                call    say
                .ascii  "disks"
		.byte	0
                jmp     big2b
big2a:          call    say
                .ascii  "a disk"
		.byte	0
big2b:          call    say
                .ascii  " with more than 1023 cylinders"
		.byte	0
                br      big1c



nflop:          .byte      0
nhard:          .byte      0
bigflag:        .byte      0
bigcyl:         db      0
nlimit:         dd	1024*255*63, 0


; inquire whether EDD drive BIOS calls are valid
; Carry clear says NO, Carry set says YES, CX=device bits &
; SI = pointer to dparam table

inqedd:         push    ax
                push    bx
                push    dx
                push    si

                mov     ah,#0x41
                mov     bx,#0x55aa
                int     0x13
                jc      edd7
                cmp     bx,#0xaa55
                jne     edd7
                test    cl,#7
                stc
                jz      edd8
                lea     si,dparam
                mov     word (si),#dlth
;;;	nop	;spacer
;;;	nop	;spacer
                mov     dh,ah           ;save version number
                mov     ah,#0x48         ;get drive parameters
                int     0x13
                jc      edd7
                stc
                pop     ax              ;discard saved SI
                mov     (si+1),dh       ;save version info
                jmp     edd9            ;return SI, too
             

edd7:           xor     cx,cx           ;carry is clear
edd8:           pop     si
edd9:           pop     dx
                pop     bx
                pop     ax
                ret


; pause for the user to look at the screen

pause:		call	say
		.ascii	"Hit any key to continue..."
		.byte	0
		mov	ah,#0
		int	0x16
		call	say
		.ascii	"\r                           \n"
		.byte	0
		ret

; print out the IBM BIOS drive parameters for the drive in DL

drive:          push    bp
                push    ax
                push    bx
                push    cx
                push    es
                push    di
                push    si
                push    dx

                call    say
                .ascii  "Drive 0x"
		.byte	0
                mov     al,dl
                call    bout
                call    say
                .ascii  "   Cyl:Head:Sec = "
		.byte	0

                mov     ah,#8
                int     0x13
#if DEBUG
		mov	cx,#0xFAFF
		mov	dh,#0xFF		; 0xFE is the max.
#endif
                push    cx
                push    dx
                rol     cl,1
                mov     di,#1000
                rol     cl,1
                xor     bh,bh
                and     cl,#3
                xchg    ch,cl
                inc     cx
                mov     ax,cx
                xor     dx,dx
                div     di
                mov     bp,cx
                or      ax,ax
                jz      cyl2
                call    say
                .ascii  "1"
		.byte	0
                mov     bh,#0x80
cyl2:           xchg    ax,dx
                call    dec3
                call    punct
                pop     dx
                xor     ax,ax
                mov     al,dh
                xor     bh,bh
                inc     ax
                call    dec3
                mov     dx,ax
                call    punct
;;;		pop     cx
;;;		and     cl,#0x3F
;;;		mov     al,cl
		pop	ax
#if 0
; sectors = [1..63]
		and	ax,#0x3F
#else
;; version 1.6
;; avoid Davide bug:  Sectors == 0
		dec	ax
		and	ax,#0x3F
		inc	ax	; now sectors = [1..64]
;; version 1.6 end
#endif
                call    dec3
                call    say
                .ascii  " ("
		.byte	0
;;;		mul     dl
		mul	dx
                mul     bp
                push    ds
                pop     es
                lea     di,ac0
                push    di
                stosw
                mov     ax,dx
                stosw
                xor     ax,ax
                stosw
                stosw
                pop     si
                call    dprint
                call    say
                .ascii  " sectors)  -->  "
		.byte	0

                call    sizeit

                call    say
                .byte   10,0

                pop     dx
                push    dx
                call    inqedd
                jc      xdd1
                br      xdd4
xdd1:
                call    say
                .ascii  "   EDD rev "
		.byte	0
                mov     al,(si+1)
                mov     cl,#4
                mov     ah,al
                shr     al,cl
                add     al,#'0
                call    putc
                mov     al,#'.
                call    putc
                mov     al,ah
                and     al,#0x0F
                add     al,#'0
                call    putc

                call    say
                .ascii  " geometry = "
		.byte	0
                test    byte (si+2),#2
                jz      xdd2
                mov     ax,(si+4)
                mov     dx,(si+6)
                or      dx,dx
                jnz     xdd1a
                cmp     ax,#1024
                jb      xdd1b
xdd1a:          inc     byte (bigcyl)
xdd1b:
                call    print
                call    punct
                mov     ax,(si+8)
                mov     dx,(si+10)
                call    print
                call    punct
                mov     ax,(si+12)
                mov     dx,(si+14)
                call    print
                call    say
                .ascii  " "
		.byte	0
xdd2:
                call    say
                .ascii  "("
		.byte	0
                lea     si,(si+16)
                call    dprint
                call    say
                .ascii  " sectors)  -->  "
		.byte	0
                mov     ax,(si+6)
                cmp     ax,nlimit+6
                jb      xdd3
                ja      xdd2a
                mov     ax,(si+4)
                cmp     ax,nlimit+4
                jb      xdd3
                ja      xdd2a
                mov     ax,(si+2)
                cmp     ax,nlimit+2
                jb      xdd3
                ja      xdd2a
                mov     ax,(si)
                cmp     ax,nlimit
                jb      xdd3
xdd2a:          inc     byte bigflag
xdd3:
                mov     dl,#1
                call    sizeit
                call    say
                .byte   10,0

xdd4:

                pop     dx
                pop     si
                pop     di
                pop     es
                pop     cx
                pop     bx
                pop     ax
                pop     bp
                ret

punct:          mov     al,#':
                call    putc
                ret

chars:          .ascii  " KMGTxyz"

sizeit:
                push    ax
                push    bx
                push    cx
                push    dx
                push    si      
                push    es
                push    di
                

                lea     bx,chars-1
                mov     di,si
                push    ds
                pop     es
                mov     ax,#512
                or      dx,dx
                jz      dpr5            ;handle small disks
                call    intmul
                jmp     dpr6
dpr5:           mov     ax,#2
                call    intdiv
                inc     bx

dpr6:           mov     ax,#1000
                lea     di,ac1
dpr7:           lea     bx,(bx+1)
                mov     cx,dx
                call    intdiv
                xchg    si,di
                jnz     dpr7

                mov     si,bx
                mov     ax,dx
                xor     bx,bx
                call    dec3
                cmp     byte ptr (si),#'K
                je      dpr8
                mov     al,#'.
                call    putc
                mov     ax,cx
#if 1
                mov     bx,#0x800a
		cmp	ax,#995
		jae	no_add
                add     ax,#5
no_add:
                div     bl
                xor     ah,ah
                div     bl
                add     al,#'0
                call    putc
                xchg    al,ah
#else
                mov     bx,#0x8000+100
                add     ax,#50
                div     bl
#endif
                add     al,#'0
                call    putc
dpr8:           mov     al,(si)
                call    putc

                pop     di
                pop     es
                pop     si
                pop     dx
                pop     cx
                pop     bx
                pop     ax
                ret
; print the decimal double word number in DX:AX
;
print:          push    ds
                push    si
                xor     si,si
                push    si
                push    si
                push    dx
                push    ax
                push    ss
                pop     ds
                mov     si,sp
                call    dprint
                lea     sp,(si+8)
                pop     si
                pop     ds
                ret


; print the decimal quad-word number in [DS:SI]
;
dprint:         push    ax
                push    bx
                push    dx
                push    es
                push    di
                push    ds
                push    si
                sub     sp,#8
                mov     di,sp
                push    ss
                pop     es
                xor     bx,bx
                mov     ax,#1000

dpr1:           inc     bx
                call    intdiv
                mov     si,di
                push    es
                pop     ds
                push    dx
                jnz     dpr1
                jmp     dpr3

dpr2:           mov     al,#',
                call    putc
dpr3:           pop     ax
                call    dec3
                mov     bh,#0x80
                dec     bl
                jnz     dpr2
                
                lea     sp,(di+8)
                pop     si
                pop     ds
                pop     di
                pop     es
                pop     dx
                pop     bx
                pop     ax
                ret


; multiply the number in the ac pointed at by [DS:SI] by the AX, putting
; the result in the ac pointed to by [ES:SI].  Return overflow in AX.
; SI and DI may be the same

intmul:
                push    bp
                push    si
                push    di
                push    bx
                push    cx
                push    dx

                mov     cx,#4
                mov     bp,ax
                xor     dx,dx
im4:            mov     bx,dx
                lodsw
                mul     bp
                add     ax,bx
                adc     dx,#0
;;;	nop	;spacer
                stosw
                loop    im4

                mov     ax,dx
                pop     dx
                pop     cx
                pop     bx
                pop     di
                pop     si
                pop     bp
                ret
                
; divide the ac pointed at by [DS:SI] by the AX, producing a result
; in [ES:DI], and a remainder in DX; the Z flag reflects the quotient
; DI may equal SI for in-place division

intdiv:         push    bx
                push    cx
                push    bp
                push    di
                push    si
                
                mov     cx,#4
                mov     bx,cx
                dec     bx
                add     bx,bx
                lea     si,(si+bx)
                lea     di,(di+bx)
                xor     dx,dx
                xor     bp,bp
                std
                mov     bx,ax
id2:            lodsw
                div     bx
                or      bp,ax           ;sets the Z flag
                stosw
                loop    id2
                cld
                mov     ax,bx

                pop     si
                pop     di
                pop     bp
                pop     cx
                pop     bx
                ret

; write the number < 1000 in AX as 3 decimal digits
; BH flags whether leading zeroes are printed (0x80=yes, 0=no)

dec3:           push    bx
                push    ax
                push    cx
                mov     cx,#2
                mov     bl,#100
dec32:          div     bl
                xor     al,bh
                jz      dec36
                xor     al,bh
                mov     bh,#0x80
dec34:          add     al,#'0
                call    putc
                mov     bh,#0x80
dec36:          mov     al,ah
                mov     ah,#0
                mov     bl,#10
                dec     cx
                jg      dec32
                jz      dec34
                pop     cx
                pop     ax
                pop     bx          
                ret

; write the <nul> terminated string which follows the call
; no registers altered

say:            push    bp
                mov     bp,sp
                push    ds
                push    si
                push    ax
                mov     si,(bp+2)
                push    cs
                pop     ds
say1:           lodsb
                or      al,al
                jz      say2
                call    putc
                jmp     say1
say2:           mov     (bp+2),si
                pop     ax
                pop     si
                pop     ds
                pop     bp
                ret

; write the word in AX in hex
wout:		xchg	ah,al
		call	bout
		xchg	ah,al
		call	bout
		ret

; write the byte in AL in hex
bout:           push    ax
                push    cx
                push    ax
                mov     cx,#0x204
                shr     al,cl
bout1:          add     al,#'0
                cmp     al,#'9
                jbe     bout2
                add     al,#'A-'0-10
bout2:          call    putc
                dec     ch
                jz      bout4
                pop     ax
                and     al,#0xF
                jmp     bout1
bout4:          pop     cx
                pop     ax
                ret


; write the character in AL in teletype mode
; all registers are preserved

putc:           push    bx
                push    ax
                mov     ah,#14
                xor     bh,bh
                cmp     al,#10           ;test for new-line
                jne     putc2
                mov     al,#13           ;get <cr>
                int     0x10
                mov     al,#10
putc2:          int     0x10
                pop     ax
                pop     bx
                ret

#define LILO_ASM
#include "lilo.h"
#include "read.S"
#include "bdata.h"
#define BD_VERBOSE
#include "biosdata.S"

exit:           mov     ax,cs
                mov     dx,ds
                cmp     ax,dx
		jae	bd_test
exit_dos:       mov     ax,#0x4c00
                int     0x21

bd_test:
		call	pause
                call    say
                .ascii  "BIOS data collection test.\n"
		.ascii	"Failure of this test will require booting all Linux\n"
		.ascii	"kernels with the 'nobd' command-line option.\n"
                .ascii  "Hit <ESC> to bypass, any other key to continue..."
		.byte	0
                mov     ah,#0
                int     0x16
		call	say
		.byte	10,10,0
		cmp	al,#0x1b	; <ESC>
		je	bd_test_skip

#if 1
		mov	ax,cs
		mov	bx,#SYSSEG
		cmp	ax,bx
		jae	collect
		mov	es,bx
		mov	di,#theend-1
		std
		lea	cx,(di+1)
		mov	si,di
		rep
		  movsb
		mov	ss,bx
		mov	ds,bx
		cld
		push	es
		push	#collect
		retf
collect:
#endif

		mov	dx,dx_save		; DX passed in on boot
		call	io_biosdata

		call	say
		.ascii	"\nALL OKAY\n\n"
		.byte	0

bd_test_skip:
                call    say
                .ascii  "Remove the floppy disk from the drive.\n"
                .ascii  "Hit any key to reboot..."
		.byte	0
                mov     ah,#0
                int     0x16
                call    say
                .byte      10,10,10,0
bs_helper:      int     0x19			;label here for kludge


id_string:	.ascii	"Disk.Com"
		.byte	0


ac0:            .word      0,0,0,0
ac1:            .word      0,0,0,0

dparam:         .word      dlth
dflags:         .word      0
dcyl:           dd      0
dhead:          dd      0
dsec:           dd      0
dsecs:          dd      0,0
ssize:          .word   0
dptp:           dd      0
dlthe:
dlth            =     dlthe-dparam
modelist:

theend:
