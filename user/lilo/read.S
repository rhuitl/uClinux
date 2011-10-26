/*
;  read.S  is
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/
#define NEW_WRITE 1
;
; lba_read:      read using LBA
;
;  Enter with:
;       AL      actual count of blocks to transfer
;       DL      device (0x00=A:, 0x80=C:, 0x81=D:) and LINEAR/LBA32 flags
;       ES:BX   buffer pointer
;       DI:CX   LBA to read
;
;  Exit with:
;       No Error:  carry clear
;       CX      count of blocks read
;       ES:BX   unchanged
;       DX      unchanged
;       AH      error status if CF=1
;       DI      trashed
;

lba_read:       push    si              ;save some registers
#ifndef JRC_NOCOMPACT
                push    bx
                push    dx
                xor     ah,ah           ;convert count to word
                push    ax
#endif
                push    cx              ;gotta ask about 32-bit addressing 
                push    bx
#ifndef JRC_FLAGS_IN_DH
		mov     dh,dl           ;use BL for flag test
#endif
		and     dl,#DEV_MASK_asm    ;remove spurious flags (0x8F)
#ifndef JRC_MBR
		test    dh,#LBA32_FLAG
		jz	no_lba          ;linear will never use EDD calls
#endif
#ifndef JRC_NOCOMPACT
	        cmp     al,#127		;test for LINEAR transfer too big
		ja      no_lba          ; for LBA mode (127 is max)
                push    ax
#endif
                mov     bx,#0x55AA      ;magic number
                mov     ah,#0x41        ;function call
                int     0x13
#ifndef JRC_NOCOMPACT
                pop     ax
#endif
                jc      no_lba
                cmp     bx,#0xAA55      ;magic return
                jne     no_lba
                test    cl,#EDD_PACKET  ;packet calls supported?
                jz      no_lba


; LBA mode is to be used

lba_avail:
                pop     bx
                pop     cx

#ifndef JRC_NOCOMPACT
                pop     ax
                push    ax
#endif
#ifndef JRC_DS_EQ_SS
                push    ds              ;save DS
#endif
		push	dword #0		;  0L is pushed
                push    di              ;LBA hi word
                push    cx              ;    lo word
                push    es              ;ES:BX
                push    bx
#ifndef JRC_NOCOMPACT
                push    ax
#else
                push    #1		;count always 1
#endif
                push    #16		;size of parameter area  ;#
                         		;actually pushes a word
                mov     si,sp		;DS:SI is param block pointer
#ifndef JRC_DS_EQ_SS
                push    ss
                pop     ds              ;DS:SI points at param block
#endif
#ifndef JRC_NOCOMPACT
                mov     ax,#0x4200      ;read function -- must be AX
					; as AL has meaning on WRITE
                call    dsk_do_rw
#else
;;;		mov     ax,#0x4200      ;read function
		mov	ah,#0x42	;read only -- AL matters not
                int     0x13
#endif
                lea     sp,word ptr (si+16)      ;use lea so flags are not changed
#ifndef JRC_DS_EQ_SS
                pop     ds              ;restore DS
#endif
                jmp     lba_read_exit1



no_lba:
                pop     bx
                pop     cx


lba_small:                      ;must get the disk geometry
#ifndef JRC_NOCOMPACT
lba_more_small:
                push    bx
                push    di
                push    cx
                push    ax
#endif
                push    bx
                push    dx
                push    di
                push    cx

                push    es
                mov     ah,#8          ; DL is set to device
#ifndef JRC_NOCOMPACT
                call    dsk_do_int13
#else
                int     0x13
#endif
                pop     es
                jc      lba_geom_error

                push    cx
                shr     cl,#6		;;;;
                xchg    cl,ch           ;CX is max cylinder number
                mov     di,cx           ;DI saves it
                pop     cx

		shr	dx,#8
		xchg	ax,dx		;AX <- DX
		inc	ax		;AX is number of heads (256 allowed)

; compensate for Davide BIOS bug
		dec	cx		; 1..63 -> 0..62;  0->63
		and	cx,#0x003f	;CX is number of sectors
		inc	cx		; allow Sectors==0 to mean 64

                mul     cx		; kills DX
                xchg    ax,si           ;save in SI

                pop     ax              ;was CX
                pop     dx              ;was DI
                cmp     dx,si
                jae     lba_geom_error2  ;prevent division error
                div     si              ;AX is cyl, DX is head/sect
                cmp     ax,di
                ja      lba_geom_error2  ;cyl is too big

                shl     ah,#6		;;;;
                xchg    al,ah
                xchg    ax,dx
                div     cl              ;AH = sec-1, AL = head
#ifndef JRC_NOCOMPACT
                sub     cl,ah           ;CX = max count possible
                mov     si,cx           ;save in SI
#endif
                inc     ah
                add     dl,ah           ;form Cyl/Sec
                mov     cx,dx
                pop     dx              ;get device
                pop     bx
                xchg    al,dh           ;

#ifndef JRC_NOCOMPACT
                pop     ax              ;restore the count
                push    ax              ;keep in the stack
                cmp     ax,si           ;
                jb      lba_cntltmax
                mov     ax,si           ;smaller is in AX
lba_cntltmax:   push    ax
                mov     ah,#2           ;READ
                call    dsk_do_rw
#else
                mov     ax,#0x201       ;read, count of 1
                int     0x13
#endif
        ; carry is set or clear
#ifndef JRC_NOCOMPACT
                pop     bx              ;actual count read (was AX)
                pop     si              ;count remaining
                pop     cx
                pop     di
                jc      lba_read_exit_e
                add     cx,bx           ;update lba address
                adc     di,#0           ;the # was omitted in rev 3
                xchg    ax,bx
                pop     bx              ;buffer address
                add     bh,al           ;update ES:BX
                add     bh,al           ;LILO has already checked for seg update
                xchg    si,ax
                sub     ax,si           ;AX is remaining count after transfer
                jnz     lba_more_small
                         ; after the sub yields 0, the carry is clear
#endif
lba_read_exit1:	jmp	lba_read_exit

#ifndef JRC_NOCOMPACT

#ifndef LCF_READONLY

#if NEW_WRITE

dsk_do_rw:	or	ah,#0		; 0=read, 1=write, 2=read-only test
dsk_wrflag	equ	*-1		; byte data area is the immediate

#else
dsk_wrflag:     .byte   0               ; 0=read, 1=write, 2=read-only test

dsk_do_rw:
                seg     cs
                or	ah,dsk_wrflag
#endif

#else
#if DEBUG_NEW
dsk_wrflag:     .byte   0               ; 0=read, 1=write, 2=read-only test
#endif
dsk_do_rw:
#endif

dsk_do_int13:
                push    bp
                mov     bp,#5           ;number of tries
dsk_do_int13a:  pusha
                int     0x13
                jnc     dsk_io_exit
                dec     bp              ;does not affect the carry
                jz      dsk_io_exit
                xor     ax,ax           ;reset disk controllers
                int     0x13
                popa
                dec     bp
                jmp     dsk_do_int13a

dsk_io_exit:    mov     bp,sp           ;do not touch any flags
                lea     sp,(bp+16)      ;an ADD would touch flags
                pop     bp              ;do not touch any flags
                ret
#endif
lba_geom_error:
                pop     cx
                pop     di
                jmp     lba_g3
lba_geom_error2:
                mov     ah,#0x40         ;seek failure error code
lba_g3:         pop     dx
                pop     bx
#ifndef JRC_NOCOMPACT
                pop     cx              ;was AX
                pop     cx
                pop     di
lba_read_exit_e:
                pop     bx
#endif
                stc
lba_read_exit:
#ifndef JRC_NOCOMPACT
                pop     cx              ;return count in CX
                pop     dx
                pop     bx
#endif
                pop     si
#ifndef JRC_NORETURN
                ret
#endif
