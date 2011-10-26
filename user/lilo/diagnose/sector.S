; sector.S -- boot program named:  HIPBOOT.SYS
;             from any MSDOS floppy diskette
;
; Copyright 2001-2005 John Coffman.
; All rights reserved.
;
; Licensed under the terms contained in the file 'COPYING' in the LILO
; source directory.
;
#define DEBUG 0		/* enables loading .EXE for codeview debugging */
#define OPTION 1	/* enables fast directory search exit */
#define LARGE 0		/* enables loading code >32K */
#define TESTFAT 0	/* enables testing for FAT12/FAT16 */
#define SYSSEG 0x1000  	/* load at a fixed address SYSSEG:0000 */

;;directory_entry         
			block	0

dir_filename:		.blkb	8
dir_filename_ext:	.blkb	3
dir_attribute:		.blkb	1
dir_Reserved:		.blkb	10
dir_time_updated:	.blkw	1
dir_date_updated:	.blkw	1
dir_cluster:		.blkw	1
dir_file_size:		.blkw	2

dir_entry_size:
			endb

base    equ     0x7C00
buffer  equ     0x0500          ;scratch disk buffer





;contAddr  equ   SS:[bp-4]      ;dword     DO NOT MOVE
;dataBase  equ   SS:[bp-8]       ;dword    DO NOT MOVE
;FATshift  equ   SS:[bp-9]      ; byte 
;diskNumber  equ SS:[bp-10]      ; byte    DO NOT MOVE
;dirBase equ     SS:[bp-14]       ;dword
;nDirSec equ     SS:[bp-16]      ;word
;FATsector equ   SS:[bp-18]      ;word
;FATnibbles  equ SS:[bp-20]      ;word


stacksize	equ	20


			block	-stacksize

FATnibbles:	.blkw	1
FATsector:	.blkw	1
nDirSec:	.blkw	1
dirBase:	.blkw	2
diskNumber:	.blkb	1	; DO NOT MOVE
FATshift:	.blkb	1
dataBase:	.blkw	2	; DO NOT MOVE
contAddr:	.blkw	2	; DO NOT MOVE

stack:	/* this had better be zero */

		.blkb	3	; jump instruction
		.blkb	8	; system ID string
secSiz:		.blkw	1	; bytes_per_sector
secPerCl:	.blkb	1	; sectors_per_cluster
FATbase:	.blkw	1	; reserved_sectors
nFATs:		.blkb	1	; FAT_copies
nDirEnt:	.blkw	1	; directory_entries
totSec:		.blkw	1	; total_sectors
media:		.blkb	1	; media_descriptor
secPerFAT:	.blkw	1	; sectors_per_FAT
nSEC:		.blkw	1	; sectors_per_track
nSides:		.blkw	1	; heads_per_cylinder
hidSec:		.blkw	2	; hidden_sectors
		.blkb	22
fs_id:		.blkb	8	; filesystem_id

			endb

.globl _main
			org	0
; jump instruction
_main:			jmp	beginning
			nop

system_id_string:	.ascii	"DISKBOOT"	; 8 chars

msdos_boot_data:

bytes_per_sector:	dw	512
sectors_per_cluster:	db	1
reserved_sectors:	dw	1
FAT_copies:		db	2
directory_entries:	dw	224       ; 112 & 224 are typical
total_sectors:		dw	2880
media_descriptor:	db	0xf0      ; 0f9H, 0f0h, 0fAh, etc.
sectors_per_FAT:	dw	9
sectors_per_track:	dw	18
heads_per_cylinder:	dw	2
hidden_sectors:		dd	0       ; always zero for floppies
total_sectors_2:	dd      0       ; actual value if 'total_sectors' is zero
BPB_rsvd:		dw      0       ; reserved
vol_id_marker:		db      0x29    ; marker? for volume ID
serial_number:		dd      0       ; volume unique ID number

volume_label:		.ascii	"NO NAME    "	; 11 chars
filesystem_id:		.ascii	"FAT12   "	;  8 chars



beginning:
        xor     ax,ax
        mov     bp,#base         ;origin at 7C00
#if DEBUG
        xor     dl,dl
        mov     ax,ss
#endif
        cli
        mov     ss,ax
        lea     sp,(bp-stacksize)
        sti

        cld
        mov     es,ax           ;both at zero
        mov     ds,ax
#if DEBUG
        xor     ax,ax
#endif
        mov     diskNumber(bp),dl   ;save disk number
        int     0x13             ;reset the disk system
        jc      error
noError:
        mov     ax,#0x0403        ;shift=4, nibbles=3 -- FAT12
fat12   equ     *-2
#if TESTFAT
        cmp     byte ptr fs_id+4(bp),#$36	; '6'
        jne     isFAT12
        mov     ax,#0004        ;shift=0, nibbles=4 -- FAT16
isFAT12:
#endif
        mov     FATshift(bp),ah     ;set shift count
        cbw
        mov     FATnibbles(bp),ax   ;set number of nibbles per FAT index entry

        mov     al,nFATs(bp)        ;number of FATs
;       cbw
        mul     word ptr secPerFAT(bp)       ;* sectors per FAT
        add     ax,FATbase(bp)      ;+ FAT base
        adc     dx,#0            ; SI = 0
        mov     dirBase(bp),ax
        mov     dirBase+2(bp),dx    ;save directory base

        mov     dataBase(bp),ax
        mov     dataBase+2(bp),dx   ;still forming Data base 

        mov     ax,#dir_entry_size
        mul     word ptr nDirEnt(bp)
        mov     bx,secSiz(bp)
        add     ax,bx           
        dec     ax
        div     bx              ;get base of data
#if DEBUG
        add     bx,bx
#endif
#if SYSSEG
        mov     contAddr(bp),ss            ; SS = 0
        mov     word ptr contAddr+2(bp),#SYSSEG      ; begin at SYSSEG:0000
#else
        add     bx,#base
        mov     contAddr(bp),bx     ;save continuation address
        mov     contAddr+2(bp),es
#endif
        mov     nDirSec(bp),ax      ;save no. of Directory sectors
        add     dataBase(bp),ax
        adc     word ptr dataBase+2(bp),#0           ; SI = 0

; scan the directory for the required bootstrap file

        mov     ax,dirBase(bp)      ; starting disk block in DX:AX
        mov     dx,dirBase+2(bp)
dirscan:
        mov     bx,#buffer        ; ES:BX points to buffer
        call    ReadSector
        mov     di,bx
        mov     bx,secSiz(bp)
dirscan1:
        
        call    S21
tofind: .ascii	"HIPBOOT SYS"

error:
        call    write
        db      13,10,10
	.ascii	'Non-SYSTEM disk or disk error'
        db      13,10
	.ascii	'Press any key to re-boot ...'
	db	0
done:
        xor     ax,ax
        int     0x16             ;wait for keypress
        int     0x19             ;re-boot


S21:    pop     si
        push    di
        mov     cx,#11           ;name length
        rep     
	 seg cs
	  cmpsb    ;byte ptr CS:[si],ES:[di]
        pop     di
        je      hipboot
#if OPTION
        cmp     byte ptr (di),#0
        je      endOfDirectory
#endif
        lea     di,dir_entry_size(di)
        sub     bx,#dir_entry_size
        jg      dirscan1

        inc     ax
        dec     word ptr nDirSec(bp)
        jnz     dirscan
endOfDirectory:
error2:
        jmp     error

ReadSector:
        push    dx              ;save registers
        push    cx
        push    ax
        
        add     ax,hidSec(bp)       ;+ Hidden Sectors
        adc     dx,hidSec+2(bp)     ;
        xchg    ax,dx
        push    dx              ;AX=dividend-hi, DX=dividend-low
        cwd
        div     word ptr nSEC(bp)            ;DX=remainder, AX=quo-hi
        
        pop     cx
        xchg    ax,cx           ;CX=quo-hi, DX:AX=dividend-low
        div     word ptr nSEC(bp)            ;remainder is sector number, zero based
        inc     dx              ;DX=sector#, CX:AX=quotient
        push    dx              ;save sector number

        mov     dx,cx           ;DX:AX=quotient
        div     word ptr nSides(bp)          ;DX = side, AX = Cyl No.
        mov     cl,#6
        shl     ah,cl           ;AH is hi-bits of cyl no.
        pop     cx              ;restore sector number
        or      cl,ah
        mov     ch,al
        mov     dh,dl
        mov     dl,diskNumber(bp)
retry:
        mov     ax,#0x0201        ;BIOS read 1 sector
        int     0x13
#if DEBUG
        jnc     readcont
        xor     ax,ax
        int     0x13
        jmp     retry
readcont:
#endif
error3:
        jc      error2
        pop     ax
        pop     cx
        pop     dx
        ret

hipboot:
        mov     cx,dir_cluster(di)
        mov     word ptr FATsector(bp),#-1    ;no FAT sector present
        les     bx,contAddr(bp)     ;get continue address
nextCluster:
        call    readCluster
        push    es
        push    bx
        mov     ax,FATnibbles(bp)   ;get number of nibbles in a FAT entry
        mul     cx              ;DX:AX is nibble index
        shr     dx,1
        rcr     ax,1            ;DX:AX is byte index, CF=odd/even
        pushf                   ;save CF
        mov     si,secSiz(bp)       ;sector size to SI
        div     si              ;AX is rel. sector, DX is byte offset
        mov     di,dx           ;DI is byte offset
        push    ds
        pop     es
        mov     bx,#buffer
        call    ForceFatSector  ;AX is rel. FATsector to force
        mov     dl,(bx+di)   ;get low byte
        dec     si
        inc     di
        and     di,si           ;mask DI byte offset
        jnz     sameFATsec
        inc     ax
        call    ForceFatSector
sameFATsec:
        mov     dh,(bx+di)
        popf                    ;restore shift flag
        mov     cl,FATshift(bp)
        jc      shiftIt
        shl     dx,cl
shiftIt:
        shr     dx,cl
        mov     si,#-1
        shr     si,cl           ;si is EOF
        and     si,#-8		;0xFFF8
        mov     cx,dx           ;CX is next cluster
        pop     bx
        pop     es

        cmp     cx,si
        jb      nextCluster

        mov     ch,media(bp)        ;pass on media descriptor
        lea     sp,diskNumber(bp)
        pop     dx
        pop     bx              ;low order start of data
        pop     ax              ;high order start of data
#if DEBUG
        jmp     done
#endif
        retf


readCluster:
        push    cx
        mov     al,secPerCl(bp)     ;sectors per cluster
        cbw
        xchg    ax,cx           ;AX=cluster #,  CX=# sectors per cluster
        dec     ax
        dec     ax              ;base it at 0, instead of 2
        mul     cx
        add     ax,dataBase(bp)     ;offset onto disk
        adc     dx,dataBase+2(bp)
readClus1:
        call    ReadSector      ;read a sector
        add     bx,secSiz(bp)       ;update address
#if LARGE
        jnc     readClus2
        mov     si,es           ;get segment register
        add     si,#0x1000        ;REAL mode increment
        mov     es,si           ;update segment register
#else
        jc      error3          ;segment overflow
#endif
readClus2:
        inc     ax              ;update sector number
        jnz     readClus3
        inc     dx
readClus3:
        loop    readClus1

        pop     cx
        ret


ForceFatSector:
        push    dx
        cmp     ax,FATsector(bp)
        je      gotFATsector
        mov     FATsector(bp),ax
        add     ax,FATbase(bp)
        xor     dx,dx
        call    ReadSector
gotFATsector:
        pop     dx
        ret



write:
        pop     si              ;get character string pointer
write1:
	seg cs
        lodsb   ;byte ptr CS:[si]
        test    al,al
        jz      return
        mov     ah,#0x0e
        mov     bx,#7
        int     0x10
        jmp     write1
return:
        jmp     si

	org	510
	dw	0xAA55		; BOOT_SIGNATURE

endup:
theend:


