;*
;* $Id: arj_xms.asm,v 1.1.1.1 2002/03/28 00:02:01 andrew_belov Exp $
;* ---------------------------------------------------------------------------
;* To make FILELIST.C less platform-dependent, its XMS routies are placed into
;* this file.
;*

INCLUDE         ASM_INCL.INC

;*
;* XMS move structure as proposed by XMS v 2.0
;*

xms_move        struc
  blk_length    dd      ?
  src_handle    dw      ?
  src_offset    dd      ?
  dest_handle   dw      ?
  dest_offset   dd      ?
xms_move        ends

;*
;* Exported stubs
;*

public          detect_xms, get_xms_entry, allocate_xms, free_xms, move_xms

.CODE

;*
;* Detects XMS presence. Returns 1 if it's present
;*

detect_xms      proc
                mov     ah, 30h
                int     21h
                cmp     al, 3
                jb      dx_none
                mov     ax, 4300h
                int     2Fh
                cmp     al, 80h
                jne     dx_none
                mov     ax, 1
                jmp     short dx_return
dx_none:
                sub     ax, ax
dx_return:
                ret
detect_xms      endp

;*
;* Stores XMS entry point in an internal area
;*

get_xms_entry   proc    uses es bx
                mov     ax, 4310h
                int     2Fh
                mov     word ptr xms_entry, bx
                mov     word ptr xms_entry+2, es
                ret
get_xms_entry   endp

;*
;* Allocates N kilobytes of XMS memory
;*

allocate_xms    proc    uses bx, kbs:word, hptr:ptr word
                mov     ah, 9
                mov     dx, kbs
                call    dword ptr xms_entry
IF @DataSize
                push    es
                les     bx, hptr
                mov     word ptr es:[bx], dx
                pop     es
ELSE
                mov     bx, hptr
                mov     word ptr ss:[bx], dx
ENDIF
                ret
allocate_xms    endp

;*
;* Frees a block of XMS memory
;*

free_xms        proc    uses bx, handle:word
                mov     ah, 0Ah
                mov     dx, handle
                call    dword ptr xms_entry
                ret
free_xms        endp

;*
;* Moves a block
;*

move_xms        proc    uses bx si ds, xms_mm:ptr xms_move
                mov     ah, 0Bh
IF @DataSize
                lds     si, xms_mm
ELSE
                mov     si, xms_mm
                push    ss
                pop     ds
ENDIF
                call    dword ptr xms_entry
                ret
move_xms        endp

.DATA?

xms_entry       dd      ?

        	end
