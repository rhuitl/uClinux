;*
;* $Id: fmemcmp.asm,v 1.2 2004/05/31 16:08:41 andrew_belov Exp $
;* ---------------------------------------------------------------------------
;* This file provides a far memory comparison routine.
;*

INCLUDE         ASM_INCL.INC

;*
;* Exported stubs
;*

public          far_memcmp

.CODE _TEXT

;*
;* Comprares two FAR memory blocks
;*

far_memcmp      proc, str1:dword, str2:dword, len:word
                push    ds
                push    es
                push    si
                push    di
                push    cx
                mov     cx, len
                jcxz    @matched
                cld
                lds     si, str1
                les     di, str2
                repe    cmpsb
                jcxz    @matched
                mov     ax, 1
                jmp     short @ret
@matched:
                sub     ax, ax
@ret:
                pop     cx
                pop     di
                pop     si
                pop     es
                pop     ds
                ret
far_memcmp      endp

        	end
