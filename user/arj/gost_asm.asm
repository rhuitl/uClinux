;*
;* $Id: gost_asm.asm,v 1.1.1.1 2002/03/28 00:03:01 andrew_belov Exp $
;* ---------------------------------------------------------------------------
;* Optimized assembly language routines for 386+ are located in this module.
;*

INCLUDE         ASM_INCL.INC

public          gost_loop_32

.386C
.CODE

;*
;* Imported variables
;*

extern          pattern:byte

;*
;* General GOST procedure
;*

gost_term_32    proc

data_acc	= dword	ptr -4
g_data		= dword	ptr  4

		push	bp
		mov	bp, sp
		sub	sp, 4
		push	si
		lea	si, [bp+g_data]
		mov	al, [si]
		mov	ah, 0
		mov	bx, ax
                mov     al, pattern[bx+300h]
		mov	byte ptr [bp+data_acc],	al
		mov	al, byte ptr [bp+g_data+1]
		mov	ah, 0
		mov	bx, ax
                mov     al, pattern[bx+200h]
		mov	byte ptr [bp+data_acc+1], al
		mov	al, byte ptr [bp+g_data+2]
		mov	ah, 0
		mov	bx, ax
                mov     al, pattern[bx+100h]
		mov	byte ptr [bp+data_acc+2], al
		mov	al, byte ptr [bp+g_data+3]
		mov	ah, 0
		mov	bx, ax
                mov     al, pattern[bx]
		mov	byte ptr [bp+data_acc+3], al
		mov	eax, [bp+data_acc]
		shl	eax, 11
		mov	edx, [bp+data_acc]
		shr	edx, 21
		or	eax, edx
		shld	edx, eax, 16
		pop	si
		leave
                ret
gost_term_32    endp

;*
;* Encoding/decoding loop
;*

gost_loop_32    proc

mod1		= dword	ptr -8
mod2		= dword	ptr -4
src		= word ptr  4
dest		= word ptr  6
key		= word ptr  8

		push	bp
		mov	bp, sp
		sub	sp, 8
		push	si
		push	di
		mov	di, [bp+src]
		mov	si, [bp+key]
		mov	eax, [di]
		mov	[bp+mod2], eax
		mov	eax, [di+4]
		mov	[bp+mod1], eax
		xor	di, di
loop_start:
		mov	eax, [bp+mod2]
		add	eax, [si]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+4]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	eax, [bp+mod2]
		add	eax, [si+8]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+12]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	eax, [bp+mod2]
		add	eax, [si+16]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+20]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	eax, [bp+mod2]
		add	eax, [si+24]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+28]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		inc	di
		cmp	di, 3
                jge     loop_end
                jmp     loop_start
loop_end:
		mov	eax, [bp+mod2]
		add	eax, [si+28]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+24]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	eax, [bp+mod2]
		add	eax, [si+20]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+16]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	eax, [bp+mod2]
		add	eax, [si+12]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si+8]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	eax, [bp+mod2]
		add	eax, [si+4]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod1], eax
		mov	eax, [bp+mod1]
		add	eax, [si]
		push	eax
                call    gost_term_32
		shl	eax, 16
		shrd	eax, edx, 16
		add	sp, 4
		xor	[bp+mod2], eax
		mov	bx, [bp+dest]
		mov	eax, [bp+mod1]
		mov	[bx], eax
		mov	eax, [bp+mod2]
		mov	[bx+4],	eax
		pop	di
		pop	si
		leave
                ret
gost_loop_32    endp

                end
