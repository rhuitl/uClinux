;*
;* $Id: sfxstub.asm,v 1.1.1.2 2002/03/28 00:03:24 andrew_belov Exp $
;* ---------------------------------------------------------------------------
;* This is a compact SFX startup stub file.
;*

INCLUDE         ASM_INCL.INC

; OS/2 definitions

IFDEF _OS2

 IFDEF FLATMODE
  EXTERN        DOSWRITE:proc
  EXTERN        DOSEXIT:proc
  INCLUDELIB OS2386.LIB
 ELSE
  extrn         DOSWRITE:far
  extrn         DOSEXIT:far
 ENDIF

WRITE_STR MACRO LENPARM, STRPARM
 IFDEF          FLATMODE
                push    offset junk
                push    LENPARM
                push    offset STRPARM
                push    1
                call    DosWrite
                add     esp, 16
 ELSE
                push    1
                push    ds
                push    offset STRPARM
                push    LENPARM
                push    ds
                push    offset junk
                call    DosWrite
 ENDIF
ENDM

ENDIF

; DGROUP

                DOSSEG
DGROUP          GROUP _DATA, STACK

; Stack segment

STACK           SEGMENT AL_PARA STACK 'STACK'
 IFDEF          FLATMODE
                DB 16384 DUP (?)
 ELSE
                DB 2560 DUP (?)
 ENDIF
STACK           ENDS

; Data segment

_DATA           SEGMENT AL_WORD PUBLIC 'DATA'

INCLUDE         STUBINCL.INC

IFDEF           _OS2
                junk    V_DW 0
ENDIF

_DATA           ENDS

; Code segment

_TEXT           SEGMENT AL_WORD PUBLIC 'CODE'
                ASSUME cs:_TEXT, ds:DGROUP, ss:DGROUP

start:
IFDEF           _OS2
                WRITE_STR L_M_SFXSTUB_BANNER, M_SFXSTUB_BANNER
                WRITE_STR L_M_SFXSTUB_BLURB_1, M_SFXSTUB_BLURB_1
                WRITE_STR L_M_SFXSTUB_BLURB_2, M_SFXSTUB_BLURB_2
                push    1
                push    1
                call    DosExit
ELSE
                mov     ax, seg M_SFXSTUB_BANNER
                mov     ds, ax
                mov     ah, 9
                mov     dx, offset M_SFXSTUB_BANNER
                int     21h
                mov     ax, seg M_SFXSTUB_BLURB_1
                mov     ds, ax
                mov     ah, 9
                mov     dx, offset M_SFXSTUB_BLURB_1
                int     21h
                mov     ax, seg M_SFXSTUB_BLURB_2
                mov     ds, ax
                mov     ah, 9
                mov     dx, offset M_SFXSTUB_BLURB_2
                int     21h
                mov     ah, 4Ch
                int     21h
ENDIF
db              "zyxwbaaRJsfX"

_TEXT           ENDS

                end start
