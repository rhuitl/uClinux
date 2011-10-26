;*
;* $Id: asm_incl.inc,v 1.1.1.1 2002/03/28 00:02:01 andrew_belov Exp $
;* ---------------------------------------------------------------------------
;* Common setup for assembly-language modules of ARJ.
;*

INCLUDE ASM_DEFS.INC

IFDEF FLATMODE
 .386p
ELSE
 IFDEF _OS2
  .286
 ENDIF
ENDIF

IFDEF FLATMODE
 .MODEL FLAT, PASCAL
ELSE
 IFNDEF SFXSTUB
  IFDEF MODL
   IFDEF _OS2
    .MODEL MODL, C, OS_OS2
   ELSE
    .MODEL MODL, C
   ENDIF
  ELSE
   .ERR <ERROR: Use /DMODL=... to select model before processing>
  ENDIF
 ENDIF
ENDIF

; Mode-specific addressing

IFDEF FLATMODE
        OPTION SEGMENT:USE16
        V_DW   EQU     <dd>
        V_WORD EQU     <dword>
ELSE
        V_DW   EQU     <dw>
        V_WORD EQU     <word>
ENDIF

IFNDEF          FLATMODE
 AL_PARA        EQU     <PARA>
 AL_WORD        EQU     <WORD>
ELSE
 AL_PARA        EQU
 AL_WORD        EQU
ENDIF

OPTION SCOPED
