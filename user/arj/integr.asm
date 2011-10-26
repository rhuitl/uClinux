;*
;* $Id: integr.asm,v 1.1.1.1 2002/03/28 00:03:01 andrew_belov Exp $
;* ---------------------------------------------------------------------------
;* Data template for integrity check is stored in this  file. It must be first
;* in the linking chain in order to be accessible for the  check routine. This
;* module is to be compiled with Microsoft MASM v 6.0 or later.
;*

INCLUDE         ASM_INCL.INC

.CODE _TEXT

;*
;* A unique pattern for locating the data area
;*

                dw	3B0h, 2B0h, 3B0h, 4B0h, 5B0h

;*
;* Data storage
;*

crc             dd      90909090h       ; CRC32 of the remainder
len             dd      90909090h       ; (file length)+2

;*
;* Ending sequence
;*

                dw      1B0h, 1B0h, 0C3h

        	end
