/* memset.S
 * Copyright (C) 2003, 2005, 2006 Analog Devices Inc., All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 */

/* void *memset(void *s, int c, size_t n);
 * R0 = address (s) (leave unchanged to form result)
 * R1 = filler byte (c)
 * R2 = count (n)
 *
 * Note: Favours word aligned data.
 */

.text

.align 2

.global _memset
.type _memset, STT_FUNC
_memset:
	P0 = R0 ;             // P0 = address
	P2 = R2 ;             // P2 = count
	R3 = R0 + R2;         // end
	CC = R2 <= 7(IU);
	IF CC JUMP  too_small;
	R1 = R1.B (Z);        // R1 = fill char
	R2 =  3;
	R2 = R0 & R2;         // addr bottom two bits
	CC =  R2 == 0;             // AZ set if zero.
	IF !CC JUMP  force_align ;  // Jump if addr not aligned.

aligned:
	P1 = P2 >> 2;          // count = n/4
	R2 = R1 <<  8;         // create quad filler
	R2.L = R2.L + R1.L(NS);
	R2.H = R2.L + R1.H(NS);
	P2 = R3;

	LSETUP (quad_loop , quad_loop) LC0=P1;
quad_loop:
	[P0++] = R2;

	CC = P0 == P2;
	IF !CC JUMP bytes_left;
	RTS;

bytes_left:
	R2 = R3;         // end point
	R3 = P0;         // current position
	R2 = R2 - R3;    // bytes left
	P2 = R2;

too_small:
	CC = P2 == 0;           //Check zero count
	IF CC JUMP finished;    // Unusual

bytes:       LSETUP (byte_loop , byte_loop) LC0=P2;
byte_loop:   B[P0++] = R1;

finished:
	RTS;

force_align:
	CC = BITTST (R0, 0 );  // odd byte
	R0 = 4;
	R0 = R0 - R2;
	P1 = R0;
	R0 = P0;			// Recover return address
	IF !CC JUMP skip1;
	B[P0++] = R1;
skip1:
	CC = R2 <= 2;          // 2 bytes
	P2 -= P1;              // reduce count
	IF !CC JUMP aligned;
	B[P0++] = R1;
	B[P0++] = R1;
	JUMP aligned;
.size _memset,.-_memset

libc_hidden_def (memset)
