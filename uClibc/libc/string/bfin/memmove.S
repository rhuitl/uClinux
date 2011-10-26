/* memmove.S
 * Copyright (C) 2003, 2005, 2006 Analog Devices Inc., All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 */

/* void *memmove(void *dest, const void *src, size_t n);
 * R0 = To Address (dest) (leave unchanged to form result)
 * R1 = From Address (src)
 * R2 = count (n)
 *
 * Note: Data may overlap
 */

.text

.align 2

.global _memmove
.type _memmove, STT_FUNC
_memmove:
	I1 = P3;
	P0 = R0;              // P0 = To address
	P3 = R1;              // P3 = From Address
	P2 = R2 ;             // P2 = count
	CC = P2 == 0;           //Check zero count
	IF CC JUMP finished;    // very unlikely

	CC = R1 < R0 (IU);	// From < To
	IF !CC JUMP no_overlap;
	R3 = R1 + R2;
	CC = R0 <= R3 (IU);	// (From+len) >= To
	IF CC JUMP overlap;
no_overlap:
	R3 = 11;
	CC = R2 <= R3;
	IF CC JUMP  bytes;
	R3 = R1 | R0;         // OR addresses together
	R3 <<= 30;            // check bottom two bits
	CC =  AZ;             // AZ set if zero.
	IF !CC JUMP  bytes ;  // Jump if addrs not aligned.

	I0 = P3;
	P1 = P2 >> 2;         // count = n/4
	P1 += -1;
	R3 =  3;
	R2 = R2 & R3;         // remainder
	P2 = R2;              // set remainder
	R1 = [I0++];

#if !defined(__WORKAROUND_AVOID_DAG1)
	LSETUP (quad_loop , quad_loop) LC0=P1;
quad_loop:		MNOP || [P0++] = R1 || R1 = [I0++];
#else
	LSETUP (quad_loop_s, quad_loop_e) LC0=P1;
quad_loop_s:	[P0++] = R1;
quad_loop_e:	R1 = [I0++];
#endif
	[P0++] = R1;

	CC = P2 == 0;         // any remaining bytes?
	P3 = I0;		  // Ammend P3 to updated ptr.
	IF !CC JUMP bytes;
	P3 = I1;
	RTS;

bytes:		LSETUP (byte2_s , byte2_e) LC0=P2;
byte2_s:	R1 = B[P3++](Z);
byte2_e:	B[P0++] = R1;

finished:
	P3 = I1;
	RTS;

overlap:
	P2 += -1;
	P0 = P0 + P2;
	P3 = P3 + P2;
	R1 = B[P3--] (Z);
	CC = P2 == 0;
	IF CC JUMP no_loop;
	LSETUP (ol_s, ol_e) LC0 = P2;
ol_s:		B[P0--] = R1;
ol_e:		R1 = B[P3--] (Z);
no_loop:	B[P0] = R1;
	P3 = I1;
	RTS;
.size _memmove,.-_memmove

libc_hidden_def (memmove)
