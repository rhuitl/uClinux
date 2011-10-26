/* memcmp.S
 * Copyright (C) 2003, 2005, 2006 Analog Devices Inc., All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 */

/* int memcmp(const void *s1, const void *s2, size_t n);
 * R0 = First Address (s1)
 * R1 = Second Address (s2)
 * R2 = count (n)
 *
 * Favours word aligned data.
 */

#include <features.h>

.text

.align 2

.global _memcmp
.type _memcmp, STT_FUNC
_memcmp:
	I1 = P3;
	P0 = R0;              // P0 = s1 address
	P3 = R1;              // P3 = s2 Address
	P2 = R2 ;             // P2 = count
	CC = R2 <= 7(IU);
	IF CC JUMP  too_small;
	I0 = R1;		    // s2
	R1 = R1 | R0;         // OR addresses together
	R1 <<= 30;            // check bottom two bits
	CC =  AZ;             // AZ set if zero.
	IF !CC JUMP  bytes ;  // Jump if addrs not aligned.

	P1 = P2 >> 2;          // count = n/4
	R3 =  3;
	R2 = R2 & R3;         // remainder
	P2 = R2;               // set remainder

	LSETUP (quad_loop_s , quad_loop_e) LC0=P1;
quad_loop_s:
#if !defined(__WORKAROUND_AVOID_DAG1)
	MNOP || R0 = [P0++] || R1 = [I0++];
#else
	R0 = [P0++];
	R1 = [I0++];
#endif
	CC = R0 == R1;
	IF !CC JUMP quad_different;
quad_loop_e:
	NOP;

	P3 = I0;                 // s2
too_small:
	CC = P2 == 0;            //Check zero count
	IF CC JUMP finished;     // very unlikely

bytes:
	LSETUP (byte_loop_s , byte_loop_e) LC0=P2;
byte_loop_s:
	R1 = B[P3++](Z);	// *s2
	R0 = B[P0++](Z);	// *s1
	CC = R0 == R1;
	IF !CC JUMP different;
byte_loop_e:
	NOP;

different:
	R0 = R0 - R1;
	P3 = I1;
	RTS;

quad_different:
	// We've read two quads which don't match.
	// Can't just compare them, because we're
	// a little-endian machine, so the MSBs of
	// the regs occur at later addresses in the
	// string.
	// Arrange to re-read those two quads again,
	// byte-by-byte.
	P0 += -4;	// back up to the start of the
	P3 = I0;	// quads, and increase the
	P2 += 4;	// remainder count
	P3 += -4;
	JUMP bytes;

finished:
	R0 = 0;
	P3 = I1;
	RTS;
.size _memcmp,.-_memcmp

libc_hidden_def (memcmp)

#ifdef __UCLIBC_SUSV3_LEGACY__
strong_alias (memcmp,bcmp)
#endif
