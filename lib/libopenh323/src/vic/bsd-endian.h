/*
 * Copyright (c) 1993-1994 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and the Network Research Group at
 *      Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/************ Change log
 *
 * $Log: bsd-endian.h,v $
 * Revision 1.8  2003/03/14 07:25:55  robertj
 * Removed $header keyword so is not different on alternate repositories
 *
 * Revision 1.7  2002/10/10 05:35:42  robertj
 * VxWorks port, thanks Martijn Roest
 *
 * Revision 1.6  2001/05/25 04:32:25  yurik
 * Added Arm based to list of little endian machines
 *
 * Revision 1.5  2001/05/16 06:30:16  yurik
 * Moved int_64 it to config.h
 *
 * Revision 1.4  2001/05/16 05:37:13  yurik
 * Fixed crash on video receive by #define INT_64
 *
 * Revision 1.3  2000/08/25 03:18:49  dereks
 * Add change log facility (Thanks Robert for the info on implementation)
 *
 *
 *
 ********/



#include "config.h"

#ifdef WIN32
#include <winsock.h>
#else
#ifndef P_VXWORKS
#include <sys/param.h>
#endif
#endif
#ifdef __linux__
#include <endian.h>
#endif
#ifndef IPPROTO_IP
#include <netinet/in.h>
#endif
#ifndef BYTE_ORDER
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#if defined(ultrix) || defined(__alpha) || defined(__i386__) || defined(__i486__) || defined(_X86_) || defined(_ARM_) 
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define SHIFT(n) (24 - (n))
#else
#define SHIFT(n) (n)
#endif
#define EXTRACT(v, n) (((v) >> SHIFT(n)) & 0xff)
#define SPLICE(v, p, n) (v) |= (p) << SHIFT(n)
