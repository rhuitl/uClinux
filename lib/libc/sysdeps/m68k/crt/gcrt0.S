/*
 * Copyright (c) 1993 Eric Youngdale, Peter MacDonald, David Engel
 * and Hongjiu Lu.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the above contributors may not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Notice of general intent:
 *
 * The linux operating system generally contains large amounts of code
 * that fall under the GNU General Public License, or GPL for short.
 * This file contains source code that by it's very nature would always
 * be linked with an application program, and because of this a GPL type
 * of copyright on this file would place restrictions upon the
 * distribution of binary-only commercial software.  Since the goal of the
 * Linux project as a whole is not to discourage the development and
 * distribution of commercial software for Linux, this file has been placed
 * under a more relaxed BSD-style of copyright.
 *
 * It is the general understanding of the above contributors that a
 * program executable linked to a library containing code that falls
 * under the GPL or GLPL style of license is not subject to the terms of
 * the GPL or GLPL license if the program executable(s) that are supplied
 * are linked to a shared library form of the GPL or GLPL library, and as long
 * as the form of the shared library is such that it is possible for
 * the end user to modify and rebuild the library and use it in
 * conjunction with the program executable.
 */

#ifdef __ELF__
#define _main main
#define _atexit atexit
#define _exit exit
#define ___libc_init __libc_init
#define _setlocale setlocale
#define ___setfpucw __setfpucw
#define ___fpu_control __fpu_control
#define ___environ __environ
#define ____brk_addr ___brk_addr
#define _monstartup monstartup
#define __mcleanup _mcleanup
#define __entry _start
#define d0 %D0
#define d1 %D1
#define a0 %A0
#define sp %SP
#endif

	.file "gcrt0.S"

#if defined (__ELF__) && defined (CALL_DEFAULT_LOCALE)
	.section .rodata
	.align 4
	.type ___null_string,@object
	.size ___null_string,4
___null_string:
	.long .L_shared_dummy__
.L_shared_dummy__:
	.asciz ""
#endif

	.text
___crt_dummy__:
#ifndef __ELF__
__entry:
/*
 * The first thing we do is try to load the shared library. If that
 * fails, it won't return.
 */
	jbsr ___load_shared_libraries
#else
/* ELF stuff here */
.globl _start
.type _start,@function
_start:
	/* First locate the start of the environment variables */
	movel sp@+,d0
	movel sp,a0
	pea sp@(4,d0:l:4)
	movel a0,sp@-
	movel d0,sp@-
#endif
#if 0
/*
 *	This is important, and was missing from the new version...
 */
	moveq #45,d0
	moveq #0,d1
	trap  #0
	movel d0,____brk_addr
#endif
/*
 *	Setup profiling
 */
	pea   __mcleanup
	jbsr  _atexit
	addql #4,sp
	pea   _etext
	pea   __entry
	jbsr  _monstartup
	addql #8,sp
/*
 *	Setup ___environ and call _main
 */
	movel sp@(8),___environ
	movel ___fpu_control,sp@-
	jbsr  ___setfpucw
	addql #4,sp
/* Some functions may be needed. */
	jbsr  ___libc_init    
#ifdef CALL_DEFAULT_LOCALE
/* Set up the default locale */
	movel ___null_string,sp@-
	pea DEFAULT_LOCALE
	jbsr _setlocale
	addql #8,sp
#endif
#ifdef ELF_INIT_FINI
	pea _fini
	jbsr atexit
	addql #4,sp
	jbsr _init
#endif
	jbsr  _main
	movel d0,sp@-
	jbsr  _exit
/*
 *	Just in case _exit fails... We use trap #0 for __exit().
 */
	addql #4,sp
done:
	moveq #1,d0
	trap  #0
	bras  done

#ifdef __ELF__
	.size	_start,.-_start
        .globl __environ
	.data   
	.type __environ,@object
	.align 4
__environ:
	.long 0 
	.size __environ,4
	.weak environ
	environ = __environ
#else
	.align	2
#ifdef CALL_DEFAULT_LOCALE
___null_string:
	.long ___shared_dummy__
#endif
___shared_dummy__:
	.asciz ""
	.stabs "___SHARED_LIBRARIES__",25,0,0,___shared_dummy__

	.data
	.align	2
___shared_dummy1__:
	.long 0xfeeb1ed3  /* Magic number used by DLL code to make sure this
			     is a real list */

	.stabs "__SHARABLE_CONFLICTS__",25,0,0,___shared_dummy1__
#endif
