/* Copyright (C) 2000 Free Software Foundation, Inc.
   Seriously hacked for uClibc by Greg Ungerer (gerg@snapgear.com), 2002.
   Contributed by Jakub Jelinek <jakub@redhat.com>, 2000.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _LINUX_OR32_SYSCALL_H
#define _LINUX_OR32_SYSCALL_H 1

#undef _syscall0
#define _syscall0(type,name)						\
type name(void)								\
{									\
	register long __res __asm__ ("r11") = __NR_##name;		\
	__asm__ ("l.sys	1" : "=r" (__res) : "r" (__res)); 		\
	__asm__ ("l.nop");						\
	if (((unsigned long) res) >= ((unsigned long) -125)) {		\
		errno = -res;						\
		res = -1;						\
	}								\
	return((type) __res);						\
}

#undef	_syscall1
#define _syscall1(type,name,atype1,arg1)				\
type name(atype1 arg1)							\
{									\
	register long __res __asm__ ("r11") = __NR_##name;		\
	register long __arg1 __asm__ ("r3") = (long)(arg1);		\
	__asm__ ("l.sys	1" :						\
		"=r" (__res) :						\
		"r" (__res), "r" (__arg1)); 				\
	__asm__ ("l.nop");						\
	if (((unsigned long) res) >= ((unsigned long) -125)) {		\
		errno = -res;						\
		res = -1;						\
	}								\
	return((type) __res);						\
}

#undef	_syscall2
#define _syscall2(type,name,atype1,arg1,atype2,arg2)			\
type name(atype1 arg1, atype2 arg2)					\
{									\
	register long __res __asm__ ("r11") = __NR_##name;		\
	register long __arg1 __asm__ ("r3") = (long)(arg1);		\
	register long __arg2 __asm__ ("r4") = (long)(arg2);		\
	__asm__ ("l.sys	1" :						\
		"=r" (__res) :						\
		"r" (__res), "r" (__arg1), "r" (__arg2));		\
	__asm__ ("l.nop");						\
	if (((unsigned long) res) >= ((unsigned long) -125)) {		\
		errno = -res;						\
		res = -1;						\
	}								\
	return((type) __res);						\
}

#undef	_syscall3
#define _syscall3(type,name,atype1,arg1,atype2,arg2,atype3,arg3)	\
type name(atype1 arg1, atype2 arg2, atype3 arg3)			\
{									\
	register long __res __asm__ ("r11") = __NR_##name;		\
	register long __arg1 __asm__ ("r3") = (long)(arg1);		\
	register long __arg2 __asm__ ("r4") = (long)(arg2);		\
	register long __arg3 __asm__ ("r5") = (long)(arg3);		\
	__asm__ ("l.sys	1" :						\
		"=r" (__res) :						\
		"r" (__res), "r" (__arg1), "r" (__arg2), "r" (__arg3));	\
	__asm__ ("l.nop");						\
	if (((unsigned long) res) >= ((unsigned long) -125)) {		\
		errno = -res;						\
		res = -1;						\
	}								\
	return((type) __res);						\
}

#undef	_syscall4
#define _syscall4(type,name,atype1,arg1,atype2,arg2,atype3,arg3,atype4,arg4) \
type name(atype1 arg1, atype2 arg2, atype3 arg3, atype4 arg4)		\
{									\
	register long __res __asm__ ("r11") = __NR_##name;		\
	register long __arg1 __asm__ ("r3") = (long)(arg1);		\
	register long __arg2 __asm__ ("r4") = (long)(arg2);		\
	register long __arg3 __asm__ ("r5") = (long)(arg3);		\
	register long __arg4 __asm__ ("r6") = (long)(arg4);		\
	__asm__ ("l.sys	1" :						\
		"=r" (__res) :						\
		"r" (__res), "r" (__arg1), "r" (__arg2), "r" (__arg3),	\
		"r" (__arg4)); 						\
	__asm__ ("l.nop");						\
	if (((unsigned long) res) >= ((unsigned long) -125)) {		\
		errno = -res;						\
		res = -1;						\
	}								\
	return((type) __res);						\
}

#undef	_syscall5
#define _syscall5(type,name,atype1,arg1,atype2,arg2,atype3,arg3,atype4,arg4,atype5,arg5) \
type name(atype1 arg1, atype2 arg2, atype3 arg3, atype4 arg4, atype5 arg5) \
{									\
	register long __res __asm__ ("r11") = __NR_##name;		\
	register long __arg1 __asm__ ("r3") = (long)(arg1);		\
	register long __arg2 __asm__ ("r4") = (long)(arg2);		\
	register long __arg3 __asm__ ("r5") = (long)(arg3);		\
	register long __arg4 __asm__ ("r6") = (long)(arg4);		\
	register long __arg5 __asm__ ("r7") = (long)(arg5);		\
	__asm__ ("l.sys	1" :						\
		"=r" (__res) :						\
		"r" (__res), "r" (__arg1), "r" (__arg2), "r" (__arg3),	\
		"r" (__arg4), "r" (__arg5));				\
	__asm__ ("l.nop");						\
	if (((unsigned long) res) >= ((unsigned long) -125)) {		\
		errno = -res;						\
		res = -1;						\
	}								\
	return((type) __res);						\
}

#endif /* _LINUX_OR32_SYSCALL_H */
