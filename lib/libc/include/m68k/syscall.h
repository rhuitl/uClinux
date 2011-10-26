#ifndef _M68K_SYSCALL_H
#define _M68K_SYSCALL_H

#include <asm/unistd.h> /* ensure kernel version is always included first */

#undef _syscall0
#define _syscall0(type, name)							\
type name(void)									\
{										\
  long __res;									\
  __asm__ __volatile__ ("movel	%1, %%d0\n\t"					\
  			"trap	#0\n\t"						\
  			"movel	%%d0, %0"					\
			: "=g" (__res)						\
			: "i" (SYS_##name)					\
			: "cc", "%d0");						\
  if ((unsigned long)(__res) >= (unsigned long)(-125)) {				\
    errno = -__res;								\
    __res = -1;									\
  }										\
  return (type)__res;								\
}

#undef _syscall1
#define _syscall1(type, name, atype, a)						\
type name(atype a)								\
{										\
  long __res;									\
  __asm__ __volatile__ ("movel	%2, %%d1\n\t"					\
  			"movel	%1, %%d0\n\t"					\
  			"trap	#0\n\t"						\
  			"movel	%%d0, %0"					\
			: "=g" (__res)						\
			: "i" (SYS_##name),					\
			  "g" ((long)a)						\
			: "cc", "%d0", "%d1");					\
  if ((unsigned long)(__res) >= (unsigned long)(-125)) {				\
    errno = -__res;								\
    __res = -1;									\
  }										\
  return (type)__res;								\
}

#undef _syscall2
#define _syscall2(type, name, atype, a, btype, b)				\
type name(atype a, btype b)							\
{										\
  long __res;									\
  __asm__ __volatile__ ("movel	%3, %%d2\n\t"					\
  			"movel	%2, %%d1\n\t"					\
			"movel	%1, %%d0\n\t"					\
  			"trap	#0\n\t"						\
  			"movel	%%d0, %0"					\
			: "=g" (__res)						\
			: "i" (SYS_##name),					\
			  "ai" ((long)a),					\
			  "g" ((long)b)						\
			: "cc", "%d0", "%d1", "%d2");				\
  if ((unsigned long)(__res) >= (unsigned long)(-125)) {				\
    errno = -__res;								\
    __res = -1;									\
  }										\
  return (type)__res;								\
}

#undef _syscall3
#define _syscall3(type, name, atype, a, btype, b, ctype, c)			\
type name(atype a, btype b, ctype c)						\
{										\
  long __res;									\
  __asm__ __volatile__ ("movel	%4, %%d3\n\t"					\
			"movel	%3, %%d2\n\t"					\
  			"movel	%2, %%d1\n\t"					\
			"movel	%1, %%d0\n\t"					\
  			"trap	#0\n\t"						\
  			"movel	%%d0, %0"					\
			: "=g" (__res)						\
			: "i" (SYS_##name),					\
			  "ai" ((long)a),					\
			  "ai" ((long)b),					\
			  "g" ((long)c)						\
			: "cc", "%d0", "%d1", "%d2", "%d3");			\
  if ((unsigned long)(__res) >= (unsigned long)(-125)) {				\
    errno = -__res;								\
    __res = -1;									\
  }										\
  return (type)__res;								\
}

#undef _syscall4
#define _syscall4(type, name, atype, a, btype, b, ctype, c, dtype, d)		\
type name(atype a, btype b, ctype c, dtype d)					\
{										\
  long __res;									\
  __asm__ __volatile__ ("movel	%5, %%d4\n\t"					\
			"movel	%4, %%d3\n\t"					\
			"movel	%3, %%d2\n\t"					\
  			"movel	%2, %%d1\n\t"					\
			"movel	%1, %%d0\n\t"					\
  			"trap	#0\n\t"						\
  			"movel	%%d0, %0"					\
			: "=g" (__res)						\
			: "i" (SYS_##name),					\
			  "ai" ((long)a),					\
			  "ai" ((long)b),					\
			  "ai" ((long)c),					\
			  "g" ((long)d)						\
			: "cc", "%d0", "%d1", "%d2", "%d3",			\
			  "%d4");						\
  if ((unsigned long)(__res) >= (unsigned long)(-125)) {				\
    errno = -__res;								\
    __res = -1;									\
  }										\
  return (type)__res;								\
}

#undef _syscall5
#define _syscall5(type, name, atype, a, btype, b, ctype, c, dtype, d, etype, e)	\
type name(atype a, btype b, ctype c, dtype d, etype e)				\
{										\
  long __res;									\
  __asm__ __volatile__ ("movel	%6, %%d5\n\t"					\
			"movel	%5, %%d4\n\t"					\
			"movel	%4, %%d3\n\t"					\
			"movel	%3, %%d2\n\t"					\
  			"movel	%2, %%d1\n\t"					\
			"movel	%1, %%d0\n\t"					\
  			"trap	#0\n\t"						\
  			"movel	%%d0, %0"					\
			: "=g" (__res)						\
			: "i" (SYS_##name),					\
			  "ai" ((long)a),					\
			  "ai" ((long)b),					\
			  "ai" ((long)c),					\
			  "ai" ((long)d),					\
			  "g" ((long)e)						\
			: "cc", "%d0", "%d1", "%d2", "%d3",			\
			  "%d4", "%d5");					\
  if ((unsigned long)(__res) >= (unsigned long)(-125)) {				\
    errno = -__res;								\
    __res = -1;									\
  }										\
  return (type)__res;								\
}


#endif /* _M68K_SYSCALL_H */
