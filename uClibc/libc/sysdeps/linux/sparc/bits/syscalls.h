#ifndef _BITS_SYSCALLS_H
#define _BITS_SYSCALLS_H
#ifndef _SYSCALL_H
# error "Never use <bits/syscalls.h> directly; include <sys/syscall.h> instead."
#endif

#include <bits/wordsize.h>

#ifndef __ASSEMBLER__

#include <errno.h>

#define SYS_ify(syscall_name)  (__NR_##syscall_name)

#undef __SYSCALL_STRING
#if __WORDSIZE == 32
# define __SYSCALL_STRING \
	"t 0x10\n\t" \
	"bcc 1f\n\t" \
	"mov %%o0, %0\n\t" \
	"sub %%g0, %%o0, %0\n\t" \
	"1:\n\t"
# define __SYSCALL_RES_CHECK (__res < -255 || __res >= 0)
#elif __WORDSIZE == 64
# define __SYSCALL_STRING \
	"t 0x6d\n\t" \
	"sub %%g0, %%o0, %0\n\t" \
	"movcc %%xcc, %%o0, %0\n\t"
# define __SYSCALL_RES_CHECK (__res >= 0)
#else
# error unknown __WORDSIZE
#endif

#define __SYSCALL_RETURN(type) \
	if (__SYSCALL_RES_CHECK) \
		return (type) __res; \
	__set_errno (-__res); \
	return (type) -1;

#undef _syscall0
#define _syscall0(type,name) \
type name(void) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res)\
		      : "r" (__g1) \
		      : "o0", "cc"); \
__SYSCALL_RETURN(type) \
}

#undef _syscall1
#define _syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res), "=&r" (__o0) \
		      : "1" (__o0), "r" (__g1) \
		      : "cc"); \
__SYSCALL_RETURN(type) \
}

#undef _syscall2
#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
register long __o1 __asm__ ("o1") = (long)(arg2); \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res), "=&r" (__o0) \
		      : "1" (__o0), "r" (__o1), "r" (__g1) \
		      : "cc"); \
__SYSCALL_RETURN(type) \
}

#undef _syscall3
#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
register long __o1 __asm__ ("o1") = (long)(arg2); \
register long __o2 __asm__ ("o2") = (long)(arg3); \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res), "=&r" (__o0) \
		      : "1" (__o0), "r" (__o1), "r" (__o2), "r" (__g1) \
		      : "cc"); \
__SYSCALL_RETURN(type) \
}

#undef _syscall4
#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
register long __o1 __asm__ ("o1") = (long)(arg2); \
register long __o2 __asm__ ("o2") = (long)(arg3); \
register long __o3 __asm__ ("o3") = (long)(arg4); \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res), "=&r" (__o0) \
		      : "1" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__g1) \
		      : "cc"); \
__SYSCALL_RETURN(type) \
} 

#undef _syscall5
#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
register long __o1 __asm__ ("o1") = (long)(arg2); \
register long __o2 __asm__ ("o2") = (long)(arg3); \
register long __o3 __asm__ ("o3") = (long)(arg4); \
register long __o4 __asm__ ("o4") = (long)(arg5); \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res), "=&r" (__o0) \
		      : "1" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__o4), "r" (__g1) \
		      : "cc"); \
__SYSCALL_RETURN(type) \
}

#undef _syscall6
#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
long __res; \
register long __g1 __asm__ ("g1") = __NR_##name; \
register long __o0 __asm__ ("o0") = (long)(arg1); \
register long __o1 __asm__ ("o1") = (long)(arg2); \
register long __o2 __asm__ ("o2") = (long)(arg3); \
register long __o3 __asm__ ("o3") = (long)(arg4); \
register long __o4 __asm__ ("o4") = (long)(arg5); \
register long __o5 __asm__ ("o5") = (long)(arg6); \
__asm__ __volatile__ (__SYSCALL_STRING \
		      : "=r" (__res), "=&r" (__o0) \
		      : "1" (__o0), "r" (__o1), "r" (__o2), "r" (__o3), "r" (__o4), "r" (__o5), "r" (__g1) \
		      : "cc"); \
__SYSCALL_RETURN(type) \
}

#endif /* __ASSEMBLER__ */
#endif /* _BITS_SYSCALLS_H */
