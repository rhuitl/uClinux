#ifndef _BITS_SYSCALLS_H
#define _BITS_SYSCALLS_H
#ifndef _SYSCALL_H
# error "Never use <bits/syscalls.h> directly; include <sys/syscall.h> instead."
#endif

#ifndef __ASSEMBLER__

#include <errno.h>

#define SYS_ify(syscall_name)  (__NR_##syscall_name)

/* user-visible error numbers are in the range -1 - -4095: see <asm-frv/errno.h> */
#if defined _LIBC && !defined __set_errno
# define __syscall_return(type, res) \
do { \
        unsigned long __sr2 = (res);		    			    \
	if (__builtin_expect ((unsigned long)(__sr2)			    \
			      >= (unsigned long)(-4095), 0)) {		    \
		extern int __syscall_error (int);			    \
		return (type) __syscall_error (__sr2);		    	    \
	}								    \
	return (type) (__sr2); 						    \
} while (0)
#else
# define __syscall_return(type, res) \
do { \
        unsigned long __sr2 = (res);		    			    \
	if (__builtin_expect ((unsigned long)(__sr2)			    \
			      >= (unsigned long)(-4095), 0)) {		    \
		__set_errno (-__sr2);				    	    \
		__sr2 = -1; 						    \
	}								    \
	return (type) (__sr2); 						    \
} while (0)
#endif

#define _syscall0(type,name)						\
type name(void) {							\
	long __res;							\
	__asm__ __volatile__ (						\
		"p0 = %1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i" (__NR_##name)					\
		: "memory","CC","R0","P0");				\
	__syscall_return(type,__res);					\
}

#define _syscall1(type,name,type1,arg1)					\
type name(type1 arg1) {							\
	long __res;							\
	__asm__ __volatile__ (						\
		"r0=%2;\n\t"						\
		"p0=%1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i" (__NR_##name),					\
		  "rm" ((long)(arg1))					\
		: "memory","CC","R0","P0");				\
	__syscall_return(type,__res);					\
}

#define _syscall2(type,name,type1,arg1,type2,arg2)			\
type name(type1 arg1,type2 arg2) {					\
	long __res;							\
	__asm__ __volatile__ (						\
		"r1=%3;\n\t"						\
		"r0=%2;\n\t"						\
		"p0=%1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i" (__NR_##name),					\
		  "rm" ((long)(arg1)),					\
		  "rm" ((long)(arg2))					\
		: "memory","CC","R0","R1","P0");			\
	__syscall_return(type,__res);					\
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3)		\
type name(type1 arg1,type2 arg2,type3 arg3) {				\
	long __res;							\
	__asm__ __volatile__ (						\
		"r2=%4;\n\t"						\
		"r1=%3;\n\t"						\
		"r0=%2;\n\t"						\
		"p0=%1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i"   (__NR_##name),					\
		  "rm"   ((long)(arg1)),				\
		  "rm"   ((long)(arg2)),				\
		  "rm"   ((long)(arg3))					\
		: "memory","CC","R0","R1","R2","P0");			\
	__syscall_return(type,__res);					\
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4)\
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {		\
	long __res;							\
	__asm__ __volatile__ (						\
		"r3=%5;\n\t"						\
		"r2=%4;\n\t"						\
		"r1=%3;\n\t"						\
		"r0=%2;\n\t"						\
		"p0=%1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i"  (__NR_##name),					\
		  "rm"  ((long)(arg1)),					\
		  "rm"  ((long)(arg2)),					\
		  "rm"  ((long)(arg3)),					\
		  "rm"  ((long)(arg4))					\
		: "memory","CC","R0","R1","R2","R3","P0");		\
	__syscall_return(type,__res);					\
}

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5)	\
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {	\
	long __res;							\
	__asm__ __volatile__ (						\
		"r4=%6;\n\t"						\
		"r3=%5;\n\t"						\
		"r2=%4;\n\t"						\
		"r1=%3;\n\t"						\
		"r0=%2;\n\t"						\
		"P0=%1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i"  (__NR_##name),					\
		  "rm"  ((long)(arg1)),					\
		  "rm"  ((long)(arg2)),					\
		  "rm"  ((long)(arg3)),					\
		  "rm"  ((long)(arg4)),					\
		  "rm"  ((long)(arg5))					\
		: "memory","CC","R0","R1","R2","R3","R4","P0");		\
	__syscall_return(type,__res);					\
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5,type6,arg6) \
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) { \
	long __res;							\
	__asm__ __volatile__ (						\
		"r5=%7;\n\t"						\
		"r4=%6;\n\t"						\
		"r3=%5;\n\t"						\
		"r2=%4;\n\t"						\
		"r1=%3;\n\t"						\
		"r0=%2;\n\t"						\
		"P0=%1;\n\t"						\
		"excpt 0;\n\t"						\
		"%0=r0;\n\t"						\
		: "=da" (__res)						\
		: "i"  (__NR_##name),					\
		  "rm"  ((long)(arg1)),					\
		  "rm"  ((long)(arg2)),					\
		  "rm"  ((long)(arg3)),					\
		  "rm"  ((long)(arg4)),					\
		  "rm"  ((long)(arg5)),					\
		  "rm"  ((long)(arg6))					\
		: "memory","CC","R0","R1","R2","R3","R4","R5","P0");	\
	__syscall_return(type,__res);					\
}

#endif /* __ASSEMBLER__ */
#endif /* _BITS_SYSCALLS_H */
