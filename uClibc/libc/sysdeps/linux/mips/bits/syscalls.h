#ifndef _BITS_SYSCALLS_H
#define _BITS_SYSCALLS_H
#ifndef _SYSCALL_H
# error "Never use <bits/syscalls.h> directly; include <sys/syscall.h> instead."
#endif

#include <sgidefs.h>

#ifndef __ASSEMBLER__

#include <errno.h>

#define SYS_ify(syscall_name)  (__NR_##syscall_name)

#undef _syscall0
#define _syscall0(type,name) \
type name(void) \
{ \
return (type) (INLINE_SYSCALL(name, 0)); \
}

#undef _syscall1
#define _syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
return (type) (INLINE_SYSCALL(name, 1, arg1)); \
}

#undef _syscall2
#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
return (type) (INLINE_SYSCALL(name, 2, arg1, arg2)); \
}

#undef _syscall3
#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
return (type) (INLINE_SYSCALL(name, 3, arg1, arg2, arg3)); \
}

#undef _syscall4
#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
return (type) (INLINE_SYSCALL(name, 4, arg1, arg2, arg3, arg4)); \
} 

#undef _syscall5
#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
return (type) (INLINE_SYSCALL(name, 5, arg1, arg2, arg3, arg4, arg5)); \
}

#undef _syscall6
#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
return (type) (INLINE_SYSCALL(name, 6, arg1, arg2, arg3, arg4, arg5, arg6)); \
}

#undef _syscall7
#define _syscall7(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6,type7,arg7) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6,type7 arg7) \
{ \
return (type) (INLINE_SYSCALL(name, 7, arg1, arg2, arg3, arg4, arg5, arg6, arg7)); \
}

/*
 * Import from:
 *	glibc-ports/sysdeps/unix/sysv/linux/mips/mips32/sysdep.h
 *	glibc-ports/sysdeps/unix/sysv/linux/mips/mips64/n32/sysdep.h
 *	glibc-ports/sysdeps/unix/sysv/linux/mips/mips64/n64/sysdep.h
 */

/* Define a macro which expands into the inline wrapper code for a system
   call.  */
#undef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...)                               \
  ({ INTERNAL_SYSCALL_DECL(err);					\
     long result_var = INTERNAL_SYSCALL (name, err, nr, args);		\
     if ( INTERNAL_SYSCALL_ERROR_P (result_var, err) )			\
       {								\
	 __set_errno (INTERNAL_SYSCALL_ERRNO (result_var, err));	\
	 result_var = -1L;						\
       }								\
     result_var; })

#undef INTERNAL_SYSCALL_DECL
#define INTERNAL_SYSCALL_DECL(err) long err

#undef INTERNAL_SYSCALL_ERROR_P
#define INTERNAL_SYSCALL_ERROR_P(val, err)   ((long) (err))

#undef INTERNAL_SYSCALL_ERRNO
#define INTERNAL_SYSCALL_ERRNO(val, err)     (val)

#undef INTERNAL_SYSCALL
#define INTERNAL_SYSCALL(name, err, nr, args...) \
	internal_syscall##nr (, "li\t$2, %2\t\t\t# " #name "\n\t",	\
			      "i" (SYS_ify (name)), err, args)

#undef INTERNAL_SYSCALL_NCS
#define INTERNAL_SYSCALL_NCS(number, err, nr, args...) \
	internal_syscall##nr (= number, , "r" (__v0), err, args)

#if _MIPS_SIM == _ABIO32 || _MIPS_SIM == _ABI64
# define ARG_TYPE long
#else
# define ARG_TYPE long long
#endif

#define internal_syscall0(ncs_init, cs_init, input, err, dummy...)	\
({									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a3 __asm__("$7");				\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	".set reorder"							\
	: "=r" (__v0), "=r" (__a3)					\
	: input								\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall1(ncs_init, cs_init, input, err, arg1)		\
({									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a0 __asm__("$4") = (ARG_TYPE) arg1;		\
	register ARG_TYPE __a3 __asm__("$7");				\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	".set reorder"							\
	: "=r" (__v0), "=r" (__a3)					\
	: input, "r" (__a0)						\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall2(ncs_init, cs_init, input, err, arg1, arg2)	\
({									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a0 __asm__("$4") = (ARG_TYPE) arg1;		\
	register ARG_TYPE __a1 __asm__("$5") = (ARG_TYPE) arg2;		\
	register ARG_TYPE __a3 __asm__("$7");				\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	".set\treorder"						\
	: "=r" (__v0), "=r" (__a3)					\
	: input, "r" (__a0), "r" (__a1)					\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall3(ncs_init, cs_init, input, err, arg1, arg2, arg3)\
({									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a0 __asm__("$4") = (ARG_TYPE) arg1;		\
	register ARG_TYPE __a1 __asm__("$5") = (ARG_TYPE) arg2;		\
	register ARG_TYPE __a2 __asm__("$6") = (ARG_TYPE) arg3;		\
	register ARG_TYPE __a3 __asm__("$7");				\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	".set\treorder"						\
	: "=r" (__v0), "=r" (__a3)					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2)			\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall4(ncs_init, cs_init, input, err, arg1, arg2, arg3, arg4)\
({									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a0 __asm__("$4") = (ARG_TYPE) arg1;		\
	register ARG_TYPE __a1 __asm__("$5") = (ARG_TYPE) arg2;		\
	register ARG_TYPE __a2 __asm__("$6") = (ARG_TYPE) arg3;		\
	register ARG_TYPE __a3 __asm__("$7") = (ARG_TYPE) arg4;		\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	".set\treorder"						\
	: "=r" (__v0), "+r" (__a3)					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2)			\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#if _MIPS_SIM == _ABIO32
#include <alloca.h>
/* We need to use a frame pointer for the functions in which we
   adjust $sp around the syscall, or debug information and unwind
   information will be $sp relative and thus wrong during the syscall.  As
   of GCC 3.4.3, this is sufficient.  */
#define FORCE_FRAME_POINTER alloca (4)

#define internal_syscall5(ncs_init, cs_init, input, err, arg1, arg2, arg3, arg4, arg5)\
({									\
	long _sys_result;						\
									\
	FORCE_FRAME_POINTER;						\
	{								\
	register long __v0 __asm__("$2") ncs_init;			\
	register long __a0 __asm__("$4") = (long) arg1;			\
	register long __a1 __asm__("$5") = (long) arg2;			\
	register long __a2 __asm__("$6") = (long) arg3;			\
	register long __a3 __asm__("$7") = (long) arg4;			\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	"subu\t$29, 32\n\t"						\
	"sw\t%6, 16($29)\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	"addiu\t$29, 32\n\t"						\
	".set\treorder"						\
	: "=r" (__v0), "+r" (__a3)					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2),			\
	  "r" ((long)arg5)						\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall6(ncs_init, cs_init, input, err, arg1, arg2, arg3, arg4, arg5, arg6)\
({									\
	long _sys_result;						\
									\
	FORCE_FRAME_POINTER;						\
	{								\
	register long __v0 __asm__("$2") ncs_init;			\
	register long __a0 __asm__("$4") = (long) arg1;			\
	register long __a1 __asm__("$5") = (long) arg2;			\
	register long __a2 __asm__("$6") = (long) arg3;			\
	register long __a3 __asm__("$7") = (long) arg4;			\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	"subu\t$29, 32\n\t"						\
	"sw\t%6, 16($29)\n\t"						\
	"sw\t%7, 20($29)\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	"addiu\t$29, 32\n\t"						\
	".set\treorder"						\
	: "=r" (__v0), "+r" (__a3)					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2),			\
	  "r" ((long)arg5), "r" ((long)arg6)				\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall7(ncs_init, cs_init, input, err, arg1, arg2, arg3, arg4, arg5, arg6, arg7)\
({									\
	long _sys_result;						\
									\
	FORCE_FRAME_POINTER;						\
	{								\
	register long __v0 __asm__("$2") ncs_init;			\
	register long __a0 __asm__("$4") = (long) arg1;			\
	register long __a1 __asm__("$5") = (long) arg2;			\
	register long __a2 __asm__("$6") = (long) arg3;			\
	register long __a3 __asm__("$7") = (long) arg4;			\
	__asm__ __volatile__ (						\
	".set\tnoreorder\n\t"						\
	"subu\t$29, 32\n\t"						\
	"sw\t%6, 16($29)\n\t"						\
	"sw\t%7, 20($29)\n\t"						\
	"sw\t%8, 24($29)\n\t"						\
	cs_init								\
	"syscall\n\t"							\
	"addiu\t$29, 32\n\t"						\
	".set\treorder"						\
	: "=r" (__v0), "+r" (__a3)					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2),			\
	  "r" ((long)arg5), "r" ((long)arg6), "r" ((long)arg7)		\
	: __SYSCALL_CLOBBERS);						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define __SYSCALL_CLOBBERS "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", \
	"$14", "$15", "$24", "$25", "memory"

#else /* N32 || N64 */

#define internal_syscall5(ncs_init, cs_init, input, err, arg1, arg2, arg3, arg4, arg5) \
({ 									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a0 __asm__("$4") = (ARG_TYPE) arg1; 	\
	register ARG_TYPE __a1 __asm__("$5") = (ARG_TYPE) arg2; 	\
	register ARG_TYPE __a2 __asm__("$6") = (ARG_TYPE) arg3; 	\
	register ARG_TYPE __a3 __asm__("$7") = (ARG_TYPE) arg4; 	\
	register ARG_TYPE __a4 __asm__("$8") = (ARG_TYPE) arg5; 	\
	__asm__ __volatile__ ( 						\
	".set\tnoreorder\n\t" 						\
	cs_init								\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "+r" (__a3) 					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2), "r" (__a4)		\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall6(ncs_init, cs_init, input, err, arg1, arg2, arg3, arg4, arg5, arg6) \
({ 									\
	long _sys_result;						\
									\
	{								\
	register ARG_TYPE __v0 __asm__("$2") ncs_init;			\
	register ARG_TYPE __a0 __asm__("$4") = (ARG_TYPE) arg1; 	\
	register ARG_TYPE __a1 __asm__("$5") = (ARG_TYPE) arg2; 	\
	register ARG_TYPE __a2 __asm__("$6") = (ARG_TYPE) arg3; 	\
	register ARG_TYPE __a3 __asm__("$7") = (ARG_TYPE) arg4; 	\
	register ARG_TYPE __a4 __asm__("$8") = (ARG_TYPE) arg5; 	\
	register ARG_TYPE __a5 __asm__("$9") = (ARG_TYPE) arg6; 	\
	__asm__ __volatile__ ( 						\
	".set\tnoreorder\n\t" 						\
	cs_init								\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "+r" (__a3) 					\
	: input, "r" (__a0), "r" (__a1), "r" (__a2), "r" (__a4),	\
	  "r" (__a5)							\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define __SYSCALL_CLOBBERS "$1", "$3", "$10", "$11", "$12", "$13", \
	"$14", "$15", "$24", "$25", "memory"

#endif

#endif /* __ASSEMBLER__ */
#endif /* _BITS_SYSCALLS_H */
