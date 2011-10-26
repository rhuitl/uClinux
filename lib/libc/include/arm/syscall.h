#ifndef _ARM_SYSCALL_H
#define _ARM_SYSCALL_H

#define __sys2(x) #x
#define __sys1(x) __sys2(x)


#undef __syscall
#define __syscall(name) "swi "  "0x900000+" __sys1(SYS_##name) "\n\t"


#ifdef PTHREADS_SYSCALL

#define __fixret(r,type) return (type) r

#else /* PTHREADS_SYSCALL */

#define __fixret(r,type) \
		if (r >= 0)\
			return (type) r; \
		errno = -r;	\
		return -1;


#endif

#ifndef _syscall0
#define _syscall0(type,name)								\
			type name(void) {									\
			long __res;										\
			__asm__ __volatile__ (								\
			__syscall(name)									\
			"mov %0,r0\n\t"									\
			:"=r" (__res) : : "r0","r1","r2","r3","lr");						\
			__fixret(__res, type); \
			}

#define _syscall1(type,name,type1,arg1)							\
			type name(type1 arg1) {									\
			long __res;										\
			__asm__ __volatile__ (								\
			"mov r0,%1\n\t"									\
			__syscall(name)									\
			"mov %0,r0\n\t"									\
			: "=r" (__res)									\
			: "r" ((long)(arg1))								\
			: "r0","r1","r2","r3","lr");							\
			__fixret(__res,type); \
			}

#define _syscall2(type,name,type1,arg1,type2,arg2)					\
		type name(type1 arg1,type2 arg2) {							\
		long __res;										\
		__asm__ __volatile__ (								\
		"mov r0,%1\n\t"									\
		"mov r1,%2\n\t"									\
		__syscall(name)									\
		"mov %0,r0\n\t"									\
		: "=r" (__res)									\
		: "r" ((long)(arg1)),"r" ((long)(arg2))						\
		: "r0","r1","r2","r3","lr");							\
		__fixret(__res,type); \
		}


#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3)				\
				type name(type1 arg1,type2 arg2,type3 arg3) {						\
				long __res;										\
				__asm__ __volatile__ (								\
				"mov r0,%1\n\t"									\
				"mov r1,%2\n\t"									\
				"mov r2,%3\n\t"									\
				__syscall(name)									\
				"mov %0,r0\n\t"									\
				: "=r" (__res)									\
				: "r" ((long)(arg1)),"r" ((long)(arg2)),"r" ((long)(arg3))			\
				: "r0","r1","r2","r3","lr");							\
				__fixret(__res,type); \
				}


#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4)		\
					type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {				\
					long __res;										\
					__asm__ __volatile__ (								\
					"mov r0,%1\n\t"									\
					"mov r1,%2\n\t"									\
					"mov r2,%3\n\t"									\
					"mov r3,%4\n\t"									\
					__syscall(name)									\
					"mov %0,r0\n\t"									\
					: "=r" (__res)									\
					: "r" ((long)(arg1)),"r" ((long)(arg2)),"r" ((long)(arg3)),"r" ((long)(arg4))	\
					: "r0","r1","r2","r3","lr");							\
					__fixret(__res,type); \
					}


#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5)	\
					type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {			\
					long __res;										\
					__asm__ __volatile__ (								\
					"mov r0,%1\n\t"									\
					"mov r1,%2\n\t"									\
					"mov r2,%3\n\t"									\
					"mov r3,%4\n\t"									\
					"mov r4,%5\n\t"									\
					__syscall(name)									\
					"mov %0,r0\n\t"									\
					: "=r" (__res)									\
					: "r" ((long)(arg1)),"r" ((long)(arg2)),"r" ((long)(arg3)),"r" ((long)(arg4)),	\
					"r" ((long)(arg5))								\
					: "r0","r1","r2","r3","r4","lr");						\
					__fixret(__res,type); \
					}




#endif

#endif /* _ARM_SYSCALL_H */
