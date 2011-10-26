#ifndef _BITS_SYSCALLS_H
#define _BITS_SYSCALLS_H
#ifndef _SYSCALL_H
# error "Never use <bits/syscalls.h> directly; include <sys/syscall.h> instead."
#endif

#ifndef __ASSEMBLER__

#include <errno.h>
#include <asm/traps.h>

#define __syscall_return(type, res) \
do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
                                                                        \
                /* avoid using res which is declared to be in           \
                    register r2; errno might expand to a function       \
                    call and clobber it.                          */    \
                                                                        \
		int __err = -(res); \
		errno = __err; \
		res = -1; \
	} \
	return (type) (res); \
} while (0)

#define _syscall0(type,name) \
type name(void) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#define _syscall1(type,name,atype,a) \
type name(atype a) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
        "    mov     r4,    %3\n\t"   /* (long) a        */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
          , "r" ((long) a)            /* %3              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
          , "r4"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#define _syscall2(type,name,atype,a,btype,b) \
type name(atype a,btype b) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
        "    mov     r4,    %3\n\t"   /* (long) a        */ \
        "    mov     r5,    %4\n\t"   /* (long) b        */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
          , "r" ((long) a)            /* %3              */ \
          , "r" ((long) b)            /* %4              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
          , "r4"                      /* Clobbered       */ \
          , "r5"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#define _syscall3(type,name,atype,a,btype,b,ctype,c) \
type name(atype a,btype b,ctype c) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
        "    mov     r4,    %3\n\t"   /* (long) a        */ \
        "    mov     r5,    %4\n\t"   /* (long) b        */ \
        "    mov     r6,    %5\n\t"   /* (long) c        */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
          , "r" ((long) a)            /* %3              */ \
          , "r" ((long) b)            /* %4              */ \
          , "r" ((long) c)            /* %5              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
          , "r4"                      /* Clobbered       */ \
          , "r5"                      /* Clobbered       */ \
          , "r6"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#define _syscall4(type,name,atype,a,btype,b,ctype,c,dtype,d) \
type name (atype a, btype b, ctype c, dtype d) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
        "    mov     r4,    %3\n\t"   /* (long) a        */ \
        "    mov     r5,    %4\n\t"   /* (long) b        */ \
        "    mov     r6,    %5\n\t"   /* (long) c        */ \
        "    mov     r7,    %6\n\t"   /* (long) d        */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
          , "r" ((long) a)            /* %3              */ \
          , "r" ((long) b)            /* %4              */ \
          , "r" ((long) c)            /* %5              */ \
          , "r" ((long) d)            /* %6              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
          , "r4"                      /* Clobbered       */ \
          , "r5"                      /* Clobbered       */ \
          , "r6"                      /* Clobbered       */ \
          , "r7"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#define _syscall5(type,name,atype,a,btype,b,ctype,c,dtype,d,etype,e) \
type name (atype a,btype b,ctype c,dtype d,etype e) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
        "    mov     r4,    %3\n\t"   /* (long) a        */ \
        "    mov     r5,    %4\n\t"   /* (long) b        */ \
        "    mov     r6,    %5\n\t"   /* (long) c        */ \
        "    mov     r7,    %6\n\t"   /* (long) c        */ \
        "    mov     r8,    %7\n\t"   /* (long) e        */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
          , "r" ((long) a)            /* %3              */ \
          , "r" ((long) b)            /* %4              */ \
          , "r" ((long) c)            /* %5              */ \
          , "r" ((long) d)            /* %6              */ \
          , "r" ((long) e)            /* %7              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
          , "r4"                      /* Clobbered       */ \
          , "r5"                      /* Clobbered       */ \
          , "r6"                      /* Clobbered       */ \
          , "r7"                      /* Clobbered       */ \
          , "r8"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#define _syscall6(type,name,atype,a,btype,b,ctype,c,dtype,d,etype,e,ftype,f) \
type name (atype a,btype b,ctype c,dtype d,etype e,ftype f) \
{ \
    long __res;                                             \
                                                            \
    __asm__ __volatile__ (                                  \
                                                            \
        "    \n\t"                                          \
                                                            \
        "    movi    r2,    %2\n\t"   /* TRAP_ID_SYSCALL */ \
        "    movi    r3,    %1\n\t"   /* __NR_##name     */ \
        "    mov     r4,    %3\n\t"   /* (long) a        */ \
        "    mov     r5,    %4\n\t"   /* (long) b        */ \
        "    mov     r6,    %5\n\t"   /* (long) c        */ \
        "    mov     r7,    %6\n\t"   /* (long) c        */ \
        "    mov     r8,    %7\n\t"   /* (long) e        */ \
        "    mov     r9,    %8\n\t"   /* (long) f        */ \
                                                            \
        "    trap\n\t"                                      \
        "    mov     %0,    r2\n\t"   /* syscall rtn     */ \
                                                            \
        "    \n\t"                                          \
                                                            \
        :   "=r" (__res)              /* %0              */ \
                                                            \
        :   "i" (__NR_##name)         /* %1              */ \
          , "i" (TRAP_ID_SYSCALL)     /* %2              */ \
          , "r" ((long) a)            /* %3              */ \
          , "r" ((long) b)            /* %4              */ \
          , "r" ((long) c)            /* %5              */ \
          , "r" ((long) d)            /* %6              */ \
          , "r" ((long) e)            /* %7              */ \
          , "r" ((long) f)            /* %8              */ \
                                                            \
        :   "r2"                      /* Clobbered       */ \
          , "r3"                      /* Clobbered       */ \
          , "r4"                      /* Clobbered       */ \
          , "r5"                      /* Clobbered       */ \
          , "r6"                      /* Clobbered       */ \
          , "r7"                      /* Clobbered       */ \
          , "r8"                      /* Clobbered       */ \
          , "r9"                      /* Clobbered       */ \
        );                                                  \
                                                            \
__syscall_return(type,__res); \
}

#endif /* __ASSEMBLER__ */
#endif /* _BITS_SYSCALLS_H */

