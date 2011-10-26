#ifndef _BITS_SYSCALLS_H
#define _BITS_SYSCALLS_H
#ifndef _SYSCALL_H
# error "Never use <bits/syscalls.h> directly; include <sys/syscall.h> instead."
#endif

#ifndef __ASSEMBLER__

#include <errno.h>

#define SYS_ify(syscall_name)  (__NR_##syscall_name)

#define _syscall_return(type)						\
	return (_sc_err ? __set_errno(_sc_ret), _sc_ret = -1L : 0), (type) _sc_ret

#define _syscall_clobbers						\
	"$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8",			\
	"$22", "$23", "$24", "$25", "$27", "$28" 			\

#define _syscall0(type, name)						\
type name(void)								\
{									\
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_19 __asm__("$19");			\
									\
		_sc_0 = __NR_##name;					\
		__asm__("callsys # %0 %1 %2"				\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0)					\
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
}

#define _syscall1(type,name,type1,arg1)					\
type name(type1 arg1)							\
{									\
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_16 __asm__("$16");			\
		register long _sc_19 __asm__("$19");			\
									\
		_sc_0 = __NR_##name;					\
		_sc_16 = (long) (arg1);					\
		__asm__("callsys # %0 %1 %2 %3"				\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0), "r"(_sc_16)			\
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
}

#define _syscall2(type,name,type1,arg1,type2,arg2)			\
type name(type1 arg1,type2 arg2)					\
{									\
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_16 __asm__("$16");			\
		register long _sc_17 __asm__("$17");			\
		register long _sc_19 __asm__("$19");			\
									\
		_sc_0 = __NR_##name;					\
		_sc_16 = (long) (arg1);					\
		_sc_17 = (long) (arg2);					\
		__asm__("callsys # %0 %1 %2 %3 %4"			\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0), "r"(_sc_16), "r"(_sc_17)		\
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3)		\
type name(type1 arg1,type2 arg2,type3 arg3)				\
{									\
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_16 __asm__("$16");			\
		register long _sc_17 __asm__("$17");			\
		register long _sc_18 __asm__("$18");			\
		register long _sc_19 __asm__("$19");			\
									\
		_sc_0 = __NR_##name;					\
		_sc_16 = (long) (arg1);					\
		_sc_17 = (long) (arg2);					\
		_sc_18 = (long) (arg3);					\
		__asm__("callsys # %0 %1 %2 %3 %4 %5"			\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0), "r"(_sc_16), "r"(_sc_17),		\
			  "r"(_sc_18)					\
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4)		 \
{									 \
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_16 __asm__("$16");			\
		register long _sc_17 __asm__("$17");			\
		register long _sc_18 __asm__("$18");			\
		register long _sc_19 __asm__("$19");			\
									\
		_sc_0 = __NR_##name;					\
		_sc_16 = (long) (arg1);					\
		_sc_17 = (long) (arg2);					\
		_sc_18 = (long) (arg3);					\
		_sc_19 = (long) (arg4);					\
		__asm__("callsys # %0 %1 %2 %3 %4 %5 %6"		\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0), "r"(_sc_16), "r"(_sc_17),		\
			  "r"(_sc_18), "1"(_sc_19)			\
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
} 

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5)							 \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5)	\
{									\
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_16 __asm__("$16");			\
		register long _sc_17 __asm__("$17");			\
		register long _sc_18 __asm__("$18");			\
		register long _sc_19 __asm__("$19");			\
		register long _sc_20 __asm__("$20");			\
									\
		_sc_0 = __NR_##name;					\
		_sc_16 = (long) (arg1);					\
		_sc_17 = (long) (arg2);					\
		_sc_18 = (long) (arg3);					\
		_sc_19 = (long) (arg4);					\
		_sc_20 = (long) (arg5);					\
		__asm__("callsys # %0 %1 %2 %3 %4 %5 %6 %7"		\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0), "r"(_sc_16), "r"(_sc_17),		\
			  "r"(_sc_18), "1"(_sc_19), "r"(_sc_20)		\
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6)					 \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6)\
{									\
	long _sc_ret, _sc_err;						\
	{								\
		register long _sc_0 __asm__("$0");			\
		register long _sc_16 __asm__("$16");			\
		register long _sc_17 __asm__("$17");			\
		register long _sc_18 __asm__("$18");			\
		register long _sc_19 __asm__("$19");			\
		register long _sc_20 __asm__("$20");			\
		register long _sc_21 __asm__("$21");			\
									\
		_sc_0 = __NR_##name;					\
		_sc_16 = (long) (arg1);					\
		_sc_17 = (long) (arg2);					\
		_sc_18 = (long) (arg3);					\
		_sc_19 = (long) (arg4);					\
		_sc_20 = (long) (arg5);					\
		_sc_21 = (long) (arg6);					\
		__asm__("callsys # %0 %1 %2 %3 %4 %5 %6 %7 %8"		\
			: "=r"(_sc_0), "=r"(_sc_19)			\
			: "0"(_sc_0), "r"(_sc_16), "r"(_sc_17),		\
			  "r"(_sc_18), "1"(_sc_19), "r"(_sc_20), "r"(_sc_21) \
			: _syscall_clobbers);				\
		_sc_ret = _sc_0, _sc_err = _sc_19;			\
	}								\
	_syscall_return(type);						\
}

#endif /* __ASSEMBLER__ */
#endif /* _BITS_SYSCALLS_H */
