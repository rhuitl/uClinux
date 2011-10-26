
/* This has never been tested.  A first pass for mawk1.2
   based on V7.h that worked on mawk1.1
*/

#ifndef   CONFIG_H
#define   CONFIG_H		1

#define				V7


#define   NO_VOID_PTR		1
#define   NO_STRTOD             1
#define   NO_FMOD               1
#define   NO_MATHERR		1
#define   NO_FCNTL_H		1
#define   NO_VFPRINTF		1
#define   NO_STRCHR		1


#define   O_RDONLY		0
#define   O_WRONLY		1
#define   O_RDWR		2


#ifdef XNX23A
/* convert double to Boolean.  This is a bug work-around for
   XENIX-68K 2.3A, where logical test of double doesn't work.  This
   macro NG for register double. */
#define   D2BOOL(x)	(*((long *) &(x)))
#define   SW_FP_CHECK	1
#define   STDC_MATHERR  1
#endif

#define HAVE_REAL_PIPES 1
#endif  /* CONFIG_H */
