/*
 * bootstd.h - uCbootloader system call library header file
 *
 * Copyright (c) 2006  Arcturus Networks Inc.
 *	by Oleksandr G Zhadan <www.ArcturusNetworks.com>      
 *
 * All rights reserved.
 *
 * This material is proprietary to Arcturus Networks Inc. and, in
 * addition to the above mentioned Copyright, may be subject to
 * protection under other intellectual property regimes, including
 * patents, trade secrets, designs and/or trademarks.
 *
 * Any use of this material for any purpose, except with an express
 * license from Arcturus Networks Inc. is strictly prohibited.
 *
 */

#ifndef _BSC_FUNC_H_
#define _BSC_FUNC_H_

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/ipc.h>
#include <asm/uCbootstrap.h>

/* FIXME: The next definition is a temporary thing and need to be changed. OZH */

#if BSC_MMU

#define KERNEL_BSC_IOCTL_SUPPORT 1
#define UCTRAP_DEVICE	"/dev/bios"

#else

//#if defined(SEMTIMEDOP)
//#define BSC_SEMAPHORE_SUPPORT	1
//#endif

#endif

#define MAX_ENVNAME_SIZE	31
#define MAX_ENVDATA_SIZE	1024
#define MAX_ENVPAIR_SIZE	1060 /* 31+1+1024+4 */

#define MAX_ENVNAME_SIZE_LONG	8
#define MAX_ENVDATA_SIZE_LONG	256
#define MAX_ENVPAIR_SIZE_LONG	265

/* bsc_reset function actions */
#define PGM_ERASE_FIRST 0x0001
#define PGM_RESET_AFTER 0x0002
#define PGM_EXEC_AFTER  0x0004
#define PGM_HALT_AFTER  0x0008
#define PGM_DEBUG       0x0010

extern int   bsc_getenv (char *, char *, int);
extern int   bsc_readenv (int, char *, int);
extern char *bsc_gethwaddr (int, char *);
extern char *bsc_getserialnum (char *);
extern int   bsc_eraseall(void);
extern int   bsc_reset (int);
extern int   bsc_setenv (char *);
extern int   bsc_setpmask (unsigned int);
extern int   bsc_version (void);
extern int   bsc_free (void);
extern int   bsc_gc (void);
extern int   bsc_printenv(FILE *out, char *str);
extern int   bsc_eraseenv(char *);

#if defined(BSC_SEMAPHORE_SUPPORT)
extern int   bsc_sem_open ( void );
extern int   bsc_sem_lock ( int semId );
extern void  bsc_sem_unlock ( int semId );
extern void  bsc_sem_delete(int sid);
#endif


/***************************** Flash/Ram loader structure ******/
/* an mnode points at 4k pages of data through an offset table */
#ifndef _memnode_struct_
#define _memnode_struct_
typedef struct _memnode {
  int len;
  int *offset;
} mnode_t;
#endif

typedef struct bsc_op {
    int		arg1;
    char 	*arg2;
    int		arg3;
    char	*arg4;
    } bsc_op_t;

#endif /* _BSC_FUNC_H_ */
