#ifndef _SYS_MOUNT_H
#define _SYS_MOUNT_H

#include <features.h>
#include <sys/ioctl.h>

__BEGIN_DECLS

#define BLKGETSIZE _IO(0x12,96)  /* return device size */

extern int      mount __P ((__const char* __specialfile,
                __const char* __dir,__const char* __filesystemype,
                unsigned long __rwflag,__const void *__data));

extern int      umount __P ((__const char* __specialfile));
                                        
                                        
__END_DECLS

#endif
