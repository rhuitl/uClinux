#ifdef _SYS_DIRENT_H
#error "Can't include both sys/dir.h and sys/dirent.h"
#define _SYS_DIR_H
#endif

#ifndef _SYS_DIR_H
#define _SYS_DIR_H

#include <dirent.h>

#define direct	dirent

#undef DIRSIZ
#define DIRSIZ(dp)	((sizeof (struct direct) - (MAXNAMLEN+1)) + \
			 (((dp)->d_namlen+1 + 3) &~ 3))

#endif
