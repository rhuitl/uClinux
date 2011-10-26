/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */

#include "resize.h"


/* the front-end for kernel on-line resizer */
int resize_fs_online(char * devname, unsigned long blocks)
{
	static char buf[40];
	FILE * f;
	struct mntent * mnt;
	
	if ((f = setmntent (MOUNTED, "r")) == NULL)
		goto fail;

    while ((mnt = getmntent (f)) != NULL)
        if(strcmp(devname, mnt->mnt_fsname) == 0) {

			if (strcmp(mnt->mnt_type,"reiserfs")) 			
				die ("resize_reiserfs: can\'t resize fs other than reiserfs\n");
				
			sprintf(buf,"resize=%lu", blocks);

			if (mount(mnt->mnt_fsname, mnt->mnt_dir, mnt->mnt_type,
          			  (unsigned long) MS_REMOUNT, buf)) 
				die ("resize_reiserfs: remount failed: %s\n", strerror(errno));
			
			endmntent(f);
			return 0;
		}
fail:
   die ("resize_reiserfs: can't find mount entry\n");
   return 1;
}

