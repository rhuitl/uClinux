/* 
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <errno.h>
#include <stdio.h>
#include <mntent.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#if __GLIBC__ >= 2
#include <sys/mount.h>
#else
#include <linux/fs.h>
#endif

#ifdef EMBED
#include <getopt.h>
#endif

#include "io.h"
#include "misc.h"
#include "reiserfs_lib.h"
#include "../version.h"


#define print_usage_and_exit()\
 die ("Usage: %s  [-s[+|-]#[G|M|K]] [-fqv] device", argv[0])
 

/* reiserfs_resize.c */
extern struct buffer_head * g_sb_bh;

extern int opt_force;
extern int opt_verbose;
extern int opt_nowrite;
extern int opt_safe;

int expand_fs(struct super_block * s, unsigned long block_count_new);

/* fe.c */
int resize_fs_online(char * devname, unsigned long blocks);

/* do_shrink.c */
int shrink_fs(struct super_block * s, unsigned long blocks);
