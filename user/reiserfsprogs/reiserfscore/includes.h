/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <time.h>
#include "io.h"
#include "misc.h"
#include "reiserfs_lib.h"
