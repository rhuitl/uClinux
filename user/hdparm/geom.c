/*
 * Device geometry helpers for hdparm and friends.
 * Copyright (c) Mark Lord 2008
 *
 * You may use/distribute this freely, under the terms of either
 * (your choice) the GNU General Public License version 2,
 * or a BSD style license.
 */
#define _FILE_OFFSET_BITS 64
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>

#include "hdparm.h"

static int get_sector_count (int fd, __u64 *nsectors)
{
	int		err;
	unsigned int	nsects32 = 0;
	__u64		nbytes64 = 0;

	if (0 == sysfs_get_attr(fd, "size", "%llu", nsectors, NULL, 0))
		return 0;
#ifdef BLKGETSIZE64
	if (0 == ioctl(fd, BLKGETSIZE64, &nbytes64)) {	// returns bytes
		*nsectors = nbytes64 / 512;
		return 0;
	}
#endif
	err = ioctl(fd, BLKGETSIZE, &nsects32);	// returns sectors
	if (err == 0) {
		*nsectors = nsects32;
	} else {
		err = errno;
		perror(" BLKGETSIZE failed");
	}
	return err;
}

int get_dev_geometry (int fd, __u32 *cyls, __u32 *heads, __u32 *sects,
				__u64 *start_lba, __u64 *nsectors)
{
	static struct local_hd_geometry      g;
	static struct local_hd_big_geometry bg;
	int err = 0;

	if (nsectors) {
		err = get_sector_count(fd, nsectors);
		if (err)
			return err;
	}

	if (start_lba) {
		/*
		 * HDIO_GETGEO uses 32-bit fields on 32-bit architectures,
		 * so it cannot be relied upon for start_lba with very large drives >= 2TB.
		 */
		__u64 result;
		if (0 == sysfs_get_attr(fd, "start", "%llu", &result, NULL, 0)) {
			*start_lba = result;
			start_lba = NULL;
		}
	}

	if (cyls || heads || sects || start_lba) {
		if (!ioctl(fd, HDIO_GETGEO_BIG, &bg)) {
			if (cyls)	*cyls  = bg.cylinders;
			if (heads)	*heads = bg.heads;
			if (sects)	*sects = bg.sectors;
			if (start_lba)	*start_lba = bg.start;
		} else if (!ioctl(fd, HDIO_GETGEO, &g)) {
			if (cyls)	*cyls  = g.cylinders;
			if (heads)	*heads = g.heads;
			if (sects)	*sects = g.sectors;
			if (start_lba)	*start_lba = g.start;
		} else {
			err = errno;
			perror(" HDIO_GETGEO failed");
			return err;
		}
		/*
		 * On all (32 and 64 bit) systems, the cyls value is bit-limited.
		 * So try and correct it using other info we have at hand.
		 */
		if (nsectors && cyls && heads && sects) {
			__u64 hs  = (*heads) * (*sects);
			__u64 cyl = (*cyls);
			__u64 chs = cyl * hs;
			if (chs < (*nsectors))
				*cyls = (*nsectors) / hs;
		}
	}

	return 0;
}

static int find_dev_in_directory (dev_t dev, const char *dir, char *path, int verbose)
{
	DIR *dp;
	struct dirent *entry;
	unsigned int maj = major(dev), min = minor(dev);

	*path = '\0';
	if (!(dp = opendir(dir))) {
		int err = errno;
		if (verbose)
			perror(dir);
		return err;
	}
	while ((entry = readdir(dp)) != NULL) {
		if (entry->d_type == DT_UNKNOWN || entry->d_type == DT_BLK) {
			struct stat st;
			sprintf(path, "%s/%s", dir, entry->d_name);
			if (stat(path, &st)) {
				if (verbose)
					perror(path);
			} else if (S_ISBLK(st.st_mode)) {
				if (major(st.st_rdev) == maj && minor(st.st_rdev) == min) {
					closedir(dp);
					return 0;
				}
			}
		}
	}
	closedir(dp);
	*path = '\0';
	if (verbose)
		fprintf(stderr, "%d,%d: device not found in %s\n", major(dev), minor(dev), dir);
	return ENOENT;
}

int get_dev_t_geometry (dev_t dev, __u32 *cyls, __u32 *heads, __u32 *sects,
				__u64 *start_lba, __u64 *nsectors)
{
	char path[PATH_MAX];
	int fd, err;

	err = find_dev_in_directory (dev, "/dev", path, 1);
	if (err)
		return err;

	fd = open(path, O_RDONLY|O_NONBLOCK);
	if (fd == -1) {
		err = errno;
		perror(path);
		return err;
	}

	err = get_dev_geometry(fd, cyls, heads, sects, start_lba, nsectors);
	close(fd);
	return err;
}

