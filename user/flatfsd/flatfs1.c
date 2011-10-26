/*****************************************************************************/

/*
 *	flatfs1.c -- simple flat FLASH file-system version 1 and 2.
 *
 *	This code is capable of reading version 1 and 2 flat files,
 *	it only ever writes version 2 files (the difference is that
 *	version 2 files also carry file mode attributes).
 *
 *	Copyright (C) 1999, Greg Ungerer (gerg@snapgear.com).
 *	Copyright (C) 2001-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <syslog.h>

#include <config/autoconf.h>
#include "flatfs.h"
#include "dev.h"
#include "ops.h"
#include "flatfs1.h"

/*****************************************************************************/

/*
 * DON'T CHANGE THIS!!!
 * It is required because of the broken way we calculate checksums.
 */
#define BUF_SIZE 1024

/*****************************************************************************/

/*
 * Return the contents of the header.
 */

unsigned int flat1_gethdr(void)
{
	struct flathdr1 hdr;

	if (flat_seek(0L, SEEK_SET) != 0L)
		return ERROR_CODE();
	if (flat_read(&hdr, sizeof(hdr)) != sizeof(hdr))
		return ERROR_CODE();
        return hdr.magic;
}

/*****************************************************************************/

/*
 * Check the magics and checksum of the existing in flash flatfs
 * and log any issues accordingly.
 */

int flat1_checkfs(void)
{
	struct flathdr1 hdr;
	unsigned int len, size, sum;
	unsigned char buf[BUF_SIZE];
	unsigned int n = 0;

	if (flat_seek(0L, SEEK_SET) != 0L)
		return ERROR_CODE();

	/* Check that header is a valid version 1/2 header */
	if (flat_read(&hdr, sizeof(hdr)) != sizeof(hdr))
		return ERROR_CODE();

	if ((hdr.magic != FLATFS_MAGIC) && (hdr.magic != FLATFS_MAGIC_V2))
		return ERROR_CODE();

	len = flat_dev_length();

	/* XXX - mn
	 * We calculate the checksum wrongly here.
	 *
	 * The trick to the bug is that size != position in file,  since the
	 * first time through we read size==sizeof(hdr),  but increment size by
	 * sizeof(buf).
	 *
	 * Because sizeof(hdr) == 8 and sizeof(buf) == 1024,  we end up not
	 * including the last 1008 bytes, since we start reading 1024 bytes
	 * chunks from position 16.
	 */
	for (sum = 0, size = sizeof(hdr); (size < len); size += sizeof(buf)) {
		n = (size > sizeof(buf)) ? sizeof(buf) :  size;
		if (flat_read(&buf[0], n) != n)
			return ERROR_CODE();
		sum += chksum(&buf[0], n);
	}

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat_checkfs() calculated checksum over %d "
		"bytes = %u", len, sum);
#endif

	if (sum != hdr.chksum) {
		syslog(LOG_ERR, "bad header checksum");
		return ERROR_CODE();
	}

	return 0;
}

/*****************************************************************************/

/*
 * Read the contents of a flat file-system and dump them out as regular files.
 */

int flat1_restorefs(int version, int dowrite)
{
	unsigned int size, n = 0;
	struct flatent ent;
	char filename[128];
	unsigned char buf[BUF_SIZE];
	char *confbuf;
	mode_t mode;
	int fdfile, rc;

	if ((rc = flat1_checkfs()) != 0)
		return rc;

	/*
	 * Get back to the real data we want.
	 */
	if (flat_seek(sizeof(struct flathdr1), SEEK_SET) != sizeof(struct flathdr1))
		return ERROR_CODE();

	for (numfiles = 0, numbytes = 0; ; numfiles++) {
		/* Get the name of next file. */
		if (flat_read(&ent, sizeof(ent)) != sizeof(ent))
			return ERROR_CODE();

		if (ent.filelen == FLATFS_EOF)
			break;

		n = ((ent.namelen + 3) & ~0x3);
		if (n > sizeof(filename))
			return ERROR_CODE();

		if (flat_read(&filename[0], n) != n)
			return ERROR_CODE();

		if (version >= 2) {
			if (flat_read(&mode, sizeof(mode)) != sizeof(mode)) {
				flat_close(1, 0);
				return ERROR_CODE();
			}
		} else {
			mode = 0644;
		}

		if (strcmp(filename, FLATFSD_CONFIG) == 0) {
			/* Read our special flatfsd config file into memory */
			if (ent.filelen == 0) {
#ifndef HAS_RTC
				/* This file was not written correctly, so just ignore it */
				syslog(LOG_WARNING, "%s is zero length, ignoring", filename);
#endif
			}
			else if ((confbuf = malloc(ent.filelen)) == 0) {
				syslog(LOG_ERR, "Failed to allocate memory for %s -- ignoring it", filename);
			}
			else {
				if (flat_read(confbuf, ent.filelen) != ent.filelen) {
					free(confbuf);
					return ERROR_CODE();
				}

#ifndef HAS_RTC
				parseconfig(confbuf);
#endif
				free(confbuf);
			}
		} else {
			/* Write contents of file out for real. */
			fdfile = open(filename, (O_WRONLY | O_TRUNC | O_CREAT), mode);
			if (fdfile < 0)
				return ERROR_CODE();
			
			for (size = ent.filelen; (size > 0); size -= n) {
				n = (size > sizeof(buf)) ? sizeof(buf) : size;
				if (flat_read(&buf[0], n) != n)
					return ERROR_CODE();
				if (write(fdfile, (void *) &buf[0], n) != n)
					return ERROR_CODE();
			}

			close(fdfile);
		}

		/* Read alignment padding */
		n = ((ent.filelen + 3) & ~0x3) - ent.filelen;
		if (flat_read(&buf[0], n) != n)
			return ERROR_CODE();

		numbytes += ent.filelen;
	}

	return 0;
}

/*****************************************************************************/

static int writefile(char *name, unsigned int *ptotal, int dowrite)
{
	struct flatent ent;
	struct stat st;
	unsigned int size;
	int fdfile, zero = 0;
	mode_t mode;
	char buf[BUF_SIZE];
	int n, written;

	/*
	 * Write file entry into flat fs. Names and file
	 * contents are aligned on long word boundaries.
	 * They are padded to that length with zeros.
	 */
	if (stat(name, &st) < 0)
		return ERROR_CODE();

	size = strlen(name) + 1;
	if (size > 128) {
		numdropped++;
		return ERROR_CODE();
	}

	ent.namelen = size;
	ent.filelen = st.st_size;
	if (dowrite && flat_write(*ptotal, &ent, sizeof(ent)) < 0)
		return ERROR_CODE();
	*ptotal += sizeof(ent);

	/* Write file name out, with padding to align */
	if (dowrite && flat_write(*ptotal, name, size) < 0)
		return ERROR_CODE();
	*ptotal += size;
	size = ((size + 3) & ~0x3) - size;
	if (dowrite && flat_write(*ptotal, &zero, size) < 0)
		return ERROR_CODE();
	*ptotal += size;

	/* Write out the permissions */
	mode = (mode_t) st.st_mode;
	size = sizeof(mode);
	if (dowrite && flat_write(*ptotal, &mode, size) < 0)
		return ERROR_CODE();
	*ptotal += size;

	/* Write the contents of the file. */
	size = st.st_size;

	written = 0;

	if (size > 0) {
		if (dowrite) {
			if ((fdfile = open(name, O_RDONLY)) < 0)
				return ERROR_CODE();
			while (size>written) {
				int bytes_read;
				n = ((size-written) > sizeof(buf))?sizeof(buf):(size-written);
				if ((bytes_read = read(fdfile, buf, n)) != n) {
					/* Somebody must have trunced the file - Log it. */
					syslog(LOG_WARNING, "File %s was shorter than expected.",
						name);
					if (bytes_read <= 0)
						break;
				}
				if (dowrite && flat_write(*ptotal, buf, bytes_read) < 0) {
					close(fdfile);
					return (ERROR_CODE());
				}
				*ptotal += bytes_read;
				written += bytes_read;
			}
			if (lseek(fdfile, 0, SEEK_END) != written) {
				/* 
				 * Log the file being longer than expected.
				 * We can't write more than expected because
				 * the size is already written.
				 */
				syslog(LOG_WARNING, "File %s was longer than expected.", name);
			}
			close(fdfile);
		} else {
			*ptotal += st.st_size;
		}

		/* Pad to align */
		written = ((st.st_size + 3) & ~0x3) - st.st_size;
		if (dowrite && flat_write(*ptotal, &zero, written) < 0)
			return ERROR_CODE();
		*ptotal += written;
	}

	numfiles++;
	numbytes += ent.filelen;

	return 0;
}

/*****************************************************************************/

/*
 * Writes out the contents of all files.
 * Does not actually do the write if 'dowrite'
 * is not set. In this case, it just checks
 * to see that the config will fit.
 * The total length of data written (or simulated) is stored
 * in *total.
 * Does not remove .flatfsd
 *
 * Note that if the flash has been erased, aborting
 * early will just lose data. So we try to work around
 * problems as much as possible.
 *
 * Returns 0 if OK, or < 0 if error.
 */
int flat1_savefs(int dowrite, unsigned *total)
{
	struct flathdr1 hdr;
	struct flatent ent;
	struct dirent *dp;
	DIR *dirp;
	int rc, ret = 0;

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat1_savefs(dowrite=%d)", dowrite);
#endif

	/* Lets go, erase the flash first */
	if ((rc = flat_erase()) < 0)
		return rc;

	/* Write out contents of all files, skip over header */
	numfiles = 0;
	numbytes = 0;
	numdropped = 0;
	*total = sizeof(hdr);

#ifndef HAS_RTC
	rc = writefile(FLATFSD_CONFIG, total, dowrite);
	if (rc < 0 && !ret)
		ret = rc;
#endif

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL) {
		rc = ERROR_CODE();
		if (rc < 0 && !ret)
			ret = rc;
		/* Really nothing we can do at this point */
		return ret;
	}

	while ((dp = readdir(dirp)) != NULL) {

		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0) ||
		    (strcmp(dp->d_name, FLATFSD_CONFIG) == 0))
			continue;

		rc = writefile(dp->d_name, total, dowrite);
		if (rc < 0) {
			syslog(LOG_ERR, "Failed to write write file %s (%d): %m %d",
				dp->d_name, rc, errno);
			if (!ret)
				ret = rc;
		}
	}
	closedir(dirp);

	/* Write the terminating entry */
	if (dowrite) {
		ent.namelen = FLATFS_EOF;
		ent.filelen = FLATFS_EOF;
		rc = flat_write(*total, &ent, sizeof(ent));
		if (rc < 0 && !ret)
			ret = rc;
	}

	*total += sizeof(ent);

#ifdef USING_MTD_DEVICE
	/*
	 * We need to account for the fact that we checksum the entire device,
	 * not just the data we wrote. On MTD devices, this data is 0xFF.
	 */
	{
		int checksum_len = flat_dev_length() - (BUF_SIZE - (sizeof(struct flathdr1) * 2));

		flat_sum += 0xFFu * (checksum_len - *total);

#ifdef DEBUG
		syslog(LOG_DEBUG, "flat_savefs(): added %d 0xFF bytes to "
			"checksum -> flat_sum=%u",
			checksum_len - *total, flat_sum);
#endif
	}
#endif

	if (dowrite) {
		/* Construct header */
		hdr.magic = FLATFS_MAGIC_V2;
		hdr.chksum = flat_sum;

#ifdef DEBUG
		syslog(LOG_DEBUG, "flat_savefs(): final checksum=%u, total=%d",
			flat_sum, *total);
#endif

		rc = flat_write(0L, &hdr, sizeof(hdr));
		if (rc < 0 && !ret)
			ret = rc;
	}

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat_savefs() returning ret=%d, total=%u", ret, *total);
#endif

	return ret;
}

/*****************************************************************************/
