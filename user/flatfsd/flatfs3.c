/*****************************************************************************/

/*
 *	flatfs3.c -- flat compressed FLASH file-system version 3.
 *
 *	Copyright (C) 1999-2006, Greg Ungerer (gerg@snapgear.com).
 *	Copyright (C) 2001-2002, SnapGear (www.snapgear.com)
 *	Copyright (C) 2005 CyberGuard Corporation (www.cyberguard.com)
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
#include <utime.h>
#include <assert.h>
#include <syslog.h>
#include <zlib.h>
#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
#include <openssl/aes.h>
#include <config/autoconf.h>
#define	SGTAG_MAIN
#include <../prop/flash/sgtag.h>
#endif

#include "flatfs.h"
#include "dev.h"
#include "ops.h"
#include "flatfs1.h"
#include "flatfs3.h"

/*****************************************************************************/

/*
 * Maximum path name size that we will support. This is completely arbitary.
 */
#define	MAXNAME	256

/*
 * General work buffer size (these are often allocated on the stack).
 */
#define BUF_SIZE 1024

/*
 * zlib meta-data. Keep track of compression/decompression.
 */
#define OUTPUT_SIZE 1024
#define INPUT_SIZE 1024

struct flatzfs_s {
	off_t		offset;
	z_stream	strm;
	unsigned char	*output;
	size_t		output_size;
	unsigned char	*input;
	size_t		input_size;
	int		write;
	int		read_initialised;
#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
	AES_KEY		aeskey;
#endif
};

struct flatzfs_s flatzfs;

/*
 * Keep track of the current highest tstamp value, and which partition
 * the last restore came from. Helps us when it comes time to save the
 * fs again.
 */
int numvalid = -1;
unsigned int numstamp;

/*****************************************************************************/

/*
 * Currently the code here supports the version 3 and version 4 formats.
 * It can read both types, it only ever writes version 4.
 */

static inline int flat3_validmagic(unsigned int m)
{
	return ((m == FLATFS_MAGIC_V3) || (m == FLATFS_MAGIC_V4));
}

/*****************************************************************************/

static int flatz_read_init(void)
{
	int res;
	if (!flatzfs.read_initialised) {
		res = inflateInit(&flatzfs.strm);

		if (res != Z_OK) {
			syslog(LOG_ERR, "Initialising decompression failed - %d\n", res);
			return res;
		}

		flatzfs.read_initialised = 1;
	}

	return Z_OK;
}

/*****************************************************************************/

#ifdef CONFIG_USER_FLATFSD_ENCRYPTED

#define	AES_KEY_SIZE	32

static int aes_key_set;
static unsigned char aes_key[AES_KEY_SIZE];

static unsigned char *flatz_getkey(void)
{
	if (aes_key_set == 0) {
		int fd;
		fd = open(FLASH_TAG_FILE, O_RDONLY);
		if (fd > 0) {
			struct sgtag *tag;
			lseek(fd, CONFIG_USER_FLASH_TAG_OFFSET, SEEK_SET);
			sgtag_load_file(fd, CONFIG_USER_FLASH_TAG_SIZE);
			close(fd);

			tag = sgtag_find(SGTAG_CRYPT_KEY);
			if (tag)
				memcpy(aes_key, SGTAG_DATA(tag), AES_KEY_SIZE);
		}
		aes_key_set = 1;
	}

	return &aes_key[0];
}

#endif

/*****************************************************************************/

static int flatz_open(const char *mode)
{
	int rc;

	bzero(&flatzfs, sizeof(flatzfs));
	
	if (*mode == 'w') {
		rc = deflateInit(&flatzfs.strm, Z_DEFAULT_COMPRESSION);
		if (rc != 0)
			return ERROR_CODE();

		flatzfs.write = 1;
		flatzfs.output_size = OUTPUT_SIZE;
		flatzfs.output = (unsigned char *)malloc(flatzfs.output_size);

		flatzfs.strm.next_out = flatzfs.output;
		flatzfs.strm.avail_out = flatzfs.output_size;

#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
		AES_set_encrypt_key(flatz_getkey(), AES_KEY_SIZE*8, &flatzfs.aeskey);
#endif

	} else {
		flatzfs.write = 0;
		flatzfs.input_size = INPUT_SIZE;
		flatzfs.input = (unsigned char *)malloc(flatzfs.input_size);
#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
		AES_set_decrypt_key(flatz_getkey(), AES_KEY_SIZE*8, &flatzfs.aeskey);
#endif
	}

	return 0;
}

/*****************************************************************************/

static int flatz_close(void)
{
	if (flatzfs.read_initialised)
		inflateEnd(&flatzfs.strm);
	flatzfs.read_initialised = 0;
	if (flatzfs.write)
		deflateEnd(&flatzfs.strm);
	flatzfs.write = 0;
	if (flatzfs.output)
		free(flatzfs.output);
	flatzfs.output = NULL;
	if (flatzfs.input)
		free(flatzfs.input);
	flatzfs.input = NULL;
	return 0;
}

/*****************************************************************************/

#ifdef CONFIG_USER_FLATFSD_ENCRYPTED

/*
 *	Encrypt the compression output buffer.
 *	The encryption is done in place in the output buffer.
 */

static int flatz_encrypt(int len)
{
	unsigned char tmp[AES_BLOCK_SIZE];
	unsigned char *sp;
	int i;

	sp = flatzfs.output;

	/* Whole number of AES_BLOCK_SIZE chunks, zero pad end */
	if (len != OUTPUT_SIZE) {
		memset(&sp[len], 0, (OUTPUT_SIZE - len));
		len = (len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
	}

	for (i = 0; (i < len); i += AES_BLOCK_SIZE) {
		AES_encrypt(sp, tmp, &flatzfs.aeskey);
		memcpy(sp, tmp, AES_BLOCK_SIZE);
		sp += AES_BLOCK_SIZE;
	}

	return len;
}

#endif

/*****************************************************************************/

static int flatz_finalise(int dowrite)
{
	int size, res;
	int rc = 0;

	for (;;) {
		res = deflate(&flatzfs.strm, Z_FINISH);

		size = OUTPUT_SIZE - flatzfs.strm.avail_out;
#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
		size = flatz_encrypt(size);
#endif
		if (dowrite && (rc = flat_dev_write(flatzfs.offset, flatzfs.output, size)) < 0) 
			return rc;
			
		flatzfs.offset += size;
		flatzfs.strm.next_out = flatzfs.output;
		flatzfs.strm.avail_out = flatzfs.output_size;

		if (res == Z_STREAM_END)
			break;
	}

	return 0;
}

/*****************************************************************************/

/*
 * Compressed data write.
 */

static int flatz_write(const void *buf, size_t len, int do_write)
{
	int res;
	int rc = 0;

	flatzfs.strm.next_in = (unsigned char *) buf;
	flatzfs.strm.avail_in = len;

	for (;;) {
		res = deflate(&flatzfs.strm, Z_NO_FLUSH);

		if (flatzfs.strm.avail_out == 0) {
#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
			flatz_encrypt(OUTPUT_SIZE);
#endif

			if (do_write && (rc = flat_dev_write(flatzfs.offset, flatzfs.output, flatzfs.output_size)) < 0) 
				return rc;
			
			flatzfs.offset += flatzfs.output_size;
			flatzfs.strm.next_out = flatzfs.output;
			flatzfs.strm.avail_out = flatzfs.output_size;
		} else {
			break;
		}
	}

	return 0;
}

/*****************************************************************************/

#ifdef CONFIG_USER_FLATFSD_ENCRYPTED

/*
 * Decrypt a block of data (this is before de-compressing).
 * The decyption is done in place in the read buffer.
 */

static int flatz_decrypt(int len)
{
	unsigned char tmp[AES_BLOCK_SIZE];
	unsigned char *sp;
	int i;

	sp = flatzfs.strm.next_in;

	/* Pad out to the end of the buffer, must have modulo AES_BLOCK_SIZE */
	if (len != INPUT_SIZE)
		memset(&sp[len], 0, (INPUT_SIZE - len));

	for (i = 0; (i < len); i += AES_BLOCK_SIZE) {
		AES_decrypt(sp, tmp, &flatzfs.aeskey);
		memcpy(sp, tmp, AES_BLOCK_SIZE);
		sp += AES_BLOCK_SIZE;
	}

	return len;
}

#endif

/*****************************************************************************/

/*
 * Just like flat_read, but reads from a compressed romfs thing.
 */

static int flatz_read(void *buf, size_t len)
{
	int res;
	int flush = Z_NO_FLUSH;

	if (len == 0)
		return 0;

	flatzfs.strm.avail_out = len;
	flatzfs.strm.next_out = buf;

	do {
		int bytes_read = 0;

		if (flatzfs.strm.avail_in == 0) {

			flatzfs.strm.next_in = flatzfs.input;
			flatzfs.strm.avail_in = 0;

			bytes_read = flat_read(flatzfs.strm.next_in,
				flatzfs.input_size);

#ifdef CONFIG_USER_FLATFSD_ENCRYPTED
			bytes_read = flatz_decrypt(bytes_read);
#endif

			if (bytes_read < flatzfs.input_size)
				flush = Z_FINISH;

			flatzfs.strm.avail_in = bytes_read;

			if ((res = flatz_read_init()) < 0)
				return res;
		}

		res = inflate(&flatzfs.strm, flush);

		if (res < 0 && (res != Z_BUF_ERROR || flatzfs.strm.avail_in == 0)) {
			syslog(LOG_INFO, "Result from reading flatfs3 - %d", res);
			return res;
		}

		if (res == Z_STREAM_END) {
			return len - flatzfs.strm.avail_out;
		}
	} while (flatzfs.strm.avail_out);

	return len;
}

/*****************************************************************************/

/*
 * Check for a valid partition in flash. We attempt to restore an fs
 * (with dowrite inactive ofcourse :-)  If it succeeds then we have at
 * least one good partition to use.
 *
 * Unfortunately this is probably not exactly what we want in the case of
 * running checkfs strait after doing a savefs. We would ideally like to
 * only check the partition we just wrote. But that is not simple to
 * determine here that is actually what we are trying to test for.
 */

int flat3_checkfs(void)
{
	int rc;
	/* Now, really check that it is valid */
	if ((rc = flat3_restorefs(3, 0)) < 0)
		return rc;
	return 0;
}

/*****************************************************************************/

/*
 * Read header at specific offset. If it is in someway invalid then return
 * an empty (zeroed out) header structure.
 */
static int flat3_gethdroffset(off_t off, struct flathdr3 *hp)
{
	memset(hp, 0, sizeof(*hp));
        if (flat_seek(off, SEEK_SET) != off)
                return ERROR_CODE();
	if (flat_read((void *) hp, sizeof(*hp)) != sizeof(*hp))
		return ERROR_CODE();
	if (! flat3_validmagic(hp->magic))
		return ERROR_CODE();
	return 0;
}

/*****************************************************************************/

/*
 * Find any valid header we can in the flash (from either of the 2
 * partitions).
 */

unsigned int flat3_gethdr(void)
{
	struct flathdr3 hdr;
	unsigned int psize;
	int rc;

	psize = flat_part_length();
	rc = flat3_gethdroffset(0, &hdr);
	if ((rc < 0) || (! flat3_validmagic(hdr.magic))) {
		rc = flat3_gethdroffset(psize, &hdr);
		if (rc < 0)
			hdr.magic = 0;
	}
	return hdr.magic;
}

/*****************************************************************************/

/*
 * The stored filename may have directory path components. Scan the filename
 * and build the directories as required.
 */

static int restoredirectory(char *dirname, struct flatent *ent, struct flatent2 *ent2, int dowrite)
{
	if (dowrite) {
		if (mkdir(dirname, (mode_t) ent2->mode) < 0)
			return ERROR_CODE();
		chown(dirname, (uid_t) ent2->uid, (gid_t) ent2->gid);
	}

	return 0;
}

/*****************************************************************************/

/*
 * Read our special flatfsd config file.
 */

static int restoredotconfig(char *filename, struct flatent *ent, struct flatent2 *ent2, int dowrite)
{
	char *confbuf;

	if (ent->filelen == 0) {
#ifndef HAS_RTC
		/* This file was not written correctly, so just ignore it */
		syslog(LOG_WARNING, "%s is zero length, ignoring", filename);
#endif
	} else if ((confbuf = malloc(ent->filelen)) == 0) {
		syslog(LOG_ERR, "Failed to allocate memory for %s -- ignoring it", filename);
	} else {
		if (flatz_read(confbuf, ent->filelen) != ent->filelen)
			return ERROR_CODE();
#ifndef HAS_RTC
		if (dowrite)
			parseconfig(confbuf);
#endif
		free(confbuf);
	}

	return 0;
}

/*****************************************************************************/

/*
 * Write out the contents of the file from the flash backing store to create
 * a regular file in the RAM filesystem.
 */

static int restorefile(char *filename, struct flatent *ent, struct flatent2 *ent2, int dowrite)
{
	unsigned char buf[BUF_SIZE];
	unsigned int size, n;
	int fdfile = -1;

	if (dowrite) {
		fdfile = open(filename, (O_WRONLY | O_TRUNC | O_CREAT), 0600);
		if (fdfile < 0)
			return ERROR_CODE();
	}

	for (size = ent->filelen; (size > 0); size -= n) {
		n = (size > sizeof(buf)) ? sizeof(buf) : size;
		if (flatz_read(&buf[0], n) != n)
			return ERROR_CODE();
		if (dowrite) {
			if (write(fdfile, &buf[0], n) != n)
				return ERROR_CODE();
		}
	}

	if (dowrite) {
		struct utimbuf tt;;
		fchmod(fdfile, (mode_t) (ent2->mode & 07777));
		fchown(fdfile, (uid_t) ent2->uid, (gid_t) ent2->gid);
		close(fdfile);
		tt.actime = ent2->atime;
		tt.modtime = ent2->mtime;
		utime(filename, &tt);
	}

	return 0;
}

/*****************************************************************************/

/*
 * Read the contents of a flat file-system and dump them out as regular files.
 * Takes the offset of the filesystem into the flash address space (this
 * is to allow support multiple filesystems in a single flash partition).
 */

static int flat3_restorefsoffset(off_t offset, int dowrite)
{
	struct flathdr3 hdr;
	struct flatent ent;
	struct flatent2 ent2;
	char filename[MAXNAME], padding[4];
	unsigned int n;
	int rc;

	memset(&ent2, 0, sizeof(ent2));

	if ((rc = flatz_open("r")) < 0)
		return rc;

	if (flat_seek(offset, SEEK_SET) != offset) {
		flatz_close();
		return ERROR_CODE();
	}
	if (flat_read(&hdr, sizeof(hdr)) != sizeof(hdr)) {
		flatz_close();
		return ERROR_CODE();
	}

	for (numfiles = 0, numbytes = 0; ; numfiles++) {
		/* Get the name of next file. */
		if ((rc = flatz_read((void *) &ent, sizeof(ent))) != sizeof(ent)) {
			flatz_close();
			return ERROR_CODE();
		}

		if (ent.filelen == FLATFS_EOF)
			break;

		n = ((ent.namelen + 3) & ~0x3);
		if (n > sizeof(filename)) {
			/*fprintf(stderr, "filename length is wrong\n");*/
			flatz_close();
			return ERROR_CODE();
		}

		if (flatz_read((void *) &filename[0], n) != n) {
			flatz_close();
			return ERROR_CODE();
		}

		if (hdr.magic == FLATFS_MAGIC_V3) {
			if (flatz_read((void *) &ent2.mode, sizeof(ent2.mode)) != sizeof(ent2.mode)) {
				flatz_close();
				return ERROR_CODE();
			}
		} else /* FLATFS_MAGIC_V4 */ {
			if (flatz_read(&ent2, sizeof(ent2)) != sizeof(ent2)) {
				flatz_close();
				return ERROR_CODE();
			}

		}

		/* fprintf(stderr, "filename - %s, mode - %o, namelen - %d\n",
				filename, ent2.mode, ent.namelen); */

		if (S_ISDIR(ent2.mode)) {
			rc = restoredirectory(filename, &ent, &ent2, dowrite);
		} else if (strcmp(filename, FLATFSD_CONFIG) == 0) {
			rc = restoredotconfig(filename, &ent, &ent2, dowrite);
		} else {
			rc = restorefile(filename, &ent, &ent2, dowrite);
		}
		if (rc) {
			flatz_close();
			return rc;
		}

		/* Read alignment padding */
		n = ((ent.filelen + 3) & ~0x3) - ent.filelen;
		if (flatz_read(&padding[0], n) != n) {
			flatz_close();
			return ERROR_CODE();
		}

		numbytes += ent.filelen;
	}

	flatz_close();

	return 0;
}

/*****************************************************************************/

/*
 * Helper functions to deal with tstamp generation and comparison.
 */

/* Returns the next tstamp in sequence */
static inline unsigned next_tstamp(unsigned tstamp)
{
	return (tstamp + 1) & 0xffff;
}

/* Returns true if tstamp tstamp0 is higher in sequence than tstamp1 */
static inline int tstamp_gt(unsigned tstamp0, unsigned tstamp1)
{
	return (short)(tstamp0 - tstamp1) > 0;
}


/* Return the checksum value to write out based on a given tstamp */
#define CHKSUM_VALID	0x80000000
static inline unsigned tstamp_chksum(unsigned tstamp)
{
	return ((~tstamp) & 0xffff) | CHKSUM_VALID;
}

/*
 * Returns true if we will need to write the configuration twice,
 * to wrap tstamp on the other partition.  This ensures that the
 * correct configuration will be read if we roll back to another 
 * non chksum-aware firmware version.
 */
static inline int need_rewrite(unsigned previous_tstamp)
{
	return previous_tstamp >= 0xffff;
}

/*****************************************************************************/

/*
 * Given two headers, return which one is the "oldest" (should be
 * overwritten first), taking into account header/checksum validity
 * and tstamp wrapping.
 *
 * Returns 1 if hdr1 is "older" than hdr0, 0 otherwise.
 */

static int oldest_header(struct flathdr3 *hdr1, struct flathdr3 *hdr0)
{
	unsigned stamp1, stamp0;

	/* Partition without magic is invalid */
	if (! flat3_validmagic(hdr0->magic))
		return 0;
	if (! flat3_validmagic(hdr1->magic))
		return 1;

	/* Partition with tstamp of 0xffffffff indicates that 
	 * the previous write was incomplete. */
	if (hdr0->tstamp == 0xffffffff)
		return 0;
	if (hdr1->tstamp == 0xffffffff)
		return 1;

	/* Old style comparison for checksum-less flash header */
	if (hdr0->chksum == 0 && hdr1->chksum == 0)
		return (hdr0->tstamp > hdr1->tstamp) ? 1 : 0;

	/* Invalidiate tstamp if checksum is present but invalid. */
	stamp1 = hdr1->tstamp;
	stamp0 = hdr0->tstamp;
	if (hdr0->chksum != 0 && hdr0->chksum != tstamp_chksum(stamp0))
		stamp0 = stamp1 - 1;
	else if (hdr1->chksum != 0 && hdr1->chksum != tstamp_chksum(stamp1))
		stamp1 = stamp0 - 1;

	/* If stamp0 is higher in sequence than stamp1 then partition1 is older */
	return tstamp_gt(stamp0, stamp1) ? 1 : 0;
}

/*****************************************************************************/

/*
 * Given two headers, return which one is the "newest" (was written
 * last and most likely to have a valid configuration), taking into
 * account header/checksum validity and tstamp wrapping.
 *
 * Returns 1 if hdr1 is "newer" than hdr0, 0 otherwise.
 */

static inline int newest_header(struct flathdr3 *hdr1, struct flathdr3 *hdr0)
{
	return oldest_header(hdr1, hdr0) ? 0 : 1;
}

/*****************************************************************************/

/*
 * Restore the flat filesystem contents with the most up-to-date config
 * that can be found in the flash parition. For partitions with 2 images
 * we pick the most recent. If 'dowrite' is zero then we don't actually
 * restore the files, merely check that the save fs is valid.
 */

int flat3_restorefs(int version, int dowrite)
{
	struct flathdr3 hdr[FLAT_NUM_PARTITIONS];
	unsigned int off, psize;
	int part, nrparts, rc;

	part = 0;

	/* Figure out how many partitions we can have */
	nrparts = FLAT_NUM_PARTITIONS;
	psize = flat_dev_length();
	if ((psize / flat_dev_erase_length()) <= 1)
		nrparts = 1;
	else
		psize = flat_part_length();

	/* Get base header, and see how many partitions we have */
	rc = flat3_gethdroffset(0, &hdr[0]);
	if (! flat3_validmagic(hdr[0].magic))
		memset(&hdr[0], 0, sizeof(hdr[0]));

	if ((hdr[0].nrparts == 2) || (nrparts == 2)) {
		/* Get other header, if not valid then use base header */
		if ((rc = flat3_gethdroffset(psize, &hdr[1])) != 0) {
			memset(&hdr[1], 0, sizeof(hdr[0]));
			goto dobase;
		}

		/* Use which ever is most recent */
		part = newest_header(&hdr[1], &hdr[0]);

		off = (part) ? psize : 0;

		if ((rc = flat3_restorefsoffset(off, dowrite)) >= 0) {
			numvalid = part;
			numstamp = hdr[part].tstamp;
			if (dowrite) {
				logd("read-partition", "%d, tstamp=%d",
					part, hdr[part].tstamp);
				syslog(LOG_INFO, "restore fs- from partition "
					"%d, tstamp=%d", part, numstamp);
			}
			return rc;
		}

		/*
		 * I am adding a logd message so we catch this in the flash
		 * log. It would not normally happen, so if it does we should
		 * know about it.
		 */
		if (dowrite)
			logd("message",
				"restore partition %d failed, tstamp=%d",
				part, hdr[part].tstamp);

		/* Falling through to other partition */
		part = (part) ? 0 : 1;
	}

dobase:
	if (! flat3_validmagic(hdr[part].magic))
		return ERROR_CODE();

	off = (part) ? psize : 0;
	rc = flat3_restorefsoffset(off, dowrite);
	numvalid = part;
	numstamp = hdr[part].tstamp;
	if (dowrite) {
		logd("read-partition", "%d, tstamp=%d", part, hdr[part].tstamp);
		syslog(LOG_INFO, "restore fs+ from partition %d, tstamp=%d",
			part, numstamp);
	}
	return rc;
}

/*****************************************************************************/

static int writefile(char *name, unsigned int *ptotal, int dowrite)
{
	char buf[BUF_SIZE];
	struct flatent ent;
	struct flatent2 ent2;
	struct stat st;
	unsigned int size;
	int fdfile, zero = 0;
	int n, written;

	/*
	 * Write file entry into flat fs. Names and file contents are
	 * aligned on long word boundaries. They are padded to that length
	 * with zeros.
	 */
	if (stat(name, &st) < 0)
		return ERROR_CODE();
	if (! S_ISREG(st.st_mode))
		st.st_size = 0;

	size = strlen(name) + 1;
	if (size > MAXNAME) {
		numdropped++;
		return ERROR_CODE();
	}

	ent.namelen = size;
	ent.filelen = st.st_size;
	if (flatz_write(&ent, sizeof(ent), dowrite) < 0)
		return ERROR_CODE();

	/* Write file name out, with padding to align */
	if (flatz_write(name, size, dowrite) < 0)
		return ERROR_CODE();
	size = ((size + 3) & ~0x3) - size;
	if (flatz_write(&zero, size, dowrite) < 0)
		return ERROR_CODE();

	/* Write out the permissions, ownership, etc */
	ent2.length = sizeof(ent2);
	ent2.mode = st.st_mode;
	ent2.uid = st.st_uid;
	ent2.gid = st.st_gid;
	ent2.atime = st.st_atime;
	ent2.mtime = st.st_mtime;
	if (flatz_write(&ent2, sizeof(ent2), dowrite) < 0)
		return ERROR_CODE();

	/* If not a regular file then we are done here */
	if (! S_ISREG(st.st_mode))
		return 0;

	/* Write the contents of the file. */
	size = st.st_size;

	written = 0;

	if (size > 0) {
		if ((fdfile = open(name, O_RDONLY)) < 0)
			return ERROR_CODE();
		while (size > written) {
			int bytes_read;
			n = ((size - written) > sizeof(buf)) ? sizeof(buf) : (size - written);
			if ((bytes_read = read(fdfile, buf, n)) != n) {
				/* Somebody must have trunced the file. */
				syslog(LOG_WARNING, "File %s was shorter than "
					"expected.", name);
				if (bytes_read <= 0)
					break;
			}
			if (flatz_write(buf, bytes_read, dowrite) < 0) {
				close(fdfile);
				return ERROR_CODE();
			}
			written += bytes_read;
		}
		if (lseek(fdfile, 0, SEEK_END) != written) {
			/* 
			 * Log the file being longer than expected.
			 * We can't write more than expected because the size
			 * is already written.
			 */
			syslog(LOG_WARNING, "File %s was longer than expected.", name);
		}
		close(fdfile);

		/* Pad to align */
		written = ((st.st_size + 3) & ~0x3)- st.st_size;
		if (flatz_write(&zero, written, dowrite) < 0)
			return ERROR_CODE();
	}

	numfiles++;

	return 0;
}

/*****************************************************************************/

static int writedirectory(char *path, DIR *dirp, unsigned int *ptotal, int dowrite)
{
	char filename[MAXNAME];
	struct stat st;
	struct dirent *dp;
	DIR *subdirp;
	int pathlen, rc;

	pathlen = strlen(path);

	while ((dp = readdir(dirp)) != NULL) {

		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0) ||
		    (strcmp(dp->d_name, FLATFSD_CONFIG) == 0))
			continue;

		if ((pathlen + strlen(dp->d_name) + 2) > MAXNAME) {
			syslog(LOG_ERR, "dropping long name (max %d) %s/%s",
				MAXNAME, path, dp->d_name);
			continue;
		}

		sprintf(filename, "%s%s%s", path,
			(path[0] == '\0') ? "" : "/", dp->d_name);

		if (stat(filename, &st) < 0)
			return ERROR_CODE();

		rc = writefile(filename, ptotal, dowrite);
		if (rc < 0) {
			syslog(LOG_ERR, "Failed to write write file %s "
				"(%d): %m %d", filename, rc, errno);
		}

		if (S_ISDIR(st.st_mode)) {
			if ((subdirp = opendir(filename)) == NULL)
				return ERROR_CODE();
			rc = writedirectory(filename, subdirp, ptotal, dowrite);
			closedir(subdirp);
			if (rc)
				return rc;
			continue;
		}
	}

	return 0;
}

/*****************************************************************************/

/*
 * Writes out the contents of all files. Does not actually do the write
 * if 'dowrite' is not set. In this case, it just checks to see that the
 * config will fit. The total length of data written (or simulated) is
 * stored in *total. Does not remove .flatfsd
 *
 * Note that if the flash has been erased, aborting early will just lose
 * data. So we try to work around problems as much as possible.
 *
 * Returns 0 if OK, or < 0 if error.
 */

static int flat3_savefsoffset(int dowrite, off_t off, size_t len, int nrparts, unsigned int *total)
{
	struct flathdr3 hdr;
	struct flatent ent;
	DIR *dirp;
	int rc, ret = 0;

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat3_savefsoffset(dowrite=%d)", dowrite);
#endif

	if (dowrite) {
		/* Lets erase the relevant flash segments */
		if ((rc = flat_dev_erase(off, len)) < 0)
			return rc;
	}

	/* Write out contents of all files, skip over header */
	numfiles = 0;
	numbytes = 0;
	numdropped = 0;
	*total = sizeof(hdr);

	if ((rc = flatz_open("w")) < 0) {
		syslog(LOG_ERR, "Couldn't init compression engine\n");
		return rc;
	}

	flatzfs.offset = off + sizeof(hdr);

#ifndef HAS_RTC
	rc = writefile(FLATFSD_CONFIG, total, dowrite);
	if ((rc < 0) && !ret)
		ret = rc;
#endif

	/* Scan directory */
	if ((dirp = opendir(".")) == NULL) {
		rc = ERROR_CODE();
		if ((rc < 0) && !ret)
			ret = rc;
		flatz_close();
		/* Really nothing we can do at this point */
		return ret;
	}

	writedirectory("", dirp, total, dowrite);
	closedir(dirp);

	/* Write the terminating entry */
	ent.namelen = FLATFS_EOF;
	ent.filelen = FLATFS_EOF;
	rc = flatz_write(&ent, sizeof(ent), dowrite);
	if (rc < 0 && !ret)
		ret = rc;

	flatz_finalise(dowrite);

	*total += flatzfs.strm.total_out;

	if (dowrite) {
		/* Get next tstamp in sequence */
		numstamp = next_tstamp(numstamp);

		/* Construct header */
		hdr.magic = FLATFS_MAGIC_V4;
		hdr.chksum = tstamp_chksum(numstamp);
		hdr.nrparts = nrparts;
		hdr.tstamp = numstamp;

		rc = flat_dev_write(off, &hdr, sizeof(hdr));
		if ((rc < 0) && !ret)
			ret = rc;
	}

#ifdef DEBUG
	syslog(LOG_DEBUG, "flat3_savefsoffset(): returning ret=%d, total=%u",
		ret, *total);
#endif

	flatz_close();
	return ret;
}

/*****************************************************************************/

/*
 * Write out the filesystem to flash/disk. If we store 2 parititions then
 * we need to figure out which one to write too.  Use the flatfs headers
 * to determine the oldest image and replace it.
 */

static int _flat3_savefs(int dowrite, unsigned int *total, int rewriting)
{
	struct flathdr3 hdr[FLAT_NUM_PARTITIONS];
	unsigned int off, size, psize;
	int nrparts, part, rc, rewrite = 0;

	part = 0;
	numvalid = -1;
	numstamp = 0;

	/* Figure out how many partitions we can have */
	nrparts = FLAT_NUM_PARTITIONS;
	size = psize = flat_dev_length();
	if ((size / flat_dev_erase_length()) <= 1)
		nrparts = 1;

	/* Figure out which partition to use */
	if (nrparts > 1) {
		psize = flat_part_length();
		flat3_gethdroffset(0, &hdr[0]);
		flat3_gethdroffset(psize, &hdr[1]);

		/* Choose a partition */
		part = oldest_header(&hdr[1], &hdr[0]);

		/* Set highest current tstamp */
		if (part == 0)
			numstamp = hdr[1].tstamp;
		else
			numstamp = hdr[0].tstamp;

		/* Check if tstamp will wrap and we need to write twice */
		rewrite = need_rewrite(numstamp);
	}

	off = (part) ? psize : 0;
	if (dowrite) {
		logd("write-partition", "%d, tstamp=%d",
			part, next_tstamp(numstamp));
		syslog(LOG_INFO, "saving fs to partition %d, tstamp=%d\n",
			part, next_tstamp(numstamp));
	}
	
	rc = flat3_savefsoffset(dowrite, off, psize, nrparts, total);
	if (rc < 0 || rewriting)
		return rc;

	/* Write the configuration to the other parititon if tstamp wrapped */
	if (dowrite && rewrite && (rc = flat3_restorefsoffset(off, 0)) >= 0) {
		logd("message", "rewriting fs for backwards compatibility");
		syslog(LOG_INFO, "rewriting fs for backwards compatibility\n");
		rc = _flat3_savefs(dowrite, total, 1);
	}
	return rc;
}

int flat3_savefs(int dowrite, unsigned int *total)
{
	return _flat3_savefs(dowrite, total, 0);
}

/*****************************************************************************/
