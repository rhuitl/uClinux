/****************************************************************************/

/*
 *	blkmem.c (c) 2003 SnapGear (www.snapgear.com)
 *
 *	Implements flatfs access to a block device
 */

/****************************************************************************/

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <linux/blkmem.h>

#include "flatfs.h"
#include "dev.h"

/****************************************************************************/

struct flatinfo_s {
	int fd;
	size_t len;          /* total length, in bytes */
	size_t block_size;   /* device block size */
	char *buf;           /* buffer used for writing */
	int writing;         /* opened for writing? */
};

static struct flatinfo_s flatinfo = { fd: -1 };

/****************************************************************************/

int flat_dev_open(const char *flatfs, const char *mode)
{
	int open_mode;
	assert(flatinfo.fd == -1);

	flatinfo.writing = (*mode == 'w');
	open_mode = flatinfo.writing ? O_WRONLY : O_RDONLY;

	/* Open and get the size of the block device */
	if ((flatinfo.fd = open(flatfs, open_mode)) < 0) {
		flatinfo.fd = -1;
#ifdef DEBUG
		syslog(LOG_DEBUG, "open(%s, %d) = %d: %m", flatfs, open_mode, flatinfo.fd);
#endif
		return ERROR_CODE();
	}

	if (ioctl(flatinfo.fd, BMGETSIZEB, &flatinfo.len) < 0) {
		close(flatinfo.fd);
		flatinfo.fd = -1;
		return ERROR_CODE();
	}

	if (ioctl(flatinfo.fd, BMSGSIZE, &flatinfo.block_size) < 0) {
		close(flatinfo.fd);
		flatinfo.fd = -1;
		return ERROR_CODE();
	}

	return 0;
}

/****************************************************************************/

int flat_dev_length(void)
{
	assert(flatinfo.fd != -1);
	return flatinfo.len;
}

/****************************************************************************/

int flat_dev_erase_length(void)
{
	assert(flatinfo.fd != -1);
	return flatinfo.block_size;
}

/****************************************************************************/

/*
 *	This erase functions does not currnetly support paritial erase.
 *	It erases the entire flash region.
 */

int flat_dev_erase(off_t offset, size_t len)
{
	assert(flatinfo.fd != -1);
	assert(flatinfo.writing);

	if (!flatinfo.buf) {
		flatinfo.buf = malloc(flatinfo.len);
		if (!flatinfo.buf)
			return ERROR_CODE();
	}
	memset(flatinfo.buf, 0, flatinfo.len);
	return 0;
}

/****************************************************************************/

int flat_dev_write(off_t offset, const void *buf, size_t len)
{
	assert(flatinfo.fd != -1);
	assert(flatinfo.writing);
	/* Check to see if we erased first */
	assert(flatinfo.buf);

	if (offset + len > flatinfo.len)
		return ERROR_CODE();
	memcpy(&flatinfo.buf[offset], buf, len);
	return len;
}

/****************************************************************************/

int flat_dev_read(void *buf, size_t len)
{
	assert(flatinfo.fd != -1);
	assert(!flatinfo.writing);
	return read(flatinfo.fd, buf, len);
}

/****************************************************************************/

off_t flat_dev_seek(off_t offset, int whence)
{
	assert(flatinfo.fd != -1);
	return lseek(flatinfo.fd, offset, whence);
}

/****************************************************************************/

int flat_dev_close(int abort, off_t written)
{
	int rc = 0;
	(void)written;

	assert(flatinfo.fd != -1);

	if (!abort && flatinfo.writing && flatinfo.buf) {
		int pos;

		for (pos = flatinfo.len - flatinfo.block_size; pos >= 0; pos -= flatinfo.block_size) {
			if (ioctl(flatinfo.fd, BMSERASE, pos) < 0) {
				rc = ERROR_CODE();
				break;
			}
		}

		/* Write everything out */
		if (write(flatinfo.fd, flatinfo.buf, flatinfo.len) != flatinfo.len)
			rc = ERROR_CODE();
	}

	if (flatinfo.buf)
		free(flatinfo.buf);
	flatinfo.buf = 0;
	close(flatinfo.fd);
	flatinfo.fd = -1;

	return rc;
}

/****************************************************************************/
