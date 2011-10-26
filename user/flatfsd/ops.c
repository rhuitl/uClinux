/*****************************************************************************/

/*
 *	ops.c -- support for flat FLASH file systems.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2001-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "dev.h"
#include "ops.h"

/*****************************************************************************/

/*
 * The running total of the check sum.
 */
unsigned int flat_sum = 0;

/*****************************************************************************/

/*
 * Checksum the contents of FLASH file.
 * Pretty bogus check-sum really, but better than nothing :-)
 */
unsigned int chksum(const void *buf, unsigned int len)
{
	unsigned char *sp = (unsigned char *) buf;
	unsigned int chksum = 0;

	while (len--)
		chksum += *sp++;
	return chksum;
}

/*****************************************************************************/

/*
 * Just like read() against the flat device.
 */
int flat_read(void *buf, size_t len)
{
	return flat_dev_read(buf, len);
}

/*****************************************************************************/

/*
 * Write bytes to an erased flat device.
 * Writes at the given offset. Updates the checksum.
 */
int flat_write(off_t offset, const void *buf, size_t len)
{
	int rc = flat_dev_write(offset, buf, len);
	if (rc < 0)
		return rc;
	flat_sum += chksum(buf, len);
	return len;
}

/*****************************************************************************/

/*
 * Returns the total length of the flat device partition.
 */
size_t flat_part_length(void)
{
	return flat_dev_length()/FLAT_NUM_PARTITIONS;
}

/*****************************************************************************/

/*
 * Performs an lseek() on the flat device.
 */
off_t flat_seek(off_t offset, int whence)
{
	return flat_dev_seek(offset, whence);
}
 
/*****************************************************************************/

/*
 * Closes the flat device.
 * If 'abort' is not set and the device has been erased/written to,
 * then the changes are committed.
 */
int flat_close(int abort, off_t written)
{
	return flat_dev_close(abort, written);
}

/*****************************************************************************/

/*
 * Open the flat device for reading ("r") or writing ("w").
 * The size of the device is available after opening, but
 * an explicit flat_erase() needs to be done before writing
 * anything with flat_write().
 */
int flat_open(const char *flatfs, const char *mode)
{
	int rc;
	rc = flat_dev_open(flatfs, mode);
	return rc;
}

/*****************************************************************************/

/*
 * Erase the flat device which has successfully been opened for writing.
 * Sets the checksum to 0.
 */
int flat_erase(void)
{
	int rc;
	rc = flat_dev_erase(0, flat_dev_length());
	if (rc == 0)
		flat_sum = 0;
	return rc;
}
 
/*****************************************************************************/
