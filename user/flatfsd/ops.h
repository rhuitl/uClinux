/*****************************************************************************/

/*
 *	ops.h -- support for flat FLASH file systems.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2001-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/
#ifndef FLAT_OPS_INCLUDED
#define FLAT_OPS_INCLUDED
/*****************************************************************************/

extern unsigned int flat_sum;

/*
 * Just like read() against the flat device.
 */
int flat_read(void *buf, size_t len);

/*
 * Write bytes to an erased flat device.
 * Writes at the given offset.
 * Updates the checksum.
 */
int flat_write(off_t offset, const void *buf, size_t len);

/*
 * Returns the total length of a flat device partition.
 */
size_t flat_part_length(void);

/*
 * Returns the total length of the flat device.
 */
int flat_dev_length(void);

/*
 * Performs an lseek() on the flat device.
 */
off_t flat_seek(off_t offset, int whence);

/*
 * Closes the flat device.
 * If 'abort' is not set and the device has been erased/written to,
 * then the changes are committed.
 */
int flat_close(int abort, off_t written);

/*
 * Open the flat device for reading ("r") or writing ("w").
 * The size of the device is available after opening, but
 * an explicit flat_erase() needs to be done before writing
 * anything with flat_write().
 */
int flat_open(const char *flatfs, const char *mode);

/*
 * Erase the flat device which has successfully been opened for writing.
 * Sets the checksum to 0.
 */
int flat_erase(void);

/*
 * Checksum the contents of FLASH file.
 * Pretty bogus check-sum really, but better than nothing :-)
 */
unsigned int chksum(const void *buf, unsigned int len);

/*****************************************************************************/
#endif /* FLAT_OPS_INCLUDED */
