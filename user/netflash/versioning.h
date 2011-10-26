/*
 * Code to check that we are putting the correct type of flash into this
 * unit.
 * This code also removes the versioning information from the end
 * of the memory buffer.
 *
 * ret:
 *      0 - everything is correct.
 *      1 - the product name is incorrect.
 *      2 - the vendor name is incorrect.
 *      3 - the version is the same.
 *      4 - the version is older.
 *      5 - the version is invalid.
 */

/*******************************************************************************
 * The last few bytes of the image look like the following:
 *
 *  \0version\0vendore_name\0product_namechksum
 *  the chksum is 16bits wide, and the version is:
 *
 * version is w.x.y[nz], where n is ubpi, and w, x, y and z are 1 or 2 digit
 * (decimal) numbers.
 *
 ******************************************************************************/

#define MAX_VENDOR_SIZE		256
#define MAX_PRODUCT_SIZE	256
#define MAX_VERSION_SIZE	12
#define MAX_LANG_SIZE		8

extern char imageVendorName[MAX_VENDOR_SIZE];
extern char imageProductName[MAX_PRODUCT_SIZE];
extern char imageVersion[MAX_VERSION_SIZE];

extern int check_vendor(int endOffset, int *versionLength);
extern void log_upgrade(void);
