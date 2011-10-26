/*****************************************************************************/

/*
 *	flatfs.h -- support for flat FLASH file systems.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2001-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/
#ifndef flatfs_h
#define flatfs_h
/*****************************************************************************/

/*
 * The default source and destination directories. Can be overridden
 * with command line options.
 */
#if CONFIG_USER_FLATFSD_CONFIG_BLOBS
#define	FILEFS		"/sda1/configs/default.cfg"
#else
#define	FILEFS		"/dev/flash/config"
#endif
#define	DEFAULTDIR	"/etc/default"
#define	SRCDIR		"/etc/config"
#define	DSTDIR		SRCDIR

#define FLATFSD_CONFIG	".flatfsd"

/*
 * Globals for file and byte count.
 */
extern int numfiles;
extern int numbytes;
extern int numdropped;

extern int flat_new(const char *dir);
extern int flat_clean(void);
extern int flat_filecount(char *configdir);
extern int flat_needinit(void);
extern int flat_requestinit(void);

#ifndef HAS_RTC
extern void parseconfig(char *buf);
#endif

#ifdef LOGGING
extern void vlogd(int bg, const char *cmd, const char *arg);
extern void logd(const char *cmd, const char *format, ...) __attribute__ ((format(printf, 2, 3)));
#else
static inline void vlogd(int bg, const char *cmd, const char *arg)
{
}

static void logd(const char *cmd, const char *format, ...) __attribute__ ((format(printf, 2, 3)));
static inline void logd(const char *cmd, const char *format, ...)
{
}
#endif

#define ERROR_CODE()	(-(__LINE__)) /* unique failure codes :-) */

/*****************************************************************************/
#endif
