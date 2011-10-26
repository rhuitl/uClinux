/*****************************************************************************/

/*
 *	flatfs.c -- simple flat FLASH file-system.
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
#include <signal.h>

#include <config/autoconf.h>
#include "flatfs.h"
#include "dev.h"
#include "ops.h"
#include "flatfs1.h"
#include "flatfs3.h"

/*****************************************************************************/

/*
 * Globals for file and byte count.
 * This is a kind of ugly way to do it, but we are using LCP
 * (Least Change Principle)
 */
int numfiles;
int numbytes;
int numdropped;

/*
 *  The name of the file (normally a device) to store the flatfs contents.
 */
char *filefs;

/*****************************************************************************/

static void getfilefs(void)
{
	filefs = FILEFS;
}

/*****************************************************************************/

/*
 * Return the version number of flatfs we have. Return 1 or 2, otherwise
 * an error code that is less than zero.
 */

static int flat_version(void)
{
	unsigned int magic;

	magic = flat1_gethdr();
	if (magic == FLATFS_MAGIC)
		return 1;
	else if (magic == FLATFS_MAGIC_V2)
		return 2;

#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	magic = flat3_gethdr();
	if (magic == FLATFS_MAGIC_V3)
		return 3;
	if (magic == FLATFS_MAGIC_V4)
		return 4;
#endif

	syslog(LOG_ERR, "invalid header magic version");
	return ERROR_CODE();
}

/*****************************************************************************/

/*
 * Check the consistency of the flatfs in flash.
 */

static int flat_check(void)
{
	int rc;

	if (chdir(DSTDIR) < 0)
		return ERROR_CODE();

	if ((rc = flat_open(filefs, "r")) < 0)
		return rc;

	switch (rc = flat_version()) {
	case 1:
	case 2:
		rc = flat1_checkfs();
		break;
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
	case 4:
		rc = flat3_checkfs();
		break;
#endif
	default:
		/* Unknown revision? */
		break;
	}

	flat_close(0, 0);
	return rc;
}

/*****************************************************************************/

/*
 * Read the contents of a flat file-system and dump them out as regular files.
 * At this level we just figure out what version flatfs it is and call off
 * the the right place to handle it.
 */

static int flat_restorefs(const char *configdir)
{
	int rc;
	int numversion;

	if (chdir(configdir) < 0) {
		return ERROR_CODE();
	}

	if ((rc = flat_open(filefs, "r")) < 0) {
		return ERROR_CODE();
	}

	switch (numversion = flat_version()) {
	case 1:
	case 2:
		rc = flat1_restorefs(numversion, 1);
		break;
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
	case 4:
		rc = flat3_restorefs(numversion, 1);
		break;
#endif
	default:
		/* Unknown revision? */
		break;
	}

	flat_close(0, 0);
	if (rc == 0)
		syslog(LOG_INFO, "Restored %d configuration files (%d bytes)",
			numfiles, numbytes);
	return rc;
}

/*****************************************************************************/

/*
 *	Write out the contents of the local directory to flat file-system.
 *	The writing process is not quite as easy as read. Use the usual
 *	write system call so that FLASH programming is done properly.
 */

static int flat_savefs(int version, const char *configdir)
{
	unsigned int total;
	time_t start_time, flt_write_time;
	int log_level, rc = 0;

	flat_sum = 0;
	start_time = time(NULL);

	if (chdir(configdir) < 0)
		return ERROR_CODE();

#ifndef HAS_RTC
	{
		/* Create a special config file to store the current time. */
		FILE *hfile;

		if ((hfile = fopen(FLATFSD_CONFIG, "w")) == NULL)
			return ERROR_CODE();
		fprintf(hfile, "time %ld\n", time(NULL));
		/* Ignore errors! */
		fflush(hfile);
		fclose(hfile);
	}
#endif

	rc = flat_open(filefs, "w");
	if (rc < 0)
		goto cleanup;

	/* Check to see if the config will fit before we erase */
	switch (version) {
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
	case 4:
		rc = flat3_savefs(0, &total);
		if ((rc < 0) || (total > flat_part_length())) { 
			syslog(LOG_ERR, "config will not fit in flash partition");
			goto cleanup_and_close;
		}
		break;
#endif
	case 1:
	case 2:
	default:
		rc = flat1_savefs(0, &total);
		if ((rc < 0) || (total > flat_dev_length())) { 
			syslog(LOG_ERR, "config will not fit in flash");
			goto cleanup_and_close;
		}
		break;
	}

	switch (version) {
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
	case 4:
		rc = flat3_savefs(1, &total);
		break;
#endif
	case 1:
	case 2:
	default:
		rc = flat1_savefs(1, &total);
		break;
	}
	if (rc < 0)
		goto cleanup_and_close;

	unlink(FLATFSD_CONFIG);
	rc = flat_close(0, total);

	flt_write_time = time(NULL) - start_time;

	log_level = LOG_ALERT;
	if (flt_write_time <= 20)
		log_level = LOG_DEBUG;
	else if ((flt_write_time > 20) && (flt_write_time <= 40))
		log_level = LOG_NOTICE;
	else if ((flt_write_time > 40) && (flt_write_time <= 100))
		log_level = LOG_ERR;
	else
		log_level = LOG_ALERT;
	syslog(log_level, "Wrote %d bytes to flash in %ld seconds",
		total, flt_write_time);

	return rc;

cleanup_and_close:
	flat_close(1, 0);
cleanup:
	unlink(FLATFSD_CONFIG);
	return rc;
}

/*****************************************************************************/

/*
 * Simple wrappers that also do logging
 */

#ifndef HAS_RTC
void parseconfig(char *buf)
{
	char *confline, *confdata;
	time_t bst = BUILD_START_UNIX;

	confline = strtok(buf, "\n");
	while (confline) {
		confdata = strchr(confline, ' ');
		if (confdata) {
			*confdata = '\0';
			confdata++;
			if (!strcmp(confline, "time")) {
				time_t t;
				t = atol(confdata);
				if ((t > time(NULL)) && (t > bst))
					stime(&t);
				else
					stime(&bst);
				bst = 0;
			}
		}
		confline = strtok(NULL, "\n");
	}

	if (bst) {
		stime(&bst);
	}
}
#endif

static int checkconfig(void)
{
	int rc;

	rc = flat_check();
	if (rc < 0) {
		logd("chksum-bad", "%d", -rc);
		printf("Flash filesystem is invalid %d - check syslog\n", rc);
	} else {
		logd("chksum-good", NULL);
		printf("Flash filesystem is valid\n");
	}
	return rc;
}

static int readconfig(const char *configdir)
{
	int rc;

	rc = flat_restorefs(configdir);
	if (rc < 0) {
		logd("newflatfs", "recreate=%d", rc);
		printf("Failed to read flash filesystem (%d)\n", rc);
	}
	return rc;
}

static int saveconfig(int fsver, const char *configdir)
{
	int rc;

	logd("writeconfig", NULL);
	rc = flat_savefs(fsver, configdir);
	if (rc < 0)
		syslog(LOG_ERR, "Failed to write flatfs (%d): %m", rc);
	logd("write-done", NULL);
	rc = checkconfig();
	return rc;
}

/*****************************************************************************/

static void lockpidfile(void)
{
	char *pidfile = "/var/run/flatfs.pid";
	struct flock lock;
	char buf[10];
	int fd;

	fd = open(pidfile, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to open %s: %m", pidfile);
		exit(1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	while (fcntl(fd, F_SETLK, &lock) < 0) {
		if (errno != EACCES && errno != EAGAIN) {
			syslog(LOG_ERR, "Failed to lock %s: %m", pidfile);
			exit(1);
		}
		sleep(1);
	}

	snprintf(buf, sizeof(buf), "%d\n", getpid());
	write(fd, buf, strlen(buf));
}

/*****************************************************************************/

static void usage(int rc)
{
	printf("usage: flatfs [-c|-r|-s|-h|-?] [-n123] [-d <dirk>] [-f <file>]\n"
		"\t-c check that the saved flatfs is valid\n"
		"\t-d <dir> with -r to read from flash to an alternate filesystem\n"
		"\t-f <file> file or device to use for persistent flatfs storage\n"
		"\t-r read from flash, write to config filesystem\n"
		"\t-s save config filesystem to flash\n"
		"\t-1 force use of version 1 flash layout\n"
		"\t-2 force use of version 2 flash layout\n"
		"\t-3 force use of version 3 flash layout\n"
		"\t-4 force use of version 4 flash layout (default)\n"
		"\t-h this help\n");
	exit(rc);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	struct sigaction act;
	int rc, readonly, clobbercfg, action = 0;
	char *configdir = DSTDIR;
	int fsver = 4;

	clobbercfg = readonly = 0;

	openlog("flatfs", LOG_PERROR|LOG_PID, LOG_DAEMON);

	while ((rc = getopt(argc, argv, "crsd:f:1234h?")) != EOF) {
		switch (rc) {
		case 'c':
		case 'r':
		case 's':
			action = rc;
			break;
		case 'd':
			configdir = optarg;
			if (access(configdir, R_OK | W_OK) < 0) {
				printf("%s: directory does not exist or is "
					"not writeable\n", configdir);
				exit(1);
			}
			break;
		case 'f':
			filefs = optarg;
			if (access(filefs, R_OK | W_OK) < 0) {
				printf("%s: storage file does not exists or"
					"is not writable\n", filefs);
				exit(1);
			}
			break;
		case '1':
			fsver = 1;
			break;
		case '2':
			fsver = 2;
			break;
		case '3':
			fsver = 3;
			break;
		case '4':
			fsver = 4;
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (filefs == (char *) NULL)
		getfilefs();
	syslog(LOG_INFO, "using storage at %s", filefs);

	/* Make sure only one flatfs process accesses flash at a time */
	lockpidfile();

	/* Make sure we don't suddenly exit while we are writing */
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);

	switch (action) {
	case 'c':
		exit(checkconfig());
		break;
	case 'r':
		exit(readconfig(configdir));
		break;
	case 's':
		exit(saveconfig(fsver, configdir));
		break;
	}

	return 1;
}

/*****************************************************************************/
