/**
 * @file daemon/init.c
 * Daemon set up and main loop for 2.6
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 * Modified by Aravind Menon for Xen
 * These modifications are:
 * Copyright (C) 2005 Hewlett-Packard Co.
 */

#include "config.h"
 
#include "oprofiled.h"
#include "opd_stats.h"
#include "opd_sfile.h"
#include "opd_kernel.h"
#include "opd_trans.h"
#include "opd_anon.h"
#include "opd_perfmon.h"
#include "opd_printf.h"

#include "op_version.h"
#include "op_config.h"
#include "op_deviceio.h"
#include "op_get_time.h"
#include "op_libiberty.h"
#include "op_fileio.h"

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

size_t kernel_pointer_size;

static fd_t devfd;
static char * sbuf;
static size_t s_buf_bytesize;

static void opd_sighup(void);
static void opd_alarm(void);
static void opd_sigterm(void);

/**
 * opd_open_files - open necessary files
 *
 * Open the device files and the log file,
 * and mmap() the hash map.
 */
static void opd_open_files(void)
{
	devfd = op_open_device("/dev/oprofile/buffer");
	if (devfd == -1) {
		if (errno == EINVAL)
			fprintf(stderr, "Failed to open device. Possibly you have passed incorrect\n"
				"parameters. Check /var/log/messages.");
		else
			perror("Failed to open profile device");
		exit(EXIT_FAILURE);
	}

	/* give output before re-opening stdout as the logfile */
	printf("Using log file " OP_LOG_FILE "\n");

	/* set up logfile */
	close(0);
	close(1);

	if (open("/dev/null", O_RDONLY) == -1) {
		perror("oprofiled: couldn't re-open stdin as /dev/null: ");
		exit(EXIT_FAILURE);
	}

	opd_open_logfile();

	printf("oprofiled started %s", op_get_time());
	printf("kernel pointer size: %lu\n",
		(unsigned long)kernel_pointer_size);
	fflush(stdout);
}
 

/** Done writing out the samples, indicate with complete_dump file */
static void complete_dump(void)
{
	FILE * status_file;

retry:
	status_file = fopen(OP_DUMP_STATUS, "w");

	if (!status_file && errno == EMFILE) {
		if (sfile_lru_clear()) {
			printf("LRU cleared but file open fails for %s.\n",
			       OP_DUMP_STATUS);
			abort();
		}
		goto retry;
	}

	if (!status_file) {
		perror("warning: couldn't set complete_dump: ");
		return;
	}

	fprintf(status_file, "1\n");
	fclose(status_file);
}

 
/**
 * opd_do_samples - process a sample buffer
 * @param opd_buf  buffer to process
 *
 * Process a buffer of samples.
 *
 * If the sample could be processed correctly, it is written
 * to the relevant sample file.
 */
static void opd_do_samples(char const * opd_buf, ssize_t count)
{
	size_t num = count / kernel_pointer_size;
 
	opd_stats[OPD_DUMP_COUNT]++;

	verbprintf(vmisc, "Read buffer of %d entries.\n", (unsigned int)num);
 
	opd_process_samples(opd_buf, num);

	complete_dump();
}
 

/**
 * opd_do_read - enter processing loop
 * @param buf  buffer to read into
 * @param size  size of buffer
 *
 * Read some of a buffer from the device and process
 * the contents.
 */
static void opd_do_read(char * buf, size_t size)
{
	while (1) {
		ssize_t count = -1;

		/* loop to handle EINTR */
		while (count < 0) {
			count = op_read_device(devfd, buf, size);

			/* we can lose an alarm or a hup but
			 * we don't care.
			 */
			if (signal_alarm) {
				signal_alarm = 0;
				opd_alarm();
			}

			if (signal_hup) {
				signal_hup = 0;
				opd_sighup();
			}

			if (signal_term)
				opd_sigterm();

			if (signal_usr1) {
				signal_usr1 = 0;
				perfmon_start();
			}

			if (signal_usr2) {
				signal_usr2 = 0;
				perfmon_stop();
			}
		}

		opd_do_samples(buf, count);
	}
}


/** opd_alarm - sync files and report stats */
static void opd_alarm(void)
{
	sfile_sync_files();
	opd_print_stats();
	alarm(60 * 10);
}
 

/** re-open files for logrotate/opcontrol --reset */
static void opd_sighup(void)
{
	printf("Received SIGHUP.\n");
	/* We just close them, and re-open them lazily as usual. */
	sfile_close_files();
	close(1);
	close(2);
	opd_open_logfile();
}


static void clean_exit(void)
{
	perfmon_exit();
	unlink(OP_LOCK_FILE);
}


static void opd_sigterm(void)
{
	opd_print_stats();
	printf("oprofiled stopped %s", op_get_time());
	exit(EXIT_FAILURE);
}
 

static void opd_26_init(void)
{
	size_t i;
	size_t opd_buf_size;

	opd_create_vmlinux(vmlinux, kernel_range);
	opd_create_xen(xenimage, xen_range);

	opd_buf_size = opd_read_fs_int("/dev/oprofile/", "buffer_size", 1);
	kernel_pointer_size = opd_read_fs_int("/dev/oprofile/", "pointer_size", 1);

	s_buf_bytesize = opd_buf_size * kernel_pointer_size;

	sbuf = xmalloc(s_buf_bytesize);

	opd_reread_module_info();

	for (i = 0; i < OPD_MAX_STATS; i++)
		opd_stats[i] = 0;

	perfmon_init();

	cookie_init();
	sfile_init();
	anon_init();

	/* must be /after/ perfmon_init() at least */
	if (atexit(clean_exit)) {
		perfmon_exit();
		perror("oprofiled: couldn't set exit cleanup: ");
		exit(EXIT_FAILURE);
	}
}


static void opd_26_start(void)
{
	opd_open_files();

	/* simple sleep-then-process loop */
	opd_do_read(sbuf, s_buf_bytesize);
}


static void opd_26_exit(void)
{
	opd_print_stats();
	printf("oprofiled stopped %s", op_get_time());

	free(sbuf);
	free(vmlinux);
	/* FIXME: free kernel images, sfiles etc. */
}

struct oprofiled_ops opd_26_ops = {
	.init = opd_26_init,
	.start = opd_26_start,
	.exit = opd_26_exit,
};
