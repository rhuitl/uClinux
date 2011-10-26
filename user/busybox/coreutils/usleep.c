/* vi: set sw=4 ts=4: */
/*
 * usleep implementation for busybox
 *
 * Copyright (C) 2003  Manuel Novoa III  <mjn3@codepoet.org>
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

/* BB_AUDIT SUSv3 N/A -- Apparently a busybox extension. */

#include "libbb.h"

/* This is a NOFORK applet. Be very careful! */

int usleep_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int usleep_main(int argc ATTRIBUTE_UNUSED, char **argv)
{
	if (!argv[1]) {
		bb_show_usage();
	}

#ifdef __UC_LIBC__
	usleep(bb_xgetularg10_bnd(argv[1], 0, UINT_MAX));
#else
	if (usleep(xatou(argv[1]))) {
		bb_perror_nomsg_and_die();
	}
#endif

	return EXIT_SUCCESS;
}
