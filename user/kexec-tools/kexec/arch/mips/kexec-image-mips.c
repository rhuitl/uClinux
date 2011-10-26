/*
 * kexec-image-mips.c - kexec Image loader for mips
 * Copyright (C) 2009,  Greg Ungerer <gerg@snapgear.com>
 *
 * derived from kexec-elf-mips.c
 * Copyright (C) 2007 Francesco Chiechi, Alessandro Rubini
 * Copyright (C) 2007 Tvblob s.r.l.
 *
 * derived from ../ppc/kexec-elf-ppc.c
 * Copyright (C) 2004 Albert Herranz
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include "../../kexec.h"
#include "kexec-mips.h"
#include <arch/options.h>

static const int probe_debug = 0;

#define	KEXEC_ARGS_MAGIC	"_KeXeC ArGs_"
#define MAX_COMMAND_LINE	2048
#define	MAX_COMMAND_ARGS	32

struct args_page {
	char	magic[16];
	int	argc;
	char	*argvp;
	char	*argv[MAX_COMMAND_ARGS];
	char	argbuf[MAX_COMMAND_LINE];
};

struct args_page image_args;

#define OPT_APPEND	(OPT_ARCH_MAX+0)

int image_mips_probe(const char *buf, off_t len)
{
	/* Not much we can really check, this is just a binary blob. */
	return 0;
}

void image_mips_usage(void)
{
	printf("    --command-line=STRING Set the kernel command line to "
			"STRING.\n"
	       "    --append=STRING       Set the kernel command line to "
			"STRING.\n");
}

void image_mips_parseargs(char *cmdline)
{
	char *sp, *dp;

	memcpy(&image_args.magic[0], KEXEC_ARGS_MAGIC, sizeof(KEXEC_ARGS_MAGIC));
	sp = cmdline;
	dp = &image_args.argbuf[0];
	image_args.argvp = &image_args.argv[0];
	image_args.argv[image_args.argc] = dp;

	/* skip any leading white space */
	while ((*sp != '\0') && ((*sp == ' ') || (*sp == '\t')))
		sp++;

	while (*sp != '\0') {
		if (dp >= &image_args.argbuf[MAX_COMMAND_LINE-1])
			break;

		if ((*sp == ' ') || (*sp == '\t')) {
			if (image_args.argc >= MAX_COMMAND_ARGS-1)
				break;

			*dp++ = '\0';
			image_args.argc++;
			image_args.argv[image_args.argc] = dp;

			/* skip any more white space */
			while ((*sp == ' ') || (*sp == '\t'))
				sp++;
			continue;
		}

		*dp++ = *sp++;
	}

	*dp = '\0';
	if (image_args.argv[image_args.argc] == dp) {
		/* empty arg, remove from tail of list */
		image_args.argv[image_args.argc] = NULL;
	} else {
		/* include last arg in count */
		image_args.argc++;
	}
}

void image_mips_fixupargs(unsigned long paddr)
{
	char *dp = (char *) paddr;
	int i;

	/* Flatten the argv pointers (we need them as physical address) */
	image_args.argvp = dp +
		(((unsigned long) &image_args.argv[0]) -
		((unsigned long) &image_args));

	for (i = 0; (i < image_args.argc); i++) {
		image_args.argv[i] = dp +
			(((unsigned long) image_args.argv[i]) -
			((unsigned long) &image_args));
	}
}

int image_mips_load(int argc, char **argv, const char *buf, off_t len, struct kexec_info *info)
{
	unsigned long base, offset, offset_args;
	char *command_line;
	int opt;
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{"command-line", 1, 0, OPT_APPEND},
		{"append",       1, 0, OPT_APPEND},
		{0, 0, 0, 0},
	};

	static const char short_options[] = KEXEC_ARCH_OPT_STR "d";

	command_line = NULL;
	while ((opt = getopt_long(argc, argv, short_options, options, 0)) != -1) {
		switch (opt) {
		default:
			/* Ignore core options */
			if (opt < OPT_ARCH_MAX) {
				break;
			}
		case '?':
			usage();
			return -1;
		case OPT_APPEND:
			command_line = optarg;
			break;
		}
	}

	/*
	 *	Default image load address, 1MB. This is what we use on
	 *	the Octeon targets anyway. Probably be better to have this
	 *	come in through a command line arg.
	 *	The kernel boot args are put in a page just below the kernel
	 *	start address. Again, could be set at load time on the
	 *	command line.
	 */
	offset = 0x100000;
	offset_args = offset - 8192;

	/* Load image binary blob */
	base = locate_hole(info, offset+len, 0, 0, ULONG_MAX, INT_MAX);
	if (base == ULONG_MAX)
		return -1;
	add_segment(info, buf, len, base + offset, len);

	if (command_line) {
		image_mips_parseargs(command_line);
		image_mips_fixupargs(offset_args);
		add_segment(info, &image_args, sizeof(image_args), base + offset_args, sizeof(image_args));
	}

	info->entry = (void *) offset;

	return 0;
}

