/*
 * Copyright (C) 2009 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * An utility to get MTD information.
 *
 * Author: Artem Bityutskiy
 */

#define PROGRAM_VERSION "1.0"
#define PROGRAM_NAME    "mtdinfo"

#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <mtd/mtd-user.h>

#include <libubigen.h>
#include <libmtd.h>
#include "common.h"
#include "ubiutils-common.h"

/* The variables below are set by command line arguments */
struct args {
	int mtdn;
	unsigned int all:1;
	unsigned int ubinfo:1;
	const char *node;
};

static struct args args = {
	.mtdn = -1,
	.ubinfo = 0,
	.all = 0,
	.node = NULL,
};

static const char doc[] = PROGRAM_NAME " version " PROGRAM_VERSION
			 " - a tool to print MTD information.";

static const char optionsstr[] =
"-m, --mtdn=<MTD device number>  MTD device number to get information about\n"
"-u, --ubi-info                  print what would UBI layout be if it was put\n"
"                                on this MTD device\n"
"-a, --all                       print information about all MTD devices\n"
"-h, --help                      print help message\n"
"-V, --version                   print program version";

static const char usage[] =
"Usage 1: " PROGRAM_NAME " [-m <MTD device number>] [-u] [-h] [-V] [--mtdn <MTD device number>]\n"
"\t\t[--ubi-info] [--help] [--version]\n"
"Usage 2: " PROGRAM_NAME " <MTD device node file name> [-u] [-h] [-V] [--ubi-info] [--help]\n"
"\t\t[--version]\n"
"Example 1: " PROGRAM_NAME " - (no arguments) print general MTD information\n"
"Example 2: " PROGRAM_NAME " -m 1 - print information about MTD device number 1\n"
"Example 3: " PROGRAM_NAME " /dev/mtd0 - print information MTD device /dev/mtd0\n"
"Example 4: " PROGRAM_NAME " /dev/mtd0 -u - print information MTD device /dev/mtd0\n"
"\t\t\t\tand include UBI layout information\n"
"Example 5: " PROGRAM_NAME " -a - print information about all MTD devices\n"
"\t\t\tand include UBI layout information\n";

static const struct option long_options[] = {
	{ .name = "mtdn",      .has_arg = 1, .flag = NULL, .val = 'm' },
	{ .name = "ubi-info",  .has_arg = 0, .flag = NULL, .val = 'u' },
	{ .name = "all",       .has_arg = 0, .flag = NULL, .val = 'a' },
	{ .name = "help",      .has_arg = 0, .flag = NULL, .val = 'h' },
	{ .name = "version",   .has_arg = 0, .flag = NULL, .val = 'V' },
	{ NULL, 0, NULL, 0},
};

static int parse_opt(int argc, char * const argv[])
{
	while (1) {
		int key;
		char *endp;

		key = getopt_long(argc, argv, "am:uhV", long_options, NULL);
		if (key == -1)
			break;

		switch (key) {
		case 'a':
			args.all = 1;
			break;

		case 'u':
			args.ubinfo = 1;
			break;

		case 'm':
			args.mtdn = strtoul(optarg, &endp, 0);
			if (*endp != '\0' || endp == optarg || args.mtdn < 0)
				return errmsg("bad MTD device number: \"%s\"", optarg);

			break;

		case 'h':
			fprintf(stderr, "%s\n\n", doc);
			fprintf(stderr, "%s\n\n", usage);
			fprintf(stderr, "%s\n", optionsstr);
			exit(EXIT_SUCCESS);

		case 'V':
			fprintf(stderr, "%s\n", PROGRAM_VERSION);
			exit(EXIT_SUCCESS);

		case ':':
			return errmsg("parameter is missing");

		default:
			fprintf(stderr, "Use -h for help\n");
			return -1;
		}
	}

	if (optind == argc - 1)
		args.node = argv[optind];
	else if (optind < argc)
		return errmsg("more then one MTD device specified (use -h for help)");

	if (args.all && (args.node || args.mtdn != -1)) {
		args.mtdn = -1;
		args.node = NULL;
	}

	return 0;
}

static int translate_dev(libmtd_t libmtd, const char *node)
{
	int err;
	struct mtd_dev_info mtd;

	err = mtd_get_dev_info(libmtd, node, &mtd);
	if (err) {
		if (errno == ENODEV)
			return errmsg("\"%s\" does not correspond to any "
				      "existing MTD device", node);
		return sys_errmsg("cannot get information about MTD "
				  "device \"%s\"", node);
	}

	args.mtdn = mtd.mtd_num;
	return 0;
}

static int print_dev_info(libmtd_t libmtd, const struct mtd_info *mtd_info, int mtdn)
{
	int err;
	struct mtd_dev_info mtd;
	struct ubigen_info ui;

	err = mtd_get_dev_info1(libmtd, mtdn, &mtd);
	if (err) {
		if (errno == ENODEV)
			return errmsg("mtd%d does not correspond to any "
				      "existing MTD device", mtdn);
		return sys_errmsg("cannot get information about MTD device %d",
				  mtdn);
	}

	printf("mtd%d\n", mtd.mtd_num);
	printf("Name:                           %s\n", mtd.name);
	printf("Type:                           %s\n", mtd.type_str);
	printf("Eraseblock size:                ");
	ubiutils_print_bytes(mtd.eb_size, 0);
	printf("\n");
	printf("Amount of eraseblocks:          %d (", mtd.eb_cnt);
	ubiutils_print_bytes(mtd.size, 0);
	printf(")\n");
	printf("Minimum input/output unit size: %d %s\n",
	       mtd.min_io_size, mtd.min_io_size > 1 ? "bytes" : "byte");
	if (mtd_info->sysfs_supported)
		printf("Sub-page size:                  %d %s\n",
		       mtd.subpage_size,
		       mtd.subpage_size > 1 ? "bytes" : "byte");
	else if (mtd.type == MTD_NANDFLASH)
		printf("Sub-page size:                  unknown\n");

	if (mtd.oob_size > 0)
		printf("OOB size:                       %d bytes\n",
		       mtd.oob_size);
	if (mtd.region_cnt > 0)
		printf("Additional erase regions:       %d\n", mtd.oob_size);
	if (mtd_info->sysfs_supported)
		printf("Character device major/minor:   %d:%d\n",
		       mtd.major, mtd.minor);
	printf("Bad blocks are allowed:         %s\n",
	       mtd.bb_allowed ? "true" : "false");
	printf("Device is writable:             %s\n",
	      mtd.writable ? "true" : "false");

	if (!args.ubinfo)
		goto out;

	if (!mtd_info->sysfs_supported) {
		errmsg("cannot provide UBI info, becasue sub-page size is "
		       "not known");
		goto out;
	}

	ubigen_info_init(&ui, mtd.eb_size, mtd.min_io_size, mtd.subpage_size,
			 0, 1, 0);
	printf("Default UBI VID header offset:  %d\n", ui.vid_hdr_offs);
	printf("Default UBI data offset:        %d\n", ui.data_offs);
	printf("Default UBI LEB size:           ");
	ubiutils_print_bytes(ui.leb_size, 0);
	printf("\n");
	printf("Maximum UBI volumes count:      %d\n", ui.max_volumes);

out:
	printf("\n");
	return 0;
}

static int print_general_info(libmtd_t libmtd, const struct mtd_info *mtd_info,
			      int all)
{
	int i, err, first = 1;
	struct mtd_dev_info mtd;

	printf("Count of MTD devices:           %d\n", mtd_info->mtd_dev_cnt);
	if (mtd_info->mtd_dev_cnt == 0)
		return 0;

	for (i = mtd_info->lowest_mtd_num;
	     i <= mtd_info->highest_mtd_num; i++) {
		err = mtd_get_dev_info1(libmtd, i, &mtd);
		if (err == -1) {
			if (errno == ENODEV)
				continue;
			return sys_errmsg("libmtd failed get MTD device %d "
					  "information", i);
		}

		if (!first)
			printf(", mtd%d", i);
		else {
			printf("Present MTD devices:            mtd%d", i);
			first = 0;
		}
	}
	printf("\n");
	printf("Sysfs interface supported:      %s\n",
	       mtd_info->sysfs_supported ? "yes" : "no");

	if (!all)
		return 0;

	first = 1;
	printf("\n");

	for (i = mtd_info->lowest_mtd_num;
	     i <= mtd_info->highest_mtd_num; i++) {
		err = print_dev_info(libmtd, mtd_info, i);
		if (err)
			return err;
	}

	return 0;
}

int main(int argc, char * const argv[])
{
	int err;
	libmtd_t libmtd;
	struct mtd_info mtd_info;

	err = parse_opt(argc, argv);
	if (err)
		return -1;

	libmtd = libmtd_open();
	if (libmtd == NULL) {
		if (errno == 0)
			return errmsg("MTD is not present in the system");
		return sys_errmsg("cannot open libmtd");
	}

	err = mtd_get_info(libmtd, &mtd_info);
	if (err) {
		if (errno == ENODEV)
			return errmsg("MTD is not present");
		return sys_errmsg("cannot get MTD information");
	}

	if (args.node) {
		/*
		 * A character device was specified, translate this to MTD
		 * device number.
		 */
		err = translate_dev(libmtd, args.node);
		if (err)
			goto out_libmtd;
	}

	if (args.mtdn == -1)
		err = print_general_info(libmtd, &mtd_info, args.all);
	else
		err = print_dev_info(libmtd, &mtd_info, args.mtdn);
	if (err)
		goto out_libmtd;

	libmtd_close(libmtd);
	return 0;

out_libmtd:
	libmtd_close(libmtd);
	return -1;
}
