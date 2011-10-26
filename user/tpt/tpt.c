/*
 * $Header: /cvs/sw/new-wave/user/tpt/tpt.c,v 1.1 2002-02-14 23:04:55 pauli Exp $
 */

#include <stdio.h>
#include <stdlib.h>

#include "tpt.h"

static int opt_sort_friendly;

int
sort_friendly(void)
{
	return opt_sort_friendly;
}

void usage(void)
{
	fprintf(stderr, "Usage: tpt [-s] [-m MHz] [filename]\n");
	fprintf(stderr, "       -s       : produce output compatible with sort(1)\n");
	fprintf(stderr, "       -m MHz   : specify target machine's CPU rate "
				"(default from local /proc/cpuinfo)\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	unsigned long mhz = 0;
	char *file_name = 0;
	tpt_node *tpt_list;
	int arg;

	if (argc < 1)
	{
		usage();
	}

	for (arg = 1; arg < argc; arg++)
	{
		char *cp = argv[arg];
		if (*cp == '-')
		{
			cp++;
			switch (*cp)
			{
			case 'm':
				cp++;
				if (*cp == 0)
				{
					if (++arg == argc)
						usage();
					cp = argv[arg];
				}
				mhz = atoi(cp);
				if (mhz == 0)
					usage();
				break;
			case 's':	/* sort-friendly output */
				cp++;
				if (*cp)
					usage();
				opt_sort_friendly++;
				break;
			default:
				usage();
			}
		}
		else
		{
			if (file_name)
				usage();
			file_name = cp;
		}
	}

	if (file_name == 0)
		file_name = "/proc/timepeg";

	if (mhz == 0)
		mhz = get_mhz();

	tpt_list = build_graph(file_name, mhz);
/*	dump_graph(stdout, tpt_list); */
	massage_graph(mhz, tpt_list);

	dump_graph(stdout, tpt_list);
	exit(0);
}

