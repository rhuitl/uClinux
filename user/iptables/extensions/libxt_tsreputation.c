/*
 *	libxt_tsreputation - iptables part for xt_tsreputation
 *	Copyright © Paul Dale 2009
 *	Contact: <Paul_Dale@McAfee.com>
 *
 *	libxt_tsreputation.c is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 or 3 of the License.
 */
#include <sys/types.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>

#include <linux/netfilter/xt_tsreputation.h>
#include <xtables.h>

#define XT_TSREP_DEFINED	1


static const struct option tsreputation_opts[] = {
	{ "reputation", true,  NULL, 'R'},
	{ .name = NULL }
};


static void tsreputation_help(void)
{
	printf(
"tsreputation match options:\n"
"    --reputation rep     Reputation threshold (signed integer)\n");
}

static void tsreputation_init(struct xt_entry_match *m)
{
	struct xt_tsreputation_info *info = (void *)m->data;

	info->reputation = 0;
}


static int tsreputation_parse(int c, char **argv, int invert, unsigned int *flags,
                      const void *entry, struct xt_entry_match **match)
{
	struct xt_tsreputation_info *info = (void *)(*match)->data;
	char *end;

	switch (c) {
	case 'R': /* --reputation */
		if (*flags & XT_TSREP_DEFINED)
			xtables_error(PARAMETER_PROBLEM, "xt_tsreputation: "
				"Only use \"--reputation\" once!");
		*flags |= XT_TSREP_DEFINED;
		info->reputation = strtol(optarg, &end, 10);
		if (end == optarg || *end != '\0')
			xtables_error(PARAMETER_PROBLEM,
			           "No integer argument specified");
		info->invert = invert?1:0;
		return 1;
	}
	return 0;
}

static void tsreputation_print(const void *ip, const struct xt_entry_match *match,
                       int numeric)
{
	struct xt_tsreputation_info *info = (void *)match->data;

	printf("TSREPUTATION %d ", info->reputation);
}

static void tsreputation_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tsreputation_info *info = (const void *)match->data;

	printf("--reputation %d ", info->reputation);
}

static struct xtables_match tsreputation_match = {
	.name          = "tsreputation",
	.family        = AF_UNSPEC,
	.version       = XTABLES_VERSION,
	.size          = XT_ALIGN(sizeof(struct xt_tsreputation_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_tsreputation_info)),
	.help          = tsreputation_help,
	.init          = tsreputation_init,
	.parse         = tsreputation_parse,
	.print         = tsreputation_print,
	.save          = tsreputation_save,
	.extra_opts    = tsreputation_opts,
};

void _init(void)
{
	xtables_register_match(&tsreputation_match);
}
