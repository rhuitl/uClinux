/* Copyright 2009 Dr Paul Dale (pauli@snapgear.com)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License as published by   
 * the Free Software Foundation; either version 2 of the License, or      
 * (at your option) any later version.                                    
 *                                                                         
 * This program is distributed in the hope that it will be useful,        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of         
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
 * GNU General Public License for more details.                           
 *                                                                         
 * You should have received a copy of the GNU General Public License      
 * along with this program; if not, write to the Free Software            
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


#include <stdio.h>			/* *printf */
#include <string.h>			/* mem* */

#include "ipset.h"

#include <linux/netfilter_ipv4/ip_set_polynum.h>

#define BUFLEN 30;

#define OPT_CREATE_FROM    0x01
#define OPT_CREATE_TO      0x02

static void parse_polynum(const char *str, ip_set_ip_t *num) {
	if (string_to_number(str, 0, 65536, num) != 0)
		exit_error(PARAMETER_PROBLEM, 
		           "Invalid polynumber `%s' specified", str);
}

/* Initialize the create. */
static void polynum_create_init(void *data UNUSED)
{
	DP("create INIT");
	/* Nothing */
}

/* Function which parses command options; returns true if it ate an option */
static int
polynum_create_parse(int c, char *argv[] UNUSED, void *data, unsigned *flags)
{
	struct ip_set_req_polynum_create *mydata = data;

	DP("create_parse");

	switch (c) {
	case '1':
		parse_polynum(optarg, &mydata->from);

		*flags |= OPT_CREATE_FROM;

		DP("--from %x (%u)", mydata->from, mydata->from);

		break;

	case '2':
		parse_polynum(optarg, &mydata->to);

		*flags |= OPT_CREATE_TO;

		DP("--to %x (%u)", mydata->to, mydata->to);

		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
static void
polynum_create_final(void *data, unsigned int flags)
{
	struct ip_set_req_polynum_create *mydata = data;

	if (flags == 0) {
		exit_error(PARAMETER_PROBLEM,
			   "Need to specify --from and --to\n");
	} else {
		/* --from --to */
		if ((flags & OPT_CREATE_FROM) == 0
		    || (flags & OPT_CREATE_TO) == 0)
			exit_error(PARAMETER_PROBLEM,
				   "Need to specify both --from and --to\n");
	}

	DP("from : %x to: %x  diff: %d", mydata->from, mydata->to,
	   mydata->to - mydata->from);

	if (mydata->from > mydata->to)
		exit_error(PARAMETER_PROBLEM,
			   "From can't be lower than to.\n");

	if (mydata->to - mydata->from > MAX_RANGE)
		exit_error(PARAMETER_PROBLEM,
			   "Range too large. Max is %d numbers in range\n",
			   MAX_RANGE+1);
}

/* Create commandline options */
static const struct option create_opts[] = {
	{.name = "from",	.has_arg = required_argument,	.val = '1'},
	{.name = "to",		.has_arg = required_argument,	.val = '2'},
	{NULL},
};

/* Add, del, test parser */
static ip_set_ip_t
adt_parser(int cmd UNUSED, const char *arg, void *data)
{
	struct ip_set_req_polynum *mydata = data;

	parse_polynum(arg, &mydata->ip);
	DP("%u", (unsigned int)mydata->ip);

	return 1;	
}

/*
 * Print and save
 */

static void
polynum_initheader(struct set *set, const void *data)
{
	const struct ip_set_req_polynum_create *header = data;
	struct ip_set_polynum *map = set->settype->header;

	memset(map, 0, sizeof(struct ip_set_polynum));
	map->first_ip = header->from;
	map->last_ip = header->to;
}

static void
polynum_printheader(struct set *set, unsigned options)
{
	struct ip_set_polynum *mysetdata = set->settype->header;

	printf(" from: %u", mysetdata->first_ip);
	printf(" to: %u\n", mysetdata->last_ip);
}

static void
polynum_printpolynums_sorted(struct set *set, void *data,
		  u_int32_t len UNUSED, unsigned options, char dont_align)
{
	struct ip_set_polynum *mysetdata = set->settype->header;
	u_int32_t addr = mysetdata->first_ip;

	DP("%u -- %u", mysetdata->first_ip, mysetdata->last_ip);
	while (addr <= mysetdata->last_ip) {
		if (test_bit(addr - mysetdata->first_ip, data))
			printf("%u\n", (unsigned int)addr);
		addr++;
	}
}

static void
polynum_saveheader(struct set *set, unsigned options)
{
	struct ip_set_polynum *mysetdata = set->settype->header;

	printf("-N %s %s --from %u", 
	       set->name,
	       set->settype->typename,
	       mysetdata->first_ip);
	printf(" --to %u\n", mysetdata->last_ip);
}

static void
polynum_savepolynum(struct set *set, void *data,
	  u_int32_t len UNUSED, unsigned options, char dont_align)
{
	struct ip_set_polynum *mysetdata = set->settype->header;
	u_int32_t addr = mysetdata->first_ip;

	while (addr <= mysetdata->last_ip) {
		if (test_bit(addr - mysetdata->first_ip, data))
			printf("-A %s %u\n",
			       set->name, (unsigned int)addr);
		addr++;
	}
}

static void usage(void)
{
	printf
	    ("-N set polynum --from NUMBER --to NUMBER\n"
	     "-A set NUMBER\n"
	     "-D set NUMBER\n"
	     "-T set NUMBER\n");
}

static struct settype settype_polynum = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_polynum_create),
	.create_init = polynum_create_init,
	.create_parse = polynum_create_parse,
	.create_final = polynum_create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.adt_size = sizeof(struct ip_set_req_polynum),
	.adt_parser = &adt_parser,

	/* Printing */
	.header_size = sizeof(struct ip_set_polynum),
	.initheader = polynum_initheader,
	.printheader = polynum_printheader,
	.printips = polynum_printpolynums_sorted,
	.printips_sorted = polynum_printpolynums_sorted,
	.saveheader = polynum_saveheader,
	.saveips = polynum_savepolynum,

	.usage = &usage,
};

CONSTRUCTOR(polynum)
{
	settype_register(&settype_polynum);

}
