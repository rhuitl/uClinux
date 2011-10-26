/*
 * $Header: /cvs/sw/new-wave/user/tpt/massage.c,v 1.1 2002-02-14 23:04:55 pauli Exp $
 */

#include <stdio.h>
#include <ctype.h>

#include "tpt.h"

/*
 * Convert cycles to nSecs and calculate averages
 */

void
massage_graph(unsigned long mhz, tpt_node *tpt_list)
{
	tpt_node *node;

	for (node = tpt_list; node; node = node->next)
	{
		int succ_no;

		for (succ_no = 0; succ_no < node->nr_succs; succ_no++)
		{
			struct timepeg_arc *arc = &node->succs[succ_no];

			arc->tot_tp = arc->avg_tp;
			arc->tot_tp *= 1000;
			arc->tot_tp /= mhz;

			arc->avg_tp /= arc->nr_times;

			arc->avg_tp *= 1000;
			arc->avg_tp /= mhz;

			arc->min_tp *= 1000;
			arc->min_tp /= mhz;

			arc->max_tp *= 1000;
			arc->max_tp /= mhz;

		}
	}
}

static void
fix(char *p)
{
	while (*p)
	{
		if (isspace(*p))
			*p = '_';
		p++;
	}
}

/*
 * Overwrite any whitespace in identifiers with "_" so the output of
 * tpt is easier to sort (with 'sort -n +7', for example).
 */

void
rename_nodes(tpt_node *tpt_list)
{
	tpt_node *node;

	for (node = tpt_list; node; node = node->next)
	{
		fix(node->name);
	}
}
