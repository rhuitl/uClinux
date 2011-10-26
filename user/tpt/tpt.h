/*
 * Header for the timepeg tool.
 *
 * Andrew Morton <andrewm@uow.edu.au>
 * http://www.uow.edu.au/~andrewm/linux/
 *
 * $Header: /cvs/sw/new-wave/user/tpt/tpt.h,v 1.1 2002-02-14 23:04:55 pauli Exp $
 */

#ifndef _TPT_H_
#define _TPT_H_

#include <stdio.h>

#define DEBUG 0

#define TIMEPEG_NR_SUCCS	100

typedef unsigned long long timepeg_t;	/* Thank you rms */

/*
 * We don't use the per-CPU info.  Just
 * aggregate it into min/max/avg as we parse the input
 */

typedef struct tpt_node
{
	struct tpt_node *next;
	char *name;
	int nr_succs;

	struct timepeg_arc
	{
		/* Average time on this arc */
		timepeg_t avg_tp;
		unsigned long nr_times;

		/* Best and worst transit times */
		timepeg_t min_tp, max_tp;

		/* Total time */
		timepeg_t tot_tp;

		struct tpt_node *succ;
	} succs[TIMEPEG_NR_SUCCS];
} tpt_node;

int get_mhz(void);
tpt_node *build_graph(const char * const file_name, unsigned long mhz);
int dump_graph(FILE *f, tpt_node *list);
int dump_node(FILE *f, tpt_node *node,
		int *name_max, int *name2_max, int *n_max,
		int *avg_max, int *min_max, int *max_max, int *tot_max);
void massage_graph(unsigned long mhz, tpt_node *tpt_list);
int sort_friendly(void);

#endif
