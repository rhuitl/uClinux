/*
 * $Header: /cvs/sw/new-wave/user/tpt/dump.c,v 1.1 2002-02-14 23:04:55 pauli Exp $
 */

#include "tpt.h"

#define ENOUGH	200

/*
 * Convert a long long nanosecond count into
 * nnn,nnn,nnn.mm (Microseconds)
 *
 * Return a pointer to the output, which is
 * somewhere in the caller's 'buf'.
 */

char *
form_ll(char *buf, timepeg_t ll)
{
	char lbuf[100];
	char *ip;
	char *op;
	int count = 1;
	char comma = '.';

	sprintf(lbuf, "%llu", ll);
	ip = lbuf + strlen(lbuf);

	/* Ditch the last digit */
	ip--;
	op = buf + ENOUGH;
	*--op = '\0';
	while (ip > lbuf)
	{
		*--op = *--ip;
		if (ip != lbuf && ++count == 3)
		{
			if (!sort_friendly() || comma == '.')
				*--op = comma;
			comma = ',';
			count = 0;
		}
	}
	if (strlen(op) == 1)
		*--op = 0;
	if (strlen(op) == 2)
		*--op = '.';
	return op;
}

int
dump_node(FILE *f, tpt_node *node,
		int *name_max, int *name2_max, int *n_max,
		int *min_max, int *max_max, int *avg_max, int *tot_max)
{
	int i;

	if (node->nr_succs != 0)
	{
		if (f && !sort_friendly())
			fprintf(f, "\n%s ->\n", node->name);
		for (i = 0; i < node->nr_succs; i++)
		{
			char min_buf[ENOUGH];
			char max_buf[ENOUGH];
			char avg_buf[ENOUGH];
			char tot_buf[ENOUGH];
			struct timepeg_arc *arc = &node->succs[i];

			if (f)
			{
				if (sort_friendly())
				{
					char buf[*name_max + *name2_max + 10];
					sprintf(buf, "%s -> %s", node->name, arc->succ->name);
					fprintf(f, "%*s  %-*ld  %*s  %*s  %*s  %*s\n",
						*name_max + *name2_max + 4,
						buf,
						*n_max,
						arc->nr_times,
						*min_max,
						form_ll(min_buf, arc->min_tp),
						*max_max,
						form_ll(max_buf, arc->max_tp),
						*avg_max,
						form_ll(avg_buf, arc->avg_tp),
						*tot_max,
						form_ll(tot_buf, arc->tot_tp));
				}
				else
				{
					fprintf(f, "  %*s  %-*ld  %*s  %*s  %*s  %*s\n",
						*name_max,
						arc->succ->name,
						*n_max,
						arc->nr_times,
						*min_max,
						form_ll(min_buf, arc->min_tp),
						*max_max,
						form_ll(max_buf, arc->max_tp),
						*avg_max,
						form_ll(avg_buf, arc->avg_tp),
						*tot_max,
						form_ll(tot_buf, arc->tot_tp));
				}
			}
			else
			{
				char *p;

#define MAX(p, v) do { if ((v) > (*(p))) (*(p)) = (v); } while (0)

				MAX(name2_max, strlen(node->name));

				MAX(name_max, strlen(arc->succ->name));

				sprintf(avg_buf, "%ld", arc->nr_times);
				MAX(n_max, strlen(avg_buf));

				p = form_ll(min_buf, arc->min_tp);
				MAX(min_max, strlen(p));

				p = form_ll(max_buf, arc->max_tp);
				MAX(max_max, strlen(p));

				p = form_ll(avg_buf, arc->avg_tp);
				MAX(avg_max, strlen(p));

				p = form_ll(tot_buf, arc->tot_tp);
				MAX(tot_max, strlen(p));
			}
		}
	}
	return 0;
}

int
dump_graph(FILE *f, tpt_node *list)
{
	tpt_node *node;
	int ret = 0;
	int name_max = 0, name2_max = 0, n_max = 0, min_max = 0, max_max = 0, avg_max = 0, tot_max = 0;

	for (node = list; node; node = node->next)
	{
		ret = dump_node((FILE *)0, node, &name_max, &name2_max, &n_max,
				&min_max, &max_max, &avg_max, &tot_max);
		if (ret != 0)
			break;
	}

	MAX(&name_max, strlen("Destination"));
	MAX(&n_max, strlen("Count"));
	MAX(&min_max, strlen("Min"));
	MAX(&max_max, strlen("Max"));
	MAX(&avg_max, strlen("Average"));
	MAX(&tot_max, strlen("Total"));

	if (!sort_friendly())
	{
		fprintf(f,
			"  %*s  %-*s  %*s  %*s  %*s  %*s\n",
			name_max,
			"Destination",
			n_max,
			"Count",
			min_max,
			"Min",
			max_max,
			"Max",
			avg_max,
			"Average",
			tot_max,
			"Total");
	}

	for (node = list; node; node = node->next)
	{
		ret = dump_node(f, node, &name_max, &name2_max, &n_max,
				&min_max, &max_max, &avg_max, &tot_max);
		if (ret != 0)
			break;
	}
	return ret;
}
