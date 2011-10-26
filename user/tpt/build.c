/*
 * $Header: /cvs/sw/new-wave/user/tpt/build.c,v 1.1 2002-02-14 23:04:55 pauli Exp $
 * "foo $Revision: 1.1 $ bar"
 */

/*
 * Build the graph
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>

#include "tpt.h"

#define BUFSIZE 1000

static int
dprintf(char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	if (DEBUG)
		ret = vprintf(fmt, ap);
	else
		ret = 0;
	return ret;
}

tpt_node *
make_new_node()
{
	tpt_node *ret = (tpt_node *)malloc(sizeof(*ret));
	int i;

	for (i = 0; i < TIMEPEG_NR_SUCCS; i++)
	{
		ret->succs[i].avg_tp = 0;
		ret->succs[i].nr_times = 0;
		ret->succs[i].min_tp = ~0;
		ret->succs[i].max_tp = 0;
		ret->succs[i].succ = 0;
	}
	ret->next = 0;
	ret->name = 0;
	ret->nr_succs = 0;
	return ret;
}

char *
skipwhite(char *p)
{
	while (*p && isspace(*p))
		p++;
	return p;
}

static int
line(FILE *f, char *buf, int eofok)
{
	char *p;

	if (fgets(buf, BUFSIZE, f) == 0)
	{
		if (eofok)
			return 0;
		fprintf(stderr, "unexpected EOF\n");
		exit(1);
	}

	/* Chop trailing newline */
	p = buf + strlen(buf);
	p--;
	if (p >= buf && *p == '\n')
		*p = '\0';
	
	return 1;
}

static void
want(int v1, int v2, const char * const _line)
{
	if (v1 != v2)
	{
		fprintf(stderr, "error parsing line '%s'\n", _line);
		fprintf(stderr, "expected %d items, got %d\n", v1, v2);
		exit(1);
	}
}

typedef struct linebuf
{
	char *line;
	struct linebuf *next;
} linebuf;

linebuf *
build_linebuf(FILE *f)
{
	char buf[1000];
	linebuf *lb = 0, *newlb;
	linebuf *head = 0;

	while (!feof(f))
	{
		if (line(f, buf, 1) == 0)
			return head;
		newlb = (linebuf *)malloc(sizeof(*lb));
		newlb->line = strdup(buf);
		if (head == 0)
		{
			head = newlb;
			lb = head;
		}
		else
		{
			lb->next = newlb;
			lb = newlb;
		}
	}
	return head;
}

tpt_node *
find_node(tpt_node *list, const char * const name)
{
	tpt_node *node = list;

	while (node)
	{
		if (strcmp(node->name, name) == 0)
			break;
		node = node->next;
	}
	return node;
}

tpt_node *
must_find_node(tpt_node *list, const char * const name)
{
	tpt_node *ret = find_node(list, name);
	if (ret == 0)
	{
		fprintf(stderr, "Internal error; Couldn't locate node `%s'\n", name);
		exit(1);
	}
	return ret;
}

#define NEXTLB()								\
	do {									\
		if (lb == 0)							\
		{								\
			fprintf(stderr,						\
				"input parsing failed at line %d\n", __LINE__);	\
			exit(1);						\
		}								\
		lb = lb->next;							\
		if (lb)								\
			dprintf("NEXTLB:%s\n", lb->line);			\
	} while (0)

struct tpt_node *
build_graph(const char * const file_name, unsigned long mhz)
{
	FILE *f = fopen(file_name, "r");
	int nr_cpus;
	struct tpt_node *list = 0;
	linebuf *linebufs, *lb;
	char buf[400];

	if (f == 0)
	{
		fprintf(stderr, "can't open '%s'\n", file_name);
		exit(1);
	}

	line(f, buf, 0);
	want(sscanf(buf, "%d", &nr_cpus), 1, buf);


	linebufs = build_linebuf(f);
	fclose(f);

#if 0
	for (lb = linebufs; lb; lb = lb->next)
	{
		printf("%s\n", lb->line);
	}
	printf("DONE\n");
#endif

	/* Pass 1: allocate data structures and name them */
	lb = linebufs;
	while (lb)
	{
		tpt_node *new_node;
		int i;
		char namebuf[200];

		new_node = make_new_node();

		if (sscanf(lb->line, " \"%[^\"]\"", namebuf) != 1)
		{
			fprintf(stderr, "tpt: name parsing failed(1) on `%s'\n", lb->line);
			exit(1);
		}
		new_node->name = strdup(namebuf);
		NEXTLB();
		for (i = 0; i < nr_cpus; i++)
		{
			int nr_preds;
			int j;
			int cpu;

			if (sscanf(lb->line, "  cpu%d", &cpu) != 1)
			{
				fprintf(stderr, "read of CPU field failed on '%s'\n", lb->line);
				exit(1);
			}

			NEXTLB();		/* CPU identifier */
			if (sscanf(lb->line, "  %d", &nr_preds) != 1)
			{
				fprintf(stderr, "read of nr_preds failed on '%s'\n", lb->line);
				exit(1);
			}
			NEXTLB();
			for (j = 0; j < nr_preds; j++)
			{
				NEXTLB();
			}
		}
		new_node->next = list;
		list = new_node;
	}

	/* Pass 2: fill in data */

	/*
	 * We do this by visiting each node and filling in its
	 * predecessor's successor field...
	 */

	lb = linebufs;
	while (lb)
	{
		tpt_node *node;
		int i;
		char namebuf[200];

		if (sscanf(lb->line, " \"%[^\"]\"", namebuf) != 1)
		{
			fprintf(stderr, "tpt: name parsing failed(2) on `%s'\n", lb->line);
			exit(1);
		}
		node = must_find_node(list, namebuf);
		NEXTLB();		/* Advance to CPU */
		for (i = 0; i < nr_cpus; i++)
		{
			int nr_preds;
			int j;
			int cpu;

			if (sscanf(lb->line, "  cpu%d", &cpu) != 1)
			{
				fprintf(stderr, "read of CPU field failed on '%s'\n", lb->line);
				exit(1);
			}
			NEXTLB();		/* CPU identifier */

			sscanf(lb->line, "  %d", &nr_preds);
			NEXTLB();

			for (j = 0; j < nr_preds; j++)
			{
				unsigned nr_times;
				unsigned long avglo, avghi, minlo, minhi, maxlo, maxhi;
				tpt_node *pred;
				unsigned succ_idx;
				char predname[200];
				struct timepeg_arc *arc;
				int nf;

				nf = sscanf(	lb->line,
						"   \"%[^\"]\" %u %u:%u %u:%u %u:%u",
						predname,
						&nr_times,
						(int *)&avghi, (int *)&avglo,
						(int *)&minhi, (int *)&minlo,
						(int *)&maxhi, (int *)&maxlo);
				if (nf != 8)
				{
					fprintf(stderr, "error parsing `%s'\n", lb->line);
					exit(1);
				}

				NEXTLB();
				pred = find_node(list, predname);
				if (pred == 0)
				{
					fprintf(stderr, "tpt: I'm confused\n");
					exit(1);
				}

				/* Does this successor already exist? */
				arc = 0;
				for (succ_idx = 0; succ_idx < TIMEPEG_NR_SUCCS; succ_idx++)
				{
					if (pred->succs[succ_idx].succ == 0)
					{	/* Empty slot */
						arc = &pred->succs[succ_idx];
						assert(node != 0);
						assert(pred->nr_succs == succ_idx);
						pred->nr_succs++;
						arc->succ = node;
						break;
					}
					else if (pred->succs[succ_idx].succ == node)
					{	/* Another ref to this node */
						arc = &pred->succs[succ_idx];
						assert(arc->succ == node);
						break;
					}
				}
					
				if (arc)
				{
					timepeg_t avg, min, max;

					arc->succ = node;
					arc->nr_times += nr_times;

					avg = avghi;
					avg <<= 32;
					avg += avglo;
					arc->avg_tp += avg;

					min = minhi;
					min <<= 32;
					min += minlo;
					if (min < arc->min_tp)
						arc->min_tp = min;

					max = maxhi;
					max <<= 32;
					max += maxlo;
					if (max > arc->max_tp)
						arc->max_tp = max;
				}
				else
				{
					fprintf(stderr, "Internal error: TIMEPEG_NR_SUCCS is too small\n");
					exit(1);
				}
			}
		}
	}
	return list;
}
