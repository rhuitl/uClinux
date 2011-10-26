/**
 * @file op_alloc_counter.c
 * hardware counter allocation
 *
 * You can have silliness here.
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 */

#include <stdlib.h>

#include "op_events.h"
#include "op_libiberty.h"


typedef struct counter_arc_head {
	/** the head of allowed counter for this event */
	struct list_head next;
} counter_arc_head;


typedef struct counter_arc {
	/** counter nr */
	int counter;
	/** the next counter allowed for this event */
	struct list_head next;
} counter_arc;


/**
 * @param pev  an array of event
 * @param nr_events  number of entry in pev
 *
 * build an array of counter list allowed for each events
 *  counter_arc_head[i] is the list of allowed counter for pev[i] events
 * The returned pointer is an array of nr_events entry
 */
static counter_arc_head *
build_counter_arc(struct op_event const * pev[], int nr_events)
{
	counter_arc_head * ctr_arc;
	int i;

	ctr_arc = xmalloc(nr_events * sizeof(*ctr_arc));

	for (i = 0; i < nr_events; ++i) {
		int j;
		u32 mask = pev[i]->counter_mask;

		list_init(&ctr_arc[i].next);
		for (j = 0; mask; ++j) {
			if (mask & (1 << j)) {
				counter_arc * arc = 
					xmalloc(sizeof(counter_arc));
				arc->counter = j;
				/* we are looping by increasing counter number,
				 * allocation use a left to right tree walking
				 * so we add at end to ensure counter will
				 * be allocated by increasing number: it's not
				 * required but a bit less surprising when
				 * debugging code
				 */
				list_add_tail(&arc->next, &ctr_arc[i].next);
				mask &= ~(1 << j);
			}
		}
	}

	return ctr_arc;
}


/**
 * @param ctr_arc  the array to deallocate
 * @param nr_events  number of entry in array
 *
 *  deallocate all previously allocated resource by build_counter_arc()
 */
static void delete_counter_arc(counter_arc_head * ctr_arc, int nr_events)
{
	int i;
	for (i = 0; i < nr_events; ++i) {
		struct list_head * pos, * pos2;
		list_for_each_safe(pos, pos2, &ctr_arc[i].next) {
			counter_arc * arc = list_entry(pos, counter_arc, next);
			list_del(&arc->next);
			free(arc);
		}
	}
	free(ctr_arc);
}


/**
 * @param ctr_arc  tree description, ctr_arc[i] is the i-th level of tree.
 * @param max_depth  number of entry in array ctr_arc == depth of tree
 * @param depth  current level we are exploring
 * @param allocated_mask  current counter already allocated mask
 * @param counter_map  array of counter number mapping, returned results go
 *   here
 *
 * return non zero on succees, in this case counter_map is set to the counter
 * mapping number.
 *
 * Solution is searched through a simple backtracking exploring recursively all
 * possible solution until one is found, prunning is done in O(1) by tracking
 * a bitmask of already allocated counter. Walking through node is done in
 * preorder left to right.
 *
 * Possible improvment if neccessary: partition counters in class of counter,
 * two counter belong to the same class if they allow exactly the same set of
 * event. Now using a variant of the backtrack algo can works on class of
 * counter rather on counter (this is not an improvment if each counter goes
 * in it's own class)
 */
static int
allocate_counter(counter_arc_head const * ctr_arc, int max_depth, int depth,
		 u32 allocated_mask, size_t * counter_map)
{
	struct list_head * pos;

	if (depth == max_depth)
		return 1;

	list_for_each(pos, &ctr_arc[depth].next) {
		counter_arc const * arc = list_entry(pos, counter_arc, next);

		if (allocated_mask & (1 << arc->counter))
			return 0;

		counter_map[depth] = arc->counter;

		if (allocate_counter(ctr_arc, max_depth, depth + 1,
		                     allocated_mask | (1 << arc->counter),
		                     counter_map))
			return 1;
	}

	return 0;
}


size_t * map_event_to_counter(struct op_event const * pev[], int nr_events,
                              op_cpu cpu_type)
{
	counter_arc_head * ctr_arc;
	size_t * counter_map;
	int nr_counters;

	nr_counters = op_get_nr_counters(cpu_type);
	if (nr_counters < nr_events)
		return 0;

	ctr_arc = build_counter_arc(pev, nr_events);

	counter_map = xmalloc(nr_counters * sizeof(size_t));

	if (!allocate_counter(ctr_arc, nr_events, 0, 0, counter_map)) {
		free(counter_map);
		counter_map = 0;
	}

	delete_counter_arc(ctr_arc, nr_events);
	return counter_map;
}
