/*
 * Copyright 1998 Hans Reiser
 */
/*#include <stdio.h>
#include <string.h>*/
/*#include <asm/bitops.h>
#include "../include/reiserfs_fs.h"
#include "../include/reiserfs_fs_sb.h"
#include "../include/reiserfslib.h"*/
#include "fsck.h"


/* there is a situation, when we overwrite contents of unformatted
   node with direct item. One unformatted node can be overwritten
   several times by direct items */
/*
struct overwritten_unfm_segment {
  int ous_begin;
  int ous_end;
  struct overwritten_unfm_segment * ous_next;  
};
*/
struct overwritten_unfm {
  unsigned long ou_unfm_ptr;	/* block number of unfm node */
  unsigned long ou_dir_id;
  unsigned long ou_objectid; 	/* key corresponding to an unfm node */
  unsigned long ou_offset;

  struct overwritten_unfm_segment * ou_segments;	/* list of segmens, than have been overwritten in ths unfm node */
};

struct overwritten_unfm ** g_overwritten_unfms;
int g_overwritten_unfms_amount;	/* number of unformatted nodes, which contain direct items */


/* adds segment to the single linked list of segments sorted by begin
   field. Retuns pointer to first element of list */
static struct overwritten_unfm_segment * add_segment (struct overwritten_unfm_segment * first, int begin, int end)
{
  struct overwritten_unfm_segment * new, * next, * prev;

  new = getmem (sizeof (struct overwritten_unfm_segment));
  new->ous_begin = begin;
  new->ous_end = end;
  new->ous_next = 0;

  next = first;
  prev = 0;
  while (next) {
    if (next->ous_begin > begin)
      break;
    prev = next;
    next = next->ous_next;
  }

  if (prev == 0) {
    /* insert into head of list */
    first = new;
  } else {
    prev->ous_next = new;
  }
  new->ous_next = next;
  return first;
}


/* input parameter 
   `list_head` - first element of overlapping segments sorted by left edge
   `unoverwritten_segment` - returned by previous call of get_unoverwritten_segment or (-2,-2) if called first time
   */
/* returns
   1 and segment unoverwritten by elements of list `list_head`
   0 if there isno such segment
   */
int get_unoverwritten_segment (struct overwritten_unfm_segment * list_head, struct overwritten_unfm_segment * unoverwritten_segment)
{
  int end;

  /* look for segment, which has begin field greater than end of previous interval */
  while (list_head->ous_begin <= unoverwritten_segment->ous_end) {
    list_head = list_head->ous_next;
  }
  /* look for the end of the continuous region covered by otrezkami */
  end = list_head->ous_end;
  while (list_head->ous_next) {
    if (list_head->ous_next->ous_begin > end + 1)
      /* intreval found */
      break;
    if (list_head->ous_next->ous_end > end)
      end = list_head->ous_next->ous_end;
    list_head = list_head->ous_next;
  }
  /* ok, between segment and segment->next we have an interval (segment->next != 0) */
  if (list_head->ous_next != 0) {
    unoverwritten_segment->ous_begin = end + 1;
    unoverwritten_segment->ous_end = list_head->ous_next->ous_begin - 1;
    return 1;
  }
  return 0;
}


void print_segments (struct overwritten_unfm_segment * list_head)
{
  struct overwritten_unfm_segment * cur;

  cur = list_head;
  while (cur) {
    printf ("%s%d %d%s", cur == list_head ? "(" : "", cur->ous_begin, cur->ous_end, cur->ous_next ? ", " : ")\n");
    cur = cur->ous_next;
  }
}


/* this prepare list of segments to extracting of unoverwritten segments */
struct overwritten_unfm_segment * find_overwritten_unfm (unsigned long unfm, int length, struct overwritten_unfm_segment * segment_to_init)
{
  int i;

  for (i = 0; i < g_overwritten_unfms_amount && g_overwritten_unfms[i] != 0; i ++)
    if (g_overwritten_unfms[i]->ou_unfm_ptr == unfm) {
      if (g_overwritten_unfms[i]->ou_segments == 0)
	die ("find_overwritten_unfm: no segment found");
      g_overwritten_unfms[i]->ou_segments = add_segment (g_overwritten_unfms[i]->ou_segments, -1, -1);
      add_segment (g_overwritten_unfms[i]->ou_segments, length, length);
      segment_to_init->ous_begin = -2;
      segment_to_init->ous_end = -2;
      return g_overwritten_unfms[i]->ou_segments;
    }
  return 0;
}

struct overwritten_unfm * look_for_overwritten_unfm (__u32 unfm)
{
  int i;

  for (i = 0; i < g_overwritten_unfms_amount && g_overwritten_unfms[i] != 0; i ++)
    if (g_overwritten_unfms[i]->ou_unfm_ptr == unfm)
      return g_overwritten_unfms[i];
    return 0;
}

#define GROW_BY 10
struct overwritten_unfm * add_overwritten_unfm (unsigned long unfm, struct item_head * direct_ih)
{
  int i;

  for (i = 0; i < g_overwritten_unfms_amount && g_overwritten_unfms[i] != 0; i ++) {
    if (g_overwritten_unfms[i]->ou_unfm_ptr == unfm)
      return g_overwritten_unfms[i];
  }

  if (i == g_overwritten_unfms_amount) {
    g_overwritten_unfms = expandmem (g_overwritten_unfms, sizeof (struct overwritten_unfm *) * i, 
				     sizeof (struct overwritten_unfm *) * GROW_BY);
    g_overwritten_unfms_amount += GROW_BY;
  }
  g_overwritten_unfms[i] = getmem (sizeof (struct overwritten_unfm));
  g_overwritten_unfms[i]->ou_unfm_ptr = unfm;
  g_overwritten_unfms[i]->ou_dir_id = direct_ih->ih_key.k_dir_id;
  g_overwritten_unfms[i]->ou_objectid = direct_ih->ih_key.k_objectid;
  g_overwritten_unfms[i]->ou_offset = get_offset(&direct_ih->ih_key) - (get_offset(&direct_ih->ih_key) - 1) % fs->s_blocksize;
  return g_overwritten_unfms[i];
}


void save_unfm_overwriting (unsigned long unfm, struct item_head * direct_ih)
{
  struct overwritten_unfm * ov_unfm;

  /* add new overwritten unfm or return existing one */
  ov_unfm = add_overwritten_unfm (unfm, direct_ih);
  ov_unfm->ou_segments = add_segment (ov_unfm->ou_segments, (get_offset(&direct_ih->ih_key) - 1) % fs->s_blocksize,
				      (get_offset(&direct_ih->ih_key) - 1) % fs->s_blocksize + ih_item_len (direct_ih) - 1);
}


void free_overwritten_unfms (void)
{
  int i;

  for (i = 0; i < g_overwritten_unfms_amount && g_overwritten_unfms[i]; i ++) {
    /* free all segments */
    while (g_overwritten_unfms[i]->ou_segments) {
      struct overwritten_unfm_segment * tmp;

      tmp = g_overwritten_unfms[i]->ou_segments->ous_next;
      freemem (g_overwritten_unfms[i]->ou_segments);
      g_overwritten_unfms[i]->ou_segments = tmp;
    }
    /* free struct overwritten_unfm */
    freemem (g_overwritten_unfms[i]);
  }

  /* free array of pointers to overwritten unfms */
  if (g_overwritten_unfms)
    freemem (g_overwritten_unfms);
}




