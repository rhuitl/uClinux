/*
 * $Id: ext_hdr.c,v 1.1.1.1 2002/03/28 00:02:52 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Handy functions for dealing with extended headers.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Allocates a per-file extended header structure */

struct ext_hdr FAR *eh_alloc()
{
 struct ext_hdr FAR *rc;

 rc=(struct ext_hdr FAR *)farmalloc_msg(sizeof(struct ext_hdr));
 far_memset((char FAR *)rc, 0, sizeof(struct ext_hdr));
 return(rc);
}

/* Locates a block with the specified tag, returning pointer to it */

struct ext_hdr FAR *eh_lookup(struct ext_hdr FAR *eh, char tag)
{
 while(eh->next!=NULL)
 {
  if(eh->tag==tag)
   return(eh);
  eh=eh->next;
 }
 return(NULL);
}

/* Locates an unfinalized block */

struct ext_hdr FAR *eh_find_pending(struct ext_hdr FAR *eh)
{
 if(eh==NULL)
  return(NULL);
 while(eh->next!=NULL)
 {
  if(EH_STATUS(eh)!=EH_FINALIZED)
   return(eh);
  eh=eh->next;
 }
 return(NULL);
}

/* Inserts a new block into an instantiated extended header structure. If the
   block is given as NULL, performs reallocation only */

struct ext_hdr FAR *eh_append(struct ext_hdr FAR *eh, char tag, char FAR *block, unsigned int size)
{
 struct ext_hdr FAR *p_eh;

 if((p_eh=eh_lookup(eh, tag))==NULL)
 {
  for(p_eh=eh; p_eh->next!=NULL; p_eh=p_eh->next);
  p_eh->tag=tag;
  p_eh->next=eh_alloc();
 }
 p_eh->raw=(char FAR *)farrealloc_msg(p_eh->raw, p_eh->size+size);
 if(block!=NULL)
  far_memmove(p_eh->raw+p_eh->size, block, size);
 p_eh->size+=size;
 return(p_eh);
}

/* Releases the extended header structure */

void eh_release(struct ext_hdr FAR *eh)
{
 struct ext_hdr FAR *p_eh;

 while((p_eh=eh->next)!=NULL)
 {
  if(eh->raw!=NULL)
   farfree(eh->raw);
  farfree(eh);
  eh=p_eh;
 }
}
