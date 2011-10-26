/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003,2004,2005  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdlib.h>
#include <stdio.h>

#include <osipparser2/osip_port.h>
#include <osipparser2/osip_list.h>

int
osip_list_init (osip_list_t * li)
{
  if (li==NULL)
    return -1;
  memset(li, 0, sizeof(osip_list_t));
  return 0;			/* ok */
}

void
osip_list_special_free (osip_list_t * li, void *(*free_func) (void *))
{
  int pos = 0;
  void *element;

  if (li == NULL)
    return;
  while (!osip_list_eol (li, pos))
    {
      element = (void *) osip_list_get (li, pos);
      osip_list_remove (li, pos);
      if (free_func!=NULL)
	free_func (element);
    }
  osip_free (li);
}

void
osip_list_ofchar_free (osip_list_t * li)
{
  int pos = 0;
  char *chain;

  if (li == NULL)
    return;
  while (!osip_list_eol (li, pos))
    {
      chain = (char *) osip_list_get (li, pos);
      osip_list_remove (li, pos);
      osip_free (chain);
    }
  osip_free (li);
}

int
osip_list_size (const osip_list_t * li)
{
  /* 
     Robin Nayathodan <roooot@softhome.net> 
     N.K Electronics INDIA

     NULL Checks  
   */

  if (li != NULL)
    return li->nb_elt;
  else
    return -1;
}

int
osip_list_eol (const osip_list_t * li, int i)
{
  if(li==NULL) return -1;
  if (i < li->nb_elt)
    return 0;			/* not end of list */
  return 1;			/* end of list */
}

/* index starts from 0; */
int
osip_list_add (osip_list_t * li, void *el, int pos)
{
  __node_t *ntmp;
  int i = 0;

  if (li == NULL) return -1;

  if (pos == -1 || pos >= li->nb_elt)
    {				/* insert at the end  */
      pos = li->nb_elt;
    }

  if (li->nb_elt == 0)
    {

      li->node = (__node_t *) osip_malloc (sizeof (__node_t));
      if (li->node == NULL) return -1;
      li->node->element = el;
      li->node->next = NULL;
      li->nb_elt++;
      return li->nb_elt;
    }

  ntmp = li->node;		/* exist because nb_elt>0  */

  if (pos == 0) /* pos = 0 insert before first elt  */
    {
      li->node = (__node_t *) osip_malloc (sizeof (__node_t));
      if (li->node == NULL)
	{
	  /* leave the list unchanged */
	  li->node=ntmp;
	  return -1;
	}
      li->node->element = el;
      li->node->next = ntmp;
      li->nb_elt++;
      return li->nb_elt;
    }
  

  while (pos > i + 1)
    {
      i++;
      /* when pos>i next node exist  */
      ntmp = (__node_t *) ntmp->next;
    }

  /* if pos==nb_elt next node does not exist  */
  if (pos == li->nb_elt)
    {
      ntmp->next = (__node_t *) osip_malloc (sizeof (__node_t));
      if (li->node == NULL) return -1; /* leave the list unchanged */
      ntmp = (__node_t *) ntmp->next;
      ntmp->element = el;
      ntmp->next = NULL;
      li->nb_elt++;
      return li->nb_elt;
    }

  /* here pos==i so next node is where we want to insert new node */
  {
    __node_t *nextnode = (__node_t *) ntmp->next;

    ntmp->next = (__node_t *) osip_malloc (sizeof (__node_t));
    if (ntmp->next ==  NULL) {
      /* leave the list unchanged */
      ntmp->next=nextnode;
      return -1;
    }
    ntmp = (__node_t *) ntmp->next;
    ntmp->element = el;
    ntmp->next = nextnode;
    li->nb_elt++;
  }
  return li->nb_elt;
}

/* index starts from 0 */
void *
osip_list_get (const osip_list_t * li, int pos)
{
  __node_t *ntmp;
  int i = 0;

  if (li == NULL) return NULL;

  if (pos < 0 || pos >= li->nb_elt)
    /* element does not exist */
    return NULL;


  ntmp = li->node;		/* exist because nb_elt>0 */

  while (pos > i)
    {
      i++;
      ntmp = (__node_t *) ntmp->next;
    }
  return ntmp->element;
}

/* return -1 if failed */
int
osip_list_remove (osip_list_t * li, int pos)
{

  __node_t *ntmp;
  int i = 0;

  if (li == NULL) return -1;

  if (pos < 0 || pos >= li->nb_elt)
    /* element does not exist */
    return -1;

  ntmp = li->node;		/* exist because nb_elt>0 */

  if ((pos == 0))
    {				/* special case  */
      li->node = (__node_t *) ntmp->next;
      li->nb_elt--;
      osip_free (ntmp);
      return li->nb_elt;
    }

  while (pos > i + 1)
    {
      i++;
      ntmp = (__node_t *) ntmp->next;
    }

  /* insert new node */
  {
    __node_t *remnode;

    remnode = (__node_t *) ntmp->next;
    ntmp->next = ((__node_t *) ntmp->next)->next;
    osip_free (remnode);
    li->nb_elt--;
  }
  return li->nb_elt;
}
