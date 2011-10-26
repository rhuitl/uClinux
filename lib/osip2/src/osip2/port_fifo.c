/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003  Aymeric MOIZARD jack@atosc.org
  
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

#include <osip2/internal.h>
#include <osip2/osip_fifo.h>


/* always use this method to initiate osip_fifo_t.
*/
void
osip_fifo_init (osip_fifo_t * ff)
{
#ifdef OSIP_MT
  ff->qislocked = osip_mutex_init ();
  /*INIT SEMA TO BLOCK ON GET() WHEN QUEUE IS EMPTY */
  ff->qisempty = osip_sem_init (0);
#endif
  ff->queue = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init (ff->queue);
  /* ff->nb_elt = 0; */
  ff->etat = vide;
}

int
osip_fifo_add (osip_fifo_t * ff, void *el)
{
#ifdef OSIP_MT
  osip_mutex_lock (ff->qislocked);
#endif

  if (ff->etat != plein)
    {
      /* ff->nb_elt++; */
      osip_list_add (ff->queue, el, -1);	/* insert at end of queue */
    }
  else
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "too much traffic in fifo.\n"));
#ifdef OSIP_MT
      osip_mutex_unlock (ff->qislocked);
#endif
      return -1;		/* stack is full */
    }
  /* if (ff->nb_elt >= MAX_LEN) */
  if (osip_list_size (ff->queue) >= MAX_LEN)
    ff->etat = plein;
  else
    ff->etat = ok;

#ifdef OSIP_MT
  osip_sem_post (ff->qisempty);
  osip_mutex_unlock (ff->qislocked);
#endif
  return 0;
}


int
osip_fifo_insert (osip_fifo_t * ff, void *el)
{
#ifdef OSIP_MT
  osip_mutex_lock (ff->qislocked);
#endif

  if (ff->etat != plein)
    {
      /* ff->nb_elt++; */
      osip_list_add (ff->queue, el, 0);	/* insert at end of queue */
    }
  else
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_WARNING, NULL,
		   "too much traffic in fifo.\n"));
#ifdef OSIP_MT
      osip_mutex_unlock (ff->qislocked);
#endif
      return -1;		/* stack is full */
    }
  /* if (ff->nb_elt >= MAX_LEN) */
  if (osip_list_size (ff->queue) >= MAX_LEN)
    ff->etat = plein;
  else
    ff->etat = ok;

#ifdef OSIP_MT
  osip_sem_post (ff->qisempty);
  osip_mutex_unlock (ff->qislocked);
#endif
  return 0;
}


int
osip_fifo_size (osip_fifo_t * ff)
{
  int i;

#ifdef OSIP_MT
  osip_mutex_lock (ff->qislocked);
#endif

  i = osip_list_size (ff->queue);
#ifdef OSIP_MT
  osip_mutex_unlock (ff->qislocked);
#endif
  return i;
}


void *
osip_fifo_get (osip_fifo_t * ff)
{
  void *el = NULL;
#ifdef OSIP_MT
  int i = osip_sem_wait (ff->qisempty);

  if (i != 0)
    return NULL;
  osip_mutex_lock (ff->qislocked);
#endif

  if (ff->etat != vide)
    {
      el = osip_list_get (ff->queue, 0);
      osip_list_remove (ff->queue, 0);
      /* ff->nb_elt--; */
    }
  else
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "no element in fifo.\n"));
#ifdef OSIP_MT
      osip_mutex_unlock (ff->qislocked);
#endif
      return 0;			/* pile vide */
    }
  /* if (ff->nb_elt <= 0) */
  if (osip_list_size (ff->queue) <= 0)
    ff->etat = vide;
  else
    ff->etat = ok;

#ifdef OSIP_MT
  osip_mutex_unlock (ff->qislocked);
#endif
  return el;
}

void *
osip_fifo_tryget (osip_fifo_t * ff)
{
  void *el = NULL;

#ifdef OSIP_MT
  if (0 != osip_sem_trywait (ff->qisempty))
    {				/* no elements... */
      return NULL;
    }
  osip_mutex_lock (ff->qislocked);
#else
  if (ff->etat == vide)
    return NULL;
#endif

  if (ff->etat != vide)
    {
      el = osip_list_get (ff->queue, 0);
      osip_list_remove (ff->queue, 0);
      /* ff->nb_elt--; */
    }
#ifdef OSIP_MT
  else
    {				/* this case MUST never happen... */
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_INFO4, NULL,
		   "no element in fifo.\n"));
      osip_mutex_unlock (ff->qislocked);
      return 0;
    }
#endif

  /* if (ff->nb_elt <= 0) */
  if (osip_list_size (ff->queue) <= 0)
    ff->etat = vide;
  else
    ff->etat = ok;

#ifdef OSIP_MT
  osip_mutex_unlock (ff->qislocked);
#endif
  return el;
}

void
osip_fifo_free (osip_fifo_t * ff)
{
  if (ff == NULL)
    return;
#ifdef OSIP_MT
  osip_mutex_destroy (ff->qislocked);
  /* seems that pthread_mutex_destroy does not free space by itself */
  osip_sem_destroy (ff->qisempty);
#endif
  osip_free (ff->queue);
  osip_free (ff);
}
