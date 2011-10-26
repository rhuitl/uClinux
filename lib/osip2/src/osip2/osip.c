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

#include <osip2/internal.h>
#include <osip2/osip.h>

#include "fsm.h"
#include "xixt.h"

#ifdef OSIP_MT
static struct osip_mutex *ict_fastmutex;
static struct osip_mutex *ist_fastmutex;
static struct osip_mutex *nict_fastmutex;
static struct osip_mutex *nist_fastmutex;
#endif


#include <osip2/osip_dialog.h>
#ifdef OSIP_MT
static struct osip_mutex *ixt_fastmutex;
#endif

static int __osip_global_init (void);
static void __osip_global_free (void);
static int increase_ref_count (void);
static void decrease_ref_count (void);

static int
__osip_global_init ()
{
  /* load the fsm configuration */
  __ict_load_fsm ();
  __ist_load_fsm ();
  __nict_load_fsm ();
  __nist_load_fsm ();

  /* load the parser configuration */
  parser_init ();

#ifdef OSIP_MT
  ict_fastmutex = osip_mutex_init ();
  ist_fastmutex = osip_mutex_init ();
  nict_fastmutex = osip_mutex_init ();
  nist_fastmutex = osip_mutex_init ();

  ixt_fastmutex = osip_mutex_init ();

#endif
  return 0;
}

static void
__osip_global_free ()
{
  __ict_unload_fsm ();
  __ist_unload_fsm ();
  __nict_unload_fsm ();
  __nist_unload_fsm ();

#ifdef OSIP_MT
  osip_mutex_destroy (ict_fastmutex);
  osip_mutex_destroy (ist_fastmutex);
  osip_mutex_destroy (nict_fastmutex);
  osip_mutex_destroy (nist_fastmutex);

  osip_mutex_destroy (ixt_fastmutex);
#endif
}

void
osip_response_get_destination (osip_message_t * response, char **address,
			  int *portnum)
{
  osip_via_t *via;
  char *host = NULL;
  int port = 0;

  via = (osip_via_t *) osip_list_get (response->vias, 0);
  if (via)
    {
      osip_generic_param_t *maddr;
      osip_generic_param_t *received;
      osip_generic_param_t *rport;
      osip_via_param_get_byname (via, "maddr", &maddr);
      osip_via_param_get_byname (via, "received", &received);
      osip_via_param_get_byname (via, "rport", &rport);
      /* 1: user should not use the provided information
         (host and port) if they are using a reliable
         transport. Instead, they should use the already
         open socket attached to this transaction. */
      /* 2: check maddr and multicast usage */
      if (maddr != NULL)
	host = maddr->gvalue;
      /* we should check if this is a multicast address and use
         set the "ttl" in this case. (this must be done in the
         UDP message (not at the SIP layer) */
      else if (received != NULL)
	host = received->gvalue;
      else
	host = via->host;

      if (rport == NULL || rport->gvalue == NULL)
	{
	  if (via->port != NULL)
	    port = osip_atoi (via->port);
	  else
	    port = 5060;
	}
      else
	port = osip_atoi (rport->gvalue);
    }
  *portnum = port;
  if (host != NULL)
    *address = osip_strdup (host);
  else
    *address = NULL;
}


int
osip_ixt_lock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_lock (ixt_fastmutex);
#else
  return 0;
#endif
}

int
osip_ixt_unlock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_unlock (ixt_fastmutex);
#else
  return 0;
#endif
}

/* these are for transactions that would need retransmission not handled by state machines */
void
osip_add_ixt (osip_t * osip, ixt_t * ixt)
{
  /* ajout dans la liste de osip_t->ixt */
  osip_ixt_lock (osip);
  osip_list_add (osip->ixt_retransmissions, (void *) ixt, 0);
  osip_ixt_unlock (osip);
}

void
osip_remove_ixt (osip_t * osip, ixt_t * ixt)
{
  int i;
  int found = 0;
  ixt_t *tmp;
  /* ajout dans la liste de osip_t->ixt */
  osip_ixt_lock (osip);
  for (i = 0; !osip_list_eol (osip->ixt_retransmissions, i); i++)
    {
      tmp = (ixt_t *) osip_list_get (osip->ixt_retransmissions, i);
      if (tmp == ixt)
	{
	  osip_list_remove (osip->ixt_retransmissions, i);
	  found = 1;
	  break;
	}
    }
  osip_ixt_unlock (osip);
}

int
ixt_init (ixt_t ** ixt)
{
  ixt_t *pixt;
  *ixt = pixt = (ixt_t *) osip_malloc (sizeof (ixt_t));
  if (pixt==NULL) return -1;
  pixt->dialog = NULL;
  pixt->msg2xx = NULL;
  pixt->ack = NULL;
  pixt->start = time (NULL);
  pixt->interval = 500;
  pixt->counter = 7;
  pixt->dest = NULL;
  pixt->port = 5060;
  pixt->sock = -1;
  return 0;
}

void
ixt_free (ixt_t * ixt)
{
  osip_message_free (ixt->ack);
  osip_message_free (ixt->msg2xx);
  osip_free (ixt->dest);
  osip_free (ixt);
}

/* usefull for UAs */
void
osip_start_200ok_retransmissions (osip_t * osip, osip_dialog_t * dialog,
				  osip_message_t * msg200ok, int sock)
{
  ixt_t *ixt;
  ixt_init (&ixt);
  ixt->dialog = dialog;
  osip_message_clone (msg200ok, &ixt->msg2xx);
  ixt->sock = sock;
  osip_response_get_destination (msg200ok, &ixt->dest, &ixt->port);
  osip_add_ixt (osip, ixt);
}

void
osip_start_ack_retransmissions (osip_t * osip, osip_dialog_t * dialog,
				osip_message_t * ack, char *dest, int port,
				int sock)
{
  int i;
  ixt_t *ixt;
  i = ixt_init (&ixt);
  if (i != 0)
    return;
  ixt->dialog = dialog;
  osip_message_clone (ack, &ixt->ack);
  ixt->dest = osip_strdup (dest);
  ixt->port = port;
  ixt->sock = sock;
  osip_add_ixt (osip, ixt);
}

/* we stop the 200ok when receiving the corresponding ack */
struct osip_dialog *
osip_stop_200ok_retransmissions (osip_t * osip, osip_message_t * ack)
{
  osip_dialog_t *dialog = NULL;
  int i;
  ixt_t *ixt;
  osip_ixt_lock (osip);
  for (i = 0; !osip_list_eol (osip->ixt_retransmissions, i); i++)
    {
      ixt = (ixt_t *) osip_list_get (osip->ixt_retransmissions, i);
      if (osip_dialog_match_as_uas (ixt->dialog, ack) == 0)
	{
	  osip_list_remove (osip->ixt_retransmissions, i);
	  ixt_free (ixt);
	  dialog = ixt->dialog;
	  break;
	}
    }
  osip_ixt_unlock (osip);
  return dialog;
}

/* when a dialog is destroyed by the application,
   it is safer to remove all ixt that are related to it */
void
osip_stop_retransmissions_from_dialog (osip_t * osip, osip_dialog_t * dialog)
{
  int i;
  ixt_t *ixt;
  osip_ixt_lock (osip);
  for (i = 0; !osip_list_eol (osip->ixt_retransmissions, i); i++)
    {
      ixt = (ixt_t *) osip_list_get (osip->ixt_retransmissions, i);
      if (ixt->dialog == dialog)
	{
	  osip_list_remove (osip->ixt_retransmissions, i);
	  ixt_free (ixt);
	  i--;
	}
    }
  osip_ixt_unlock (osip);
}

void
ixt_retransmit (osip_t * osip, ixt_t * ixt, time_t current)
{
  if ((current - ixt->start) * 1000 > ixt->interval)
    {
      ixt->interval = ixt->interval * 2;
      ixt->start = current;
      if (ixt->ack != NULL)
	osip->cb_send_message (NULL, ixt->ack,
			       ixt->dest, ixt->port, ixt->sock);
      else if (ixt->msg2xx != NULL)
	osip->cb_send_message (NULL, ixt->msg2xx,
			       ixt->dest, ixt->port, ixt->sock);
      ixt->counter--;
    }
}

void
osip_retransmissions_execute (osip_t * osip)
{
  int i;
  time_t current;
  ixt_t *ixt;
  current = time (NULL);
  osip_ixt_lock (osip);
  for (i = 0; !osip_list_eol (osip->ixt_retransmissions, i); i++)
    {
      ixt = (ixt_t *) osip_list_get (osip->ixt_retransmissions, i);
      ixt_retransmit (osip, ixt, current);
      if (ixt->counter == 0)
	{
	  /* remove it */
	  osip_list_remove (osip->ixt_retransmissions, i);
	  ixt_free (ixt);
	  i--;
	}
    }
  osip_ixt_unlock (osip);
}

int
osip_ict_lock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_lock (ict_fastmutex);
#else
  return 0;
#endif
}

int
osip_ict_unlock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_unlock (ict_fastmutex);
#else
  return 0;
#endif
}

int
osip_ist_lock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_lock (ist_fastmutex);
#else
  return 0;
#endif
}

int
osip_ist_unlock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_unlock (ist_fastmutex);
#else
  return 0;
#endif
}

int
osip_nict_lock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_lock (nict_fastmutex);
#else
  return 0;
#endif
}

int
osip_nict_unlock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_unlock (nict_fastmutex);
#else
  return 0;
#endif
}

int
osip_nist_lock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_lock (nist_fastmutex);
#else
  return 0;
#endif
}

int
osip_nist_unlock (osip_t * osip)
{
#ifdef OSIP_MT
  return osip_mutex_unlock (nist_fastmutex);
#else
  return 0;
#endif
}

int
__osip_add_ict (osip_t * osip, osip_transaction_t * ict)
{
#ifdef OSIP_MT
  osip_mutex_lock (ict_fastmutex);
#endif
  osip_list_add (osip->osip_ict_transactions, ict, -1);
#ifdef OSIP_MT
  osip_mutex_unlock (ict_fastmutex);
#endif
  return 0;
}

int
__osip_add_ist (osip_t * osip, osip_transaction_t * ist)
{
#ifdef OSIP_MT
  osip_mutex_lock (ist_fastmutex);
#endif
  osip_list_add (osip->osip_ist_transactions, ist, -1);
#ifdef OSIP_MT
  osip_mutex_unlock (ist_fastmutex);
#endif
  return 0;
}

int
__osip_add_nict (osip_t * osip, osip_transaction_t * nict)
{
#ifdef OSIP_MT
  osip_mutex_lock (nict_fastmutex);
#endif
  osip_list_add (osip->osip_nict_transactions, nict, -1);
#ifdef OSIP_MT
  osip_mutex_unlock (nict_fastmutex);
#endif
  return 0;
}

int
__osip_add_nist (osip_t * osip, osip_transaction_t * nist)
{
#ifdef OSIP_MT
  osip_mutex_lock (nist_fastmutex);
#endif
  osip_list_add (osip->osip_nist_transactions, nist, -1);
#ifdef OSIP_MT
  osip_mutex_unlock (nist_fastmutex);
#endif
  return 0;
}

int
osip_remove_transaction (osip_t * osip, osip_transaction_t * tr)
{
  int i = -1;
  if (tr == NULL)
    return -1;
  if (tr->ctx_type == ICT)
    i = __osip_remove_ict_transaction (osip, tr);
  else if (tr->ctx_type == IST)
    i = __osip_remove_ist_transaction (osip, tr);
  else if (tr->ctx_type == NICT)
    i = __osip_remove_nict_transaction (osip, tr);
  else if (tr->ctx_type == NIST)
    i = __osip_remove_nist_transaction (osip, tr);
  else
    return -1;
  return i;
}

int
__osip_remove_ict_transaction (osip_t * osip, osip_transaction_t * ict)
{
  int pos = 0;
  osip_transaction_t *tmp;

#ifdef OSIP_MT
  osip_mutex_lock (ict_fastmutex);
#endif
  while (!osip_list_eol (osip->osip_ict_transactions, pos))
    {
      tmp = osip_list_get (osip->osip_ict_transactions, pos);
      if (tmp->transactionid == ict->transactionid)
	{
	  osip_list_remove (osip->osip_ict_transactions, pos);
#ifdef OSIP_MT
	  osip_mutex_unlock (ict_fastmutex);
#endif
	  return 0;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ict_fastmutex);
#endif
  return -1;
}

int
__osip_remove_ist_transaction (osip_t * osip, osip_transaction_t * ist)
{
  int pos = 0;
  osip_transaction_t *tmp;

#ifdef OSIP_MT
  osip_mutex_lock (ist_fastmutex);
#endif
  while (!osip_list_eol (osip->osip_ist_transactions, pos))
    {
      tmp = osip_list_get (osip->osip_ist_transactions, pos);
      if (tmp->transactionid == ist->transactionid)
	{
	  osip_list_remove (osip->osip_ist_transactions, pos);
#ifdef OSIP_MT
	  osip_mutex_unlock (ist_fastmutex);
#endif
	  return 0;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ist_fastmutex);
#endif
  return -1;
}

int
__osip_remove_nict_transaction (osip_t * osip, osip_transaction_t * nict)
{
  int pos = 0;
  osip_transaction_t *tmp;

#ifdef OSIP_MT
  osip_mutex_lock (nict_fastmutex);
#endif
  while (!osip_list_eol (osip->osip_nict_transactions, pos))
    {
      tmp = osip_list_get (osip->osip_nict_transactions, pos);
      if (tmp->transactionid == nict->transactionid)
	{
	  osip_list_remove (osip->osip_nict_transactions, pos);
#ifdef OSIP_MT
	  osip_mutex_unlock (nict_fastmutex);
#endif
	  return 0;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (nict_fastmutex);
#endif
  return -1;
}

int
__osip_remove_nist_transaction (osip_t * osip, osip_transaction_t * nist)
{
  int pos = 0;
  osip_transaction_t *tmp;

#ifdef OSIP_MT
  osip_mutex_lock (nist_fastmutex);
#endif
  while (!osip_list_eol (osip->osip_nist_transactions, pos))
    {
      tmp = osip_list_get (osip->osip_nist_transactions, pos);
      if (tmp->transactionid == nist->transactionid)
	{
	  osip_list_remove (osip->osip_nist_transactions, pos);
#ifdef OSIP_MT
	  osip_mutex_unlock (nist_fastmutex);
#endif
	  return 0;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (nist_fastmutex);
#endif
  return -1;
}

#if 0
/* this method is made obsolete because it contains bugs and is also
   too much limited.
   any call to this method should be replace this way:

   //osip_distribute(osip, evt);
   int i = osip_find_transaction_and_add_event(osip, evt);

   if (i!=0) // in case it's a new request
     {
        if (evt is an ACK)
            evt could be an ACK for INVITE (not handled by oSIP)
        else if ( evt is a 200 for INVITE)
           evt could be a retransmission of a 200 for INVITE (not handled by oSIP)
        else if (evt is a new request)  == not a ACK and not a response
	  {
           transaction = osip_create_transaction(osip, evt);
           if (transaction==NULL)
             printf("failed to create a transaction\");
          }
    }
    else
    {
    // here, the message as been taken by the stack.
    }
*/


/* finds the transaction context and add the sipevent in its fifo. */
/* USED ONLY BY THE TRANSPORT LAYER.                               */
/* INPUT : osip_t *osip | osip. contains the list of tr. context*/
/* INPUT : osip_event_t* sipevent | event to dispatch.               */
osip_transaction_t *
osip_distribute_event (osip_t * osip, osip_event_t * evt)
{
  osip_transaction_t *transaction = NULL;
  int i;
  osip_fsm_type_t ctx_type;

  if (EVT_IS_INCOMINGMSG (evt))
    {
      /* event is for ict */
      if (MSG_IS_REQUEST (evt->sip))
	{
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE")
	      || 0 == strcmp (evt->sip->cseq->method, "ACK"))
	    {
#ifdef OSIP_MT
	      osip_mutex_lock (ist_fastmutex);
#endif
	      transaction =
		osip_transaction_find (osip->osip_ist_transactions, evt);
#ifdef OSIP_MT
	      osip_mutex_unlock (ist_fastmutex);
#endif
	    }
	  else
	    {
#ifdef OSIP_MT
	      osip_mutex_lock (nist_fastmutex);
#endif
	      transaction =
		osip_transaction_find (osip->osip_nist_transactions, evt);
#ifdef OSIP_MT
	      osip_mutex_unlock (nist_fastmutex);
#endif
	    }
	}
      else
	{
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE")
	      || 0 == strcmp (evt->sip->cseq->method, "ACK"))
	    {
#ifdef OSIP_MT
	      osip_mutex_lock (ict_fastmutex);
#endif
	      transaction =
		osip_transaction_find (osip->osip_ict_transactions, evt);
#ifdef OSIP_MT
	      osip_mutex_unlock (ict_fastmutex);
#endif
	    }
	  else
	    {
#ifdef OSIP_MT
	      osip_mutex_lock (nict_fastmutex);
#endif
	      transaction =
		osip_transaction_find (osip->osip_nict_transactions, evt);
#ifdef OSIP_MT
	      osip_mutex_unlock (nict_fastmutex);
#endif
	    }
	}
      if (transaction == NULL)
	{
	  if (EVT_IS_RCV_STATUS_1XX (evt)
	      || EVT_IS_RCV_STATUS_2XX (evt)
	      || EVT_IS_RCV_STATUS_3456XX (evt) || EVT_IS_RCV_ACK (evt))
	    {			/* event MUST be ignored! */
	      /* EXCEPT FOR 2XX THAT MUST BE GIVEN TO THE CORE LAYER!!! */

	      /* TODO */

	      OSIP_TRACE (osip_trace
			  (__FILE__, __LINE__, OSIP_WARNING, NULL,
			   "transaction does not yet exist... %x callid:%s\n",
			   evt, evt->sip->call_id->number));
	      osip_message_free (evt->sip);
	      osip_free (evt);	/* transaction thread will not delete it */
	      return NULL;
	    }

	  /* we create a new context for this incoming request */
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE"))
	    ctx_type = IST;
	  else
	    ctx_type = NIST;

	  i = osip_transaction_init (&transaction, ctx_type, osip, evt->sip);
	  if (i == -1)
	    {
	      osip_message_free (evt->sip);
	      osip_free (evt);	/* transaction thread will not delete it */
	      return NULL;
	    }
	}
      evt->transactionid = transaction->transactionid;

      evt->transactionid = transaction->transactionid;
      osip_fifo_add (transaction->transactionff, evt);
      return transaction;
    }
  else
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_BUG, NULL,
		   "wrong event type %x\n", evt));
      return NULL;
    }
}
#endif

int
osip_find_transaction_and_add_event (osip_t * osip, osip_event_t * evt)
{
  osip_transaction_t *transaction = __osip_find_transaction (osip, evt, 1);

  if (transaction == NULL)
    return -1;
  return 0;
}

#ifndef OSIP_MT
osip_transaction_t *
osip_find_transaction (osip_t * osip, osip_event_t * evt)
{
  return __osip_find_transaction (osip, evt, 0);
}
#endif

osip_transaction_t *
__osip_find_transaction (osip_t * osip, osip_event_t * evt, int consume)
{
  osip_transaction_t *transaction = NULL;
  osip_list_t *transactions = NULL;

#ifdef OSIP_MT
  struct osip_mutex *mut = NULL;
#endif

  if (evt == NULL || evt->sip == NULL || evt->sip->cseq == NULL)
    return NULL;

  if (EVT_IS_INCOMINGMSG (evt))
    {
      if (MSG_IS_REQUEST (evt->sip))
	{
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE")
	      || 0 == strcmp (evt->sip->cseq->method, "ACK"))
	    {
	      transactions = osip->osip_ist_transactions;
#ifdef OSIP_MT
	      mut = ist_fastmutex;
#endif
	    }
	  else
	    {
	      transactions = osip->osip_nist_transactions;
#ifdef OSIP_MT
	      mut = nist_fastmutex;
#endif
	    }
	}
      else
	{
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE"))
	    {
	      transactions = osip->osip_ict_transactions;
#ifdef OSIP_MT
	      mut = ict_fastmutex;
#endif
	    }
	  else
	    {
	      transactions = osip->osip_nict_transactions;
#ifdef OSIP_MT
	      mut = nict_fastmutex;
#endif
	    }
	}
    }
  else if (EVT_IS_OUTGOINGMSG (evt))
    {
      if (MSG_IS_RESPONSE (evt->sip))
	{
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE"))
	    {
	      transactions = osip->osip_ist_transactions;
#ifdef OSIP_MT
	      mut = ist_fastmutex;
#endif
	    }
	  else
	    {
	      transactions = osip->osip_nist_transactions;
#ifdef OSIP_MT
	      mut = nist_fastmutex;
#endif
	    }
	}
      else
	{
	  if (0 == strcmp (evt->sip->cseq->method, "INVITE")
	      || 0 == strcmp (evt->sip->cseq->method, "ACK"))
	    {
	      transactions = osip->osip_ict_transactions;
#ifdef OSIP_MT
	      mut = ict_fastmutex;
#endif
	    }
	  else
	    {
	      transactions = osip->osip_nict_transactions;
#ifdef OSIP_MT
	      mut = nict_fastmutex;
#endif
	    }
	}
    }
  if (transactions == NULL)
    return NULL;		/* not a message??? */

#ifdef OSIP_MT
  osip_mutex_lock (mut);
#endif
  transaction = osip_transaction_find (transactions, evt);
  if (consume == 1)
    {				/* we add the event before releasing the mutex!! */
      if (transaction != NULL)
	{
	  osip_transaction_add_event (transaction, evt);
#ifdef OSIP_MT
	  osip_mutex_unlock (mut);
#endif
	  return transaction;
	}
    }
#ifdef OSIP_MT
  osip_mutex_unlock (mut);
#endif

  return transaction;
}

osip_transaction_t *
osip_create_transaction (osip_t * osip, osip_event_t * evt)
{
  osip_transaction_t *transaction;
  int i;
  osip_fsm_type_t ctx_type;

  if (evt == NULL)
    return NULL;
  if (evt->sip == NULL)
    return NULL;

  /* make sure the request's method reflect the cseq value. */
  if (MSG_IS_REQUEST (evt->sip))
    {
      /* delete request where cseq method does not match
         the method in request-line */
      if (evt->sip->cseq == NULL
	  || evt->sip->cseq->method == NULL || evt->sip->sip_method == NULL)
	{
	  return NULL;
	}
      if (0 != strcmp (evt->sip->cseq->method, evt->sip->sip_method))
	{
	  OSIP_TRACE (osip_trace
		      (__FILE__, __LINE__, OSIP_WARNING, NULL,
		       "core module: Discard invalid message with method!=cseq!\n"));
	  return NULL;
	}
    }

  if (MSG_IS_ACK (evt->sip))	/* ACK never create transactions */
    return NULL;

  if (EVT_IS_INCOMINGREQ (evt))
    {
      /* we create a new context for this incoming request */
      if (0 == strcmp (evt->sip->cseq->method, "INVITE"))
	ctx_type = IST;
      else
	ctx_type = NIST;
    }
  else if (EVT_IS_OUTGOINGREQ (evt))
    {
      if (0 == strcmp (evt->sip->cseq->method, "INVITE"))
	ctx_type = ICT;
      else
	ctx_type = NICT;
    }
  else
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "Cannot build a transction for this message!\n"));
      return NULL;
    }

  i = osip_transaction_init (&transaction, ctx_type, osip, evt->sip);
  if (i == -1)
    {
      return NULL;
    }
  evt->transactionid = transaction->transactionid;
  return transaction;
}

osip_transaction_t *
osip_transaction_find (osip_list_t * transactions, osip_event_t * evt)
{
  int pos = 0;
  osip_transaction_t *transaction;

  if (EVT_IS_INCOMINGREQ (evt))
    {
      while (!osip_list_eol (transactions, pos))
	{
	  transaction =
	    (osip_transaction_t *) osip_list_get (transactions, pos);
	  if (0 ==
	      __osip_transaction_matching_request_osip_to_xist_17_2_3
	      (transaction, evt->sip))
	    return transaction;
	  pos++;
	}
    }
  else if (EVT_IS_INCOMINGRESP (evt))
    {
      while (!osip_list_eol (transactions, pos))
	{
	  transaction =
	    (osip_transaction_t *) osip_list_get (transactions, pos);
	  if (0 ==
	      __osip_transaction_matching_response_osip_to_xict_17_1_3
	      (transaction, evt->sip))
	    return transaction;
	  pos++;
	}
    }
  else				/* handle OUTGOING message */
    {				/* THE TRANSACTION ID MUST BE SET */
      while (!osip_list_eol (transactions, pos))
	{
	  transaction =
	    (osip_transaction_t *) osip_list_get (transactions, pos);
	  if (transaction->transactionid == evt->transactionid)
	    return transaction;
	  pos++;
	}
    }
  return NULL;
}

static int ref_count = 0;
#ifdef OSIP_MT
static struct osip_mutex *ref_mutex = NULL;
#endif

static int
increase_ref_count (void)
{
#ifdef OSIP_MT
  if (ref_count == 0)
    ref_mutex = osip_mutex_init ();
  /* Here we should assert() that the mutex was really generated. */
  osip_mutex_lock (ref_mutex);
#endif
  if (ref_count == 0)
    __osip_global_init ();
  ref_count++;
#ifdef OSIP_MT
  osip_mutex_unlock (ref_mutex);
#endif

  return 0;
}

static void
decrease_ref_count (void)
{
#ifdef OSIP_MT
  osip_mutex_lock (ref_mutex);
#endif
  /* assert (ref_count > 0); */
  ref_count--;
  if (ref_count == 0)
    {
#ifdef OSIP_MT
      osip_mutex_unlock (ref_mutex);
      osip_mutex_destroy (ref_mutex);
#endif
      __osip_global_free ();
      return;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ref_mutex);
#endif
}

int
osip_init (osip_t ** osip)
{
  if (increase_ref_count () != 0)
    return -1;

  *osip = (osip_t *) osip_malloc (sizeof (osip_t));
  if (*osip == NULL)
    return -1;			/* allocation failed */

  memset (*osip, 0, sizeof (osip_t));

  (*osip)->osip_ict_transactions =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*osip)->osip_ict_transactions);
  (*osip)->osip_ist_transactions =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*osip)->osip_ist_transactions);
  (*osip)->osip_nict_transactions =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*osip)->osip_nict_transactions);
  (*osip)->osip_nist_transactions =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*osip)->osip_nist_transactions);

  (*osip)->ixt_retransmissions =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*osip)->ixt_retransmissions);

  return 0;
}

void
osip_release (osip_t * osip)
{
  osip_free (osip->osip_ict_transactions);
  osip_free (osip->osip_ist_transactions);
  osip_free (osip->osip_nict_transactions);
  osip_free (osip->osip_nist_transactions);

  osip_free (osip->ixt_retransmissions);

  osip_free (osip);
  decrease_ref_count ();
}


void
osip_set_application_context (osip_t * osip, void *pointer)
{
  osip->application_context = pointer;
}

void *
osip_get_application_context (osip_t * osip)
{
  if (osip == NULL)
    return NULL;
  return osip->application_context;
}

int
osip_ict_execute (osip_t * osip)
{
  osip_transaction_t *transaction;
  osip_event_t *se;
  int more_event;
  int tr;

  tr = 0;
  while (!osip_list_eol (osip->osip_ict_transactions, tr))
    {
      transaction = osip_list_get (osip->osip_ict_transactions, tr);
      tr++;
      more_event = 1;
      do
	{
	  se = (osip_event_t *) osip_fifo_tryget (transaction->transactionff);
	  if (se == NULL)	/* no more event for this transaction */
	    more_event = 0;
	  else
	    osip_transaction_execute (transaction, se);
	}
      while (more_event == 1);
    }
  return 0;
}

int
osip_ist_execute (osip_t * osip)
{
  osip_transaction_t *transaction;
  osip_event_t *se;
  int more_event;
  int tr;

  tr = 0;
  while (!osip_list_eol (osip->osip_ist_transactions, tr))
    {
      transaction = osip_list_get (osip->osip_ist_transactions, tr);
      tr++;
      more_event = 1;
      do
	{
	  se = (osip_event_t *) osip_fifo_tryget (transaction->transactionff);
	  if (se == NULL)	/* no more event for this transaction */
	    more_event = 0;
	  else
	    osip_transaction_execute (transaction, se);
	}
      while (more_event == 1);
    }
  return 0;
}

int
osip_nict_execute (osip_t * osip)
{
  osip_transaction_t *transaction;
  osip_event_t *se;
  int more_event;
  int tr;

  tr = 0;
  while (!osip_list_eol (osip->osip_nict_transactions, tr))
    {
      transaction = osip_list_get (osip->osip_nict_transactions, tr);
      tr++;
      more_event = 1;
      do
	{
	  se = (osip_event_t *) osip_fifo_tryget (transaction->transactionff);
	  if (se == NULL)	/* no more event for this transaction */
	    more_event = 0;
	  else
	    osip_transaction_execute (transaction, se);
	}
      while (more_event == 1);
    }
  return 0;
}

int
osip_nist_execute (osip_t * osip)
{
  osip_transaction_t *transaction;
  osip_event_t *se;
  int more_event;
  int tr;

  tr = 0;
  while (!osip_list_eol (osip->osip_nist_transactions, tr))
    {
      transaction = osip_list_get (osip->osip_nist_transactions, tr);
      tr++;
      more_event = 1;
      do
	{
	  se = (osip_event_t *) osip_fifo_tryget (transaction->transactionff);
	  if (se == NULL)	/* no more event for this transaction */
	    more_event = 0;
	  else
	    osip_transaction_execute (transaction, se);
	}
      while (more_event == 1);
    }
  return 0;
}

void
osip_timers_gettimeout (osip_t * osip, struct timeval *lower_tv)
{
  struct timeval now;
  osip_transaction_t *tr;
  int pos = 0;

  osip_gettimeofday (&now, NULL);
  lower_tv->tv_sec = now.tv_sec + 3600 * 24 * 365;	/* wake up evry year :-) */
  lower_tv->tv_usec = now.tv_usec;

#ifdef OSIP_MT
  osip_mutex_lock (ict_fastmutex);
#endif
  /* handle ict timers */
  while (!osip_list_eol (osip->osip_ict_transactions, pos))
    {
      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_ict_transactions,
					      pos);

      if (1 <= osip_fifo_size (tr->transactionff))
	{
	  OSIP_TRACE (osip_trace
		      (__FILE__, __LINE__, OSIP_INFO4, NULL,
		       "1 Pending event already in transaction !\n"));
	  lower_tv->tv_sec = 0;
	  lower_tv->tv_usec = 0;
#ifdef OSIP_MT
	  osip_mutex_unlock (ict_fastmutex);
#endif
	  return;
	}
      else
	{
	  if (tr->state == ICT_CALLING)
	    min_timercmp (lower_tv, &tr->ict_context->timer_b_start);
	  if (tr->state == ICT_CALLING)
	    min_timercmp (lower_tv, &tr->ict_context->timer_a_start);
	  if (tr->state == ICT_COMPLETED)
	    min_timercmp (lower_tv, &tr->ict_context->timer_d_start);
	  if (osip_timercmp (&now, lower_tv, >))
	    {
	      lower_tv->tv_sec = 0;
	      lower_tv->tv_usec = 0;
#ifdef OSIP_MT
	      osip_mutex_unlock (ict_fastmutex);
#endif
	      return;
	    }
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ict_fastmutex);
#endif

#ifdef OSIP_MT
  osip_mutex_lock (ist_fastmutex);
#endif
  /* handle ist timers */
  pos = 0;
  while (!osip_list_eol (osip->osip_ist_transactions, pos))
    {
      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_ist_transactions,
					      pos);

      if (tr->state == IST_CONFIRMED)
	min_timercmp (lower_tv, &tr->ist_context->timer_i_start);
      if (tr->state == IST_COMPLETED)
	min_timercmp (lower_tv, &tr->ist_context->timer_h_start);
      if (tr->state == IST_COMPLETED)
	min_timercmp (lower_tv, &tr->ist_context->timer_g_start);
      if (osip_timercmp (&now, lower_tv, >))
	{
	  lower_tv->tv_sec = 0;
	  lower_tv->tv_usec = 0;
#ifdef OSIP_MT
	  osip_mutex_unlock (ist_fastmutex);
#endif
	  return;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ist_fastmutex);
#endif

#ifdef OSIP_MT
  osip_mutex_lock (nict_fastmutex);
#endif
  /* handle nict timers */
  pos = 0;
  while (!osip_list_eol (osip->osip_nict_transactions, pos))
    {
      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_nict_transactions,
					      pos);

      if (tr->state == NICT_COMPLETED)
	min_timercmp (lower_tv, &tr->nict_context->timer_k_start);
      if (tr->state == NICT_PROCEEDING || tr->state == NICT_TRYING)
	min_timercmp (lower_tv, &tr->nict_context->timer_f_start);
      if (tr->state == NICT_PROCEEDING || tr->state == NICT_TRYING)
	min_timercmp (lower_tv, &tr->nict_context->timer_e_start);
      if (osip_timercmp (&now, lower_tv, >))
	{
	  lower_tv->tv_sec = 0;
	  lower_tv->tv_usec = 0;
#ifdef OSIP_MT
	  osip_mutex_unlock (nict_fastmutex);
#endif
	  return;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (nict_fastmutex);
#endif

#ifdef OSIP_MT
  osip_mutex_lock (nist_fastmutex);
#endif
  /* handle nist timers */
  pos = 0;
  while (!osip_list_eol (osip->osip_nist_transactions, pos))
    {
      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_nist_transactions,
					      pos);

      if (tr->state == NIST_COMPLETED)
	min_timercmp (lower_tv, &tr->nist_context->timer_j_start);
      if (osip_timercmp (&now, lower_tv, >))
	{
	  lower_tv->tv_sec = 0;
	  lower_tv->tv_usec = 0;
#ifdef OSIP_MT
	  osip_mutex_unlock (nist_fastmutex);
#endif
	  return;
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (nist_fastmutex);
#endif

#ifdef OSIP_MT
  osip_mutex_lock(ixt_fastmutex);
#endif
 {
   ixt_t *ixt;
   for (pos = 0; (ixt = (ixt_t *) osip_list_get(osip->ixt_retransmissions,
						pos))!=NULL; ++pos)
     {
       struct timeval cmpTime;
       div_t dValue = div(ixt->interval, 1000);
       cmpTime.tv_sec = ixt->start + dValue.quot;
       cmpTime.tv_usec = dValue.rem * 1000;
       min_timercmp(lower_tv, &cmpTime);
     }
 }
#ifdef OSIP_MT
  osip_mutex_unlock (ixt_fastmutex);
#endif
  
  lower_tv->tv_sec = lower_tv->tv_sec - now.tv_sec;
  lower_tv->tv_usec = lower_tv->tv_usec - now.tv_usec;

  /* just make sure the value is correct! */
  if (lower_tv->tv_usec < 0)
    {
      lower_tv->tv_usec = lower_tv->tv_usec + 1000000;
      lower_tv->tv_sec--;
    }
  if (lower_tv->tv_sec < 0)
    {
      lower_tv->tv_sec = 0;
      lower_tv->tv_usec = 0;
    }
  if (lower_tv->tv_usec > 1000000)
    {
      lower_tv->tv_usec = lower_tv->tv_usec - 1000000;
      lower_tv->tv_sec++;
    }
  return;
}

void
osip_timers_ict_execute (osip_t * osip)
{
  osip_transaction_t *tr;
  int pos = 0;

#ifdef OSIP_MT
  osip_mutex_lock (ict_fastmutex);
#endif
  /* handle ict timers */
  while (!osip_list_eol (osip->osip_ict_transactions, pos))
    {
      osip_event_t *evt;

      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_ict_transactions,
					      pos);

      if (1 <= osip_fifo_size (tr->transactionff))
	{
	  OSIP_TRACE (osip_trace
		      (__FILE__, __LINE__, OSIP_INFO4, NULL,
		       "1 Pending event already in transaction !\n"));
	}
      else
	{
	  evt = __osip_ict_need_timer_b_event (tr->ict_context, tr->state,
					       tr->transactionid);
	  if (evt != NULL)
	    osip_fifo_add (tr->transactionff, evt);
	  else
	    {
	      evt = __osip_ict_need_timer_a_event (tr->ict_context, tr->state,
						   tr->transactionid);
	      if (evt != NULL)
		osip_fifo_add (tr->transactionff, evt);
	      else
		{
		  evt =
		    __osip_ict_need_timer_d_event (tr->ict_context, tr->state,
						   tr->transactionid);
		  if (evt != NULL)
		    osip_fifo_add (tr->transactionff, evt);
		}
	    }
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ict_fastmutex);
#endif
}

void
osip_timers_ist_execute (osip_t * osip)
{
  osip_transaction_t *tr;
  int pos = 0;

#ifdef OSIP_MT
  osip_mutex_lock (ist_fastmutex);
#endif
  /* handle ist timers */
  while (!osip_list_eol (osip->osip_ist_transactions, pos))
    {
      osip_event_t *evt;

      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_ist_transactions,
					      pos);

      evt = __osip_ist_need_timer_i_event (tr->ist_context, tr->state,
					   tr->transactionid);
      if (evt != NULL)
	osip_fifo_add (tr->transactionff, evt);
      else
	{
	  evt = __osip_ist_need_timer_h_event (tr->ist_context, tr->state,
					       tr->transactionid);
	  if (evt != NULL)
	    osip_fifo_add (tr->transactionff, evt);
	  else
	    {
	      evt = __osip_ist_need_timer_g_event (tr->ist_context, tr->state,
						   tr->transactionid);
	      if (evt != NULL)
		osip_fifo_add (tr->transactionff, evt);
	    }
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (ist_fastmutex);
#endif
}

void
osip_timers_nict_execute (osip_t * osip)
{
  osip_transaction_t *tr;
  int pos = 0;

#ifdef OSIP_MT
  osip_mutex_lock (nict_fastmutex);
#endif
  /* handle nict timers */
  while (!osip_list_eol (osip->osip_nict_transactions, pos))
    {
      osip_event_t *evt;

      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_nict_transactions,
					      pos);

      evt = __osip_nict_need_timer_k_event (tr->nict_context, tr->state,
					    tr->transactionid);
      if (evt != NULL)
	osip_fifo_add (tr->transactionff, evt);
      else
	{
	  evt = __osip_nict_need_timer_f_event (tr->nict_context, tr->state,
						tr->transactionid);
	  if (evt != NULL)
	    osip_fifo_add (tr->transactionff, evt);
	  else
	    {
	      evt =
		__osip_nict_need_timer_e_event (tr->nict_context, tr->state,
						tr->transactionid);
	      if (evt != NULL)
		osip_fifo_add (tr->transactionff, evt);
	    }
	}
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (nict_fastmutex);
#endif
}


void
osip_timers_nist_execute (osip_t * osip)
{
  osip_transaction_t *tr;
  int pos = 0;

#ifdef OSIP_MT
  osip_mutex_lock (nist_fastmutex);
#endif
  /* handle nist timers */
  while (!osip_list_eol (osip->osip_nist_transactions, pos))
    {
      osip_event_t *evt;

      tr =
	(osip_transaction_t *) osip_list_get (osip->osip_nist_transactions,
					      pos);

      evt = __osip_nist_need_timer_j_event (tr->nist_context, tr->state,
					    tr->transactionid);
      if (evt != NULL)
	osip_fifo_add (tr->transactionff, evt);
      pos++;
    }
#ifdef OSIP_MT
  osip_mutex_unlock (nist_fastmutex);
#endif
}

void
osip_set_cb_send_message (osip_t * cf,
			  int (*cb) (osip_transaction_t *, osip_message_t *,
				     char *, int, int))
{
  cf->cb_send_message = cb;
}

void
__osip_message_callback (int type, osip_transaction_t * tr,
			 osip_message_t * msg)
{
  osip_t *config = tr->config;

  if (type >= OSIP_MESSAGE_CALLBACK_COUNT)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_BUG, NULL,
		   "invalid callback type %d\n", type));
      return;
    }
  if (config->msg_callbacks[type] == NULL)
    return;
  config->msg_callbacks[type] (type, tr, msg);
}

void
__osip_kill_transaction_callback (int type, osip_transaction_t * tr)
{
  osip_t *config = tr->config;

  if (type >= OSIP_KILL_CALLBACK_COUNT)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_BUG, NULL,
		   "invalid callback type %d\n", type));
      return;
    }
  if (config->kill_callbacks[type] == NULL)
    return;
  config->kill_callbacks[type] (type, tr);
}

void
__osip_transport_error_callback (int type, osip_transaction_t * tr, int error)
{
  osip_t *config = tr->config;

  if (type >= OSIP_TRANSPORT_ERROR_CALLBACK_COUNT)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_BUG, NULL,
		   "invalid callback type %d\n", type));
      return;
    }
  if (config->tp_error_callbacks[type] == NULL)
    return;
  config->tp_error_callbacks[type] (type, tr, error);
}


int
osip_set_message_callback (osip_t * config, int type, osip_message_cb_t cb)
{
  if (type >= OSIP_MESSAGE_CALLBACK_COUNT)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "invalid callback type %d\n", type));
      return -1;
    }
  config->msg_callbacks[type] = cb;

  return 0;
}

int
osip_set_kill_transaction_callback (osip_t * config, int type,
				    osip_kill_transaction_cb_t cb)
{
  if (type >= OSIP_KILL_CALLBACK_COUNT)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "invalid callback type %d\n", type));
      return -1;
    }
  config->kill_callbacks[type] = cb;
  return 0;
}

int
osip_set_transport_error_callback (osip_t * config, int type,
				   osip_transport_error_cb_t cb)
{
  if (type >= OSIP_TRANSPORT_ERROR_CALLBACK_COUNT)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "invalid callback type %d\n", type));
      return -1;
    }
  config->tp_error_callbacks[type] = cb;
  return 0;
}
