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

osip_statemachine_t *nist_fsm;

osip_statemachine_t *
__nist_get_fsm ()
{
  return nist_fsm;
}

void
__nist_unload_fsm ()
{
  transition_t *transition;
  osip_statemachine_t *statemachine = __nist_get_fsm ();

  while (!osip_list_eol (statemachine->transitions, 0))
    {
      transition =
	(transition_t *) osip_list_get (statemachine->transitions, 0);
      osip_list_remove (statemachine->transitions, 0);
      osip_free (transition);
    }
  osip_free (statemachine->transitions);
  osip_free (statemachine);
}


void
__nist_load_fsm ()
{
  transition_t *transition;

  nist_fsm =
    (osip_statemachine_t *) osip_malloc (sizeof (osip_statemachine_t));
  nist_fsm->transitions = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init (nist_fsm->transitions);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_PRE_TRYING;
  transition->type = RCV_REQUEST;
  transition->method = (void (*)(void *, void *)) &nist_rcv_request;
  osip_list_add (nist_fsm->transitions, transition, -1);

  /* This can be used to announce request but is useless, as
     the transaction cannot send any response yet!
     transition         = (transition_t *) osip_malloc(sizeof(transition_t));
     transition->state  = NIST_TRYING;
     transition->type   = RCV_REQUEST;
     transition->method = (void(*)(void *,void *))&nist_rcv_request;
     osip_list_add(nist_fsm->transitions,transition,-1);
   */

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_TRYING;
  transition->type = SND_STATUS_1XX;
  transition->method = (void (*)(void *, void *)) &nist_snd_1xx;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_TRYING;
  transition->type = SND_STATUS_2XX;
  transition->method = (void (*)(void *, void *)) &nist_snd_23456xx;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_TRYING;
  transition->type = SND_STATUS_3456XX;
  transition->method = (void (*)(void *, void *)) &nist_snd_23456xx;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_PROCEEDING;
  transition->type = SND_STATUS_1XX;
  transition->method = (void (*)(void *, void *)) &nist_snd_1xx;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_PROCEEDING;
  transition->type = SND_STATUS_2XX;
  transition->method = (void (*)(void *, void *)) &nist_snd_23456xx;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_PROCEEDING;
  transition->type = SND_STATUS_3456XX;
  transition->method = (void (*)(void *, void *)) &nist_snd_23456xx;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_PROCEEDING;
  transition->type = RCV_REQUEST;
  transition->method = (void (*)(void *, void *)) &nist_rcv_request;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_COMPLETED;
  transition->type = TIMEOUT_J;
  transition->method = (void (*)(void *, void *)) &osip_nist_timeout_j_event;
  osip_list_add (nist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = NIST_COMPLETED;
  transition->type = RCV_REQUEST;
  transition->method = (void (*)(void *, void *)) &nist_rcv_request;
  osip_list_add (nist_fsm->transitions, transition, -1);

}

static void
nist_handle_transport_error (osip_transaction_t * nist, int err)
{
  __osip_transport_error_callback (OSIP_NIST_TRANSPORT_ERROR, nist, err);
  __osip_transaction_set_state (nist, NIST_TERMINATED);
  __osip_kill_transaction_callback (OSIP_NIST_KILL_TRANSACTION, nist);
  /* TODO: MUST BE DELETED NOW */
}

void
nist_rcv_request (osip_transaction_t * nist, osip_event_t * evt)
{
  int i;
  osip_t *osip = (osip_t *) nist->config;

  if (nist->state == NIST_PRE_TRYING)	/* announce new REQUEST */
    {
      /* Here we have ist->orig_request == NULL */
      nist->orig_request = evt->sip;

      if (MSG_IS_REGISTER (evt->sip))
	__osip_message_callback (OSIP_NIST_REGISTER_RECEIVED, nist,
				 nist->orig_request);
      else if (MSG_IS_BYE (evt->sip))
	__osip_message_callback (OSIP_NIST_BYE_RECEIVED, nist,
				 nist->orig_request);
      else if (MSG_IS_OPTIONS (evt->sip))
	__osip_message_callback (OSIP_NIST_OPTIONS_RECEIVED, nist,
				 nist->orig_request);
      else if (MSG_IS_INFO (evt->sip))
	__osip_message_callback (OSIP_NIST_INFO_RECEIVED, nist,
				 nist->orig_request);
      else if (MSG_IS_CANCEL (evt->sip))
	__osip_message_callback (OSIP_NIST_CANCEL_RECEIVED, nist,
				 nist->orig_request);
      else if (MSG_IS_NOTIFY (evt->sip))
	__osip_message_callback (OSIP_NIST_NOTIFY_RECEIVED, nist,
				 nist->orig_request);
      else if (MSG_IS_SUBSCRIBE (evt->sip))
	__osip_message_callback (OSIP_NIST_SUBSCRIBE_RECEIVED, nist,
				 nist->orig_request);
      else
	__osip_message_callback (OSIP_NIST_UNKNOWN_REQUEST_RECEIVED, nist,
				 nist->orig_request);
    }
  else				/* NIST_PROCEEDING or NIST_COMPLETED */
    {
      /* delete retransmission */
      osip_message_free (evt->sip);

      __osip_message_callback (OSIP_NIST_REQUEST_RECEIVED_AGAIN, nist,
			       nist->orig_request);
      if (nist->last_response != NULL)	/* retransmit last response */
	{
	  osip_via_t *via;

	  via = (osip_via_t *) osip_list_get (nist->last_response->vias, 0);
	  if (via)
	    {
	      char *host;
	      int port;
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

	      i = osip->cb_send_message (nist, nist->last_response, host,
					 port, nist->out_socket);
	    }
	  else
	    i = -1;
	  if (i != 0)
	    {
	      nist_handle_transport_error (nist, i);
	      return;
	    }
	  else
	    {
	      if (MSG_IS_STATUS_1XX (nist->last_response))
		__osip_message_callback (OSIP_NIST_STATUS_1XX_SENT, nist,
					 nist->last_response);
	      else if (MSG_IS_STATUS_2XX (nist->last_response))
		__osip_message_callback (OSIP_NIST_STATUS_2XX_SENT_AGAIN,
					 nist, nist->last_response);
	      else
		__osip_message_callback (OSIP_NIST_STATUS_3456XX_SENT_AGAIN,
					 nist, nist->last_response);
	      return;
	    }
	}
      /* we are already in the proper state */
      return;
    }

  /* we come here only if it was the first REQUEST received */
  __osip_transaction_set_state (nist, NIST_TRYING);
}

void
nist_snd_1xx (osip_transaction_t * nist, osip_event_t * evt)
{
  int i;
  osip_via_t *via;
  osip_t *osip = (osip_t *) nist->config;

  if (nist->last_response != NULL)
    {
      osip_message_free (nist->last_response);
    }
  nist->last_response = evt->sip;

  via = (osip_via_t *) osip_list_get (nist->last_response->vias, 0);
  if (via)
    {
      char *host;
      int port;
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
      i = osip->cb_send_message (nist, nist->last_response, host,
				 port, nist->out_socket);
    }
  else
    i = -1;
  if (i != 0)
    {
      nist_handle_transport_error (nist, i);
      return;
    }
  else
    __osip_message_callback (OSIP_NIST_STATUS_1XX_SENT, nist,
			     nist->last_response);

  __osip_transaction_set_state (nist, NIST_PROCEEDING);
}

void
nist_snd_23456xx (osip_transaction_t * nist, osip_event_t * evt)
{
  int i;
  osip_via_t *via;
  osip_t *osip = (osip_t *) nist->config;

  if (nist->last_response != NULL)
    {
      osip_message_free (nist->last_response);
    }
  nist->last_response = evt->sip;

  via = (osip_via_t *) osip_list_get (nist->last_response->vias, 0);
  if (via)
    {
      char *host;
      int port;
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
      i = osip->cb_send_message (nist, nist->last_response, host,
				 port, nist->out_socket);
    }
  else
    i = -1;
  if (i != 0)
    {
      nist_handle_transport_error (nist, i);
      return;
    }
  else
    {
      if (EVT_IS_SND_STATUS_2XX (evt))
	__osip_message_callback (OSIP_NIST_STATUS_2XX_SENT, nist,
				 nist->last_response);
      else if (MSG_IS_STATUS_3XX (nist->last_response))
	__osip_message_callback (OSIP_NIST_STATUS_3XX_SENT, nist,
				 nist->last_response);
      else if (MSG_IS_STATUS_4XX (nist->last_response))
	__osip_message_callback (OSIP_NIST_STATUS_4XX_SENT, nist,
				 nist->last_response);
      else if (MSG_IS_STATUS_5XX (nist->last_response))
	__osip_message_callback (OSIP_NIST_STATUS_5XX_SENT, nist,
				 nist->last_response);
      else
	__osip_message_callback (OSIP_NIST_STATUS_6XX_SENT, nist,
				 nist->last_response);
    }

  if (nist->state != NIST_COMPLETED)	/* start J timer */
    {
      osip_gettimeofday (&nist->nist_context->timer_j_start, NULL);
      add_gettimeofday (&nist->nist_context->timer_j_start,
			nist->nist_context->timer_j_length);
    }

  __osip_transaction_set_state (nist, NIST_COMPLETED);
}


void
osip_nist_timeout_j_event (osip_transaction_t * nist, osip_event_t * evt)
{
  nist->nist_context->timer_j_length = -1;
  nist->nist_context->timer_j_start.tv_sec = -1;

  __osip_transaction_set_state (nist, NIST_TERMINATED);
  __osip_kill_transaction_callback (OSIP_NIST_KILL_TRANSACTION, nist);
}
