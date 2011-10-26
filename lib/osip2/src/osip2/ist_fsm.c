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

osip_statemachine_t *ist_fsm;

osip_statemachine_t *
__ist_get_fsm ()
{
  return ist_fsm;
}

void
__ist_unload_fsm ()
{
  transition_t *transition;
  osip_statemachine_t *statemachine = __ist_get_fsm ();

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
__ist_load_fsm ()
{
  transition_t *transition;

  ist_fsm =
    (osip_statemachine_t *) osip_malloc (sizeof (osip_statemachine_t));
  ist_fsm->transitions = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init (ist_fsm->transitions);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_PRE_PROCEEDING;
  transition->type = RCV_REQINVITE;
  transition->method = (void (*)(void *, void *)) &ist_rcv_invite;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_PROCEEDING;
  transition->type = RCV_REQINVITE;
  transition->method = (void (*)(void *, void *)) &ist_rcv_invite;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_COMPLETED;
  transition->type = RCV_REQINVITE;
  transition->method = (void (*)(void *, void *)) &ist_rcv_invite;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_COMPLETED;
  transition->type = TIMEOUT_G;
  transition->method = (void (*)(void *, void *)) &osip_ist_timeout_g_event;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_COMPLETED;
  transition->type = TIMEOUT_H;
  transition->method = (void (*)(void *, void *)) &osip_ist_timeout_h_event;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_PROCEEDING;
  transition->type = SND_STATUS_1XX;
  transition->method = (void (*)(void *, void *)) &ist_snd_1xx;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_PROCEEDING;
  transition->type = SND_STATUS_2XX;
  transition->method = (void (*)(void *, void *)) &ist_snd_2xx;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_PROCEEDING;
  transition->type = SND_STATUS_3456XX;
  transition->method = (void (*)(void *, void *)) &ist_snd_3456xx;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_COMPLETED;
  transition->type = RCV_REQACK;
  transition->method = (void (*)(void *, void *)) &ist_rcv_ack;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_CONFIRMED;
  transition->type = RCV_REQACK;
  transition->method = (void (*)(void *, void *)) &ist_rcv_ack;
  osip_list_add (ist_fsm->transitions, transition, -1);

  transition = (transition_t *) osip_malloc (sizeof (transition_t));
  transition->state = IST_CONFIRMED;
  transition->type = TIMEOUT_I;
  transition->method = (void (*)(void *, void *)) &osip_ist_timeout_i_event;
  osip_list_add (ist_fsm->transitions, transition, -1);

}

osip_message_t *
ist_create_resp_100 (osip_transaction_t * ist, osip_message_t * request)
{
  int i;
  osip_message_t *resp_100;

  i = osip_message_init (&resp_100);
  if (i != 0)
    return NULL;

  /* follow instructions from 8.2.6 */
  i = osip_from_clone (request->from, &(resp_100->from));
  if (i != 0)
    goto icr_error;
  /* 17.2.1 says: should NOT add a tag */
  i = osip_to_clone (request->to, &(resp_100->to));	/* DOES NOT include any tag! */
  if (i != 0)
    goto icr_error;
  i = osip_call_id_clone (request->call_id, &(resp_100->call_id));
  if (i != 0)
    goto icr_error;
  i = osip_cseq_clone (request->cseq, &(resp_100->cseq));
  if (i != 0)
    goto icr_error;

  /* Via headers are copied from request */
  {
    int pos = 0;
    osip_via_t *via;
    osip_via_t *orig_via;

    while (!osip_list_eol (ist->orig_request->vias, pos))
      {
	orig_via =
	  (osip_via_t *) osip_list_get (ist->orig_request->vias, pos);
	osip_via_clone (orig_via, &via);
	osip_list_add (resp_100->vias, via, -1);
	pos++;
      }
  }

  /* TODO: */
  /* MUST copy the "Timestamp" header here (+ add a delay if necessary!)        */
  /* a delay should not be necessary for 100 as it is sent in less than one sec */


  return resp_100;
icr_error:
  osip_message_free (resp_100);
  return NULL;
}

static void
ist_handle_transport_error (osip_transaction_t * ist, int err)
{
  __osip_transport_error_callback (OSIP_IST_TRANSPORT_ERROR, ist, err);
  __osip_transaction_set_state (ist, IST_TERMINATED);
  __osip_kill_transaction_callback (OSIP_IST_KILL_TRANSACTION, ist);
  /* TODO: MUST BE DELETED NOW */
}

void
ist_rcv_invite (osip_transaction_t * ist, osip_event_t * evt)
{
  int i;
  osip_t *osip = (osip_t *) ist->config;

  if (ist->state == IST_PRE_PROCEEDING)	/* announce new INVITE */
    {
      /* Here we have ist->orig_request == NULL */
      ist->orig_request = evt->sip;

      __osip_message_callback (OSIP_IST_INVITE_RECEIVED, ist, evt->sip);
    }
  else				/* IST_PROCEEDING or IST_COMPLETED */
    {
      /* delete retransmission */
      osip_message_free (evt->sip);

      __osip_message_callback (OSIP_IST_INVITE_RECEIVED_AGAIN, ist,
			       ist->orig_request);
      if (ist->last_response != NULL)	/* retransmit last response */
	{
	  osip_via_t *via;

	  via = (osip_via_t *) osip_list_get (ist->last_response->vias, 0);
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

	      i = osip->cb_send_message (ist, ist->last_response, host,
					 port, ist->out_socket);
	    }
	  else
	    i = -1;
	  if (i != 0)
	    {
	      ist_handle_transport_error (ist, i);
	      return;
	    }
	  else
	    {
	      if (MSG_IS_STATUS_1XX (ist->last_response))
		__osip_message_callback (OSIP_IST_STATUS_1XX_SENT, ist,
					 ist->last_response);
	      else if (MSG_IS_STATUS_2XX (ist->last_response))
		__osip_message_callback (OSIP_IST_STATUS_2XX_SENT_AGAIN, ist,
					 ist->last_response);
	      else
		__osip_message_callback (OSIP_IST_STATUS_3456XX_SENT_AGAIN,
					 ist, ist->last_response);
	    }
	}
      return;
    }

  /* we come here only if it was the first INVITE received */
  __osip_transaction_set_state (ist, IST_PROCEEDING);
}

void
osip_ist_timeout_g_event (osip_transaction_t * ist, osip_event_t * evt)
{
  osip_via_t *via;
  osip_t *osip = (osip_t *) ist->config;
  int i;

  ist->ist_context->timer_g_length = ist->ist_context->timer_g_length * 2;
  if (ist->ist_context->timer_g_length > 4000)
    ist->ist_context->timer_g_length = 4000;
  osip_gettimeofday (&ist->ist_context->timer_g_start, NULL);
  add_gettimeofday (&ist->ist_context->timer_g_start,
		    ist->ist_context->timer_g_length);

  /* retransmit RESPONSE */
  via = (osip_via_t *) osip_list_get (ist->last_response->vias, 0);
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

      i = osip->cb_send_message (ist, ist->last_response, host,
				 port, ist->out_socket);
    }
  else
    i = -1;
  if (i != 0)
    {
      ist_handle_transport_error (ist, i);
      return;
    }
  __osip_message_callback (OSIP_IST_STATUS_3456XX_SENT_AGAIN, ist,
			   ist->last_response);
}

void
osip_ist_timeout_h_event (osip_transaction_t * ist, osip_event_t * evt)
{
  ist->ist_context->timer_h_length = -1;
  ist->ist_context->timer_h_start.tv_sec = -1;

  __osip_transaction_set_state (ist, IST_TERMINATED);
  __osip_kill_transaction_callback (OSIP_IST_KILL_TRANSACTION, ist);
}

void
osip_ist_timeout_i_event (osip_transaction_t * ist, osip_event_t * evt)
{
  ist->ist_context->timer_i_length = -1;
  ist->ist_context->timer_i_start.tv_sec = -1;

  __osip_transaction_set_state (ist, IST_TERMINATED);
  __osip_kill_transaction_callback (OSIP_IST_KILL_TRANSACTION, ist);
}

void
ist_snd_1xx (osip_transaction_t * ist, osip_event_t * evt)
{
  int i;
  osip_via_t *via;
  osip_t *osip = (osip_t *) ist->config;

  if (ist->last_response != NULL)
    {
      osip_message_free (ist->last_response);
    }
  ist->last_response = evt->sip;

  via = (osip_via_t *) osip_list_get (ist->last_response->vias, 0);
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

      i = osip->cb_send_message (ist, ist->last_response, host,
				 port, ist->out_socket);
    }
  else
    i = -1;
  if (i != 0)
    {
      ist_handle_transport_error (ist, i);
      return;
    }
  else
    __osip_message_callback (OSIP_IST_STATUS_1XX_SENT, ist,
			     ist->last_response);

  /* we are already in the proper state */
  return;
}

void
ist_snd_2xx (osip_transaction_t * ist, osip_event_t * evt)
{
  int i;
  osip_via_t *via;
  osip_t *osip = (osip_t *) ist->config;

  if (ist->last_response != NULL)
    {
      osip_message_free (ist->last_response);
    }
  ist->last_response = evt->sip;

  via = (osip_via_t *) osip_list_get (ist->last_response->vias, 0);
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
      i = osip->cb_send_message (ist, ist->last_response, host,
				 port, ist->out_socket);
    }
  else
    i = -1;
  if (i != 0)
    {
      ist_handle_transport_error (ist, i);
      return;
    }
  else
    {
      __osip_message_callback (OSIP_IST_STATUS_2XX_SENT, ist,
			       ist->last_response);
      __osip_transaction_set_state (ist, IST_TERMINATED);
      __osip_kill_transaction_callback (OSIP_IST_KILL_TRANSACTION, ist);
    }
  return;
}

void
ist_snd_3456xx (osip_transaction_t * ist, osip_event_t * evt)
{
  int i;
  osip_via_t *via;
  osip_t *osip = (osip_t *) ist->config;

  if (ist->last_response != NULL)
    {
      osip_message_free (ist->last_response);
    }
  ist->last_response = evt->sip;

  via = (osip_via_t *) osip_list_get (ist->last_response->vias, 0);
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
      i = osip->cb_send_message (ist, ist->last_response, host,
				 port, ist->out_socket);
    }
  else
    i = -1;
  if (i != 0)
    {
      ist_handle_transport_error (ist, i);
      return;
    }
  else
    {
      if (MSG_IS_STATUS_3XX (ist->last_response))
	__osip_message_callback (OSIP_IST_STATUS_3XX_SENT, ist,
				 ist->last_response);
      else if (MSG_IS_STATUS_4XX (ist->last_response))
	__osip_message_callback (OSIP_IST_STATUS_4XX_SENT, ist,
				 ist->last_response);
      else if (MSG_IS_STATUS_5XX (ist->last_response))
	__osip_message_callback (OSIP_IST_STATUS_5XX_SENT, ist,
				 ist->last_response);
      else
	__osip_message_callback (OSIP_IST_STATUS_6XX_SENT, ist,
				 ist->last_response);
    }

  if(ist->ist_context->timer_g_length != -1)
    {
      osip_gettimeofday (&ist->ist_context->timer_g_start, NULL);
      add_gettimeofday (&ist->ist_context->timer_g_start,
			ist->ist_context->timer_g_length);
    }
  osip_gettimeofday (&ist->ist_context->timer_h_start, NULL);
  add_gettimeofday (&ist->ist_context->timer_h_start,
		    ist->ist_context->timer_h_length);
  __osip_transaction_set_state (ist, IST_COMPLETED);
  return;
}

void
ist_rcv_ack (osip_transaction_t * ist, osip_event_t * evt)
{
  if (ist->ack != NULL)
    {
      osip_message_free (ist->ack);
    }

  ist->ack = evt->sip;

  if (ist->state == IST_COMPLETED)
    __osip_message_callback (OSIP_IST_ACK_RECEIVED, ist, ist->ack);
  else				/* IST_CONFIRMED */
    __osip_message_callback (OSIP_IST_ACK_RECEIVED_AGAIN, ist, ist->ack);
  /* set the timer to 0 for reliable, and T4 for unreliable (already set) */
  osip_gettimeofday (&ist->ist_context->timer_i_start, NULL);
  add_gettimeofday (&ist->ist_context->timer_i_start,
		    ist->ist_context->timer_i_length);
  __osip_transaction_set_state (ist, IST_CONFIRMED);
}
