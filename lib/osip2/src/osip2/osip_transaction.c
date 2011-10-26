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

static int __osip_transaction_set_topvia (osip_transaction_t * transaction,
					  osip_via_t * topvia);
static int __osip_transaction_set_from (osip_transaction_t * transaction,
					osip_from_t * from);
static int __osip_transaction_set_to (osip_transaction_t * transaction,
				      osip_to_t * to);
static int __osip_transaction_set_call_id (osip_transaction_t * transaction,
					   osip_call_id_t * call_id);
static int __osip_transaction_set_cseq (osip_transaction_t * transaction,
					osip_cseq_t * cseq);

static int
__osip_transaction_set_topvia (osip_transaction_t * transaction,
			       osip_via_t * topvia)
{
  int i;

  if (transaction == NULL)
    return -1;
  i = osip_via_clone (topvia, &(transaction->topvia));
  if (i == 0)
    return 0;
  transaction->topvia = NULL;
  return -1;
}

static int
__osip_transaction_set_from (osip_transaction_t * transaction,
			     osip_from_t * from)
{
  int i;

  if (transaction == NULL)
    return -1;
  i = osip_from_clone (from, &(transaction->from));
  if (i == 0)
    return 0;
  transaction->from = NULL;
  return -1;
}

static int
__osip_transaction_set_to (osip_transaction_t * transaction, osip_to_t * to)
{
  int i;

  if (transaction == NULL)
    return -1;
  i = osip_to_clone (to, &(transaction->to));
  if (i == 0)
    return 0;
  transaction->to = NULL;
  return -1;
}

static int
__osip_transaction_set_call_id (osip_transaction_t * transaction,
				osip_call_id_t * call_id)
{
  int i;

  if (transaction == NULL)
    return -1;
  i = osip_call_id_clone (call_id, &(transaction->callid));
  if (i == 0)
    return 0;
  transaction->callid = NULL;
  return -1;
}

static int
__osip_transaction_set_cseq (osip_transaction_t * transaction,
			     osip_cseq_t * cseq)
{
  int i;

  if (transaction == NULL)
    return -1;
  i = osip_cseq_clone (cseq, &(transaction->cseq));
  if (i == 0)
    return 0;
  transaction->cseq = NULL;
  return -1;
}

int
osip_transaction_init (osip_transaction_t ** transaction,
		       osip_fsm_type_t ctx_type, osip_t * osip,
		       osip_message_t * request)
{
  static int transactionid = 1;
  osip_via_t *topvia;

  int i;
  time_t now;

  if (request==NULL)  return -1;
  if (request->call_id==NULL)  return -1;
  if (request->call_id->number==NULL)  return -1;

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL,
	       "allocating transaction ressource %i %s\n", transactionid,
	       request->call_id->number));

  *transaction =
    (osip_transaction_t *) osip_malloc (sizeof (osip_transaction_t));
  if (*transaction == NULL)
    return -1;

  now = time (NULL);

  memset (*transaction, 0, sizeof (osip_transaction_t));

  (*transaction)->birth_time = now;
  (*transaction)->transactionid = transactionid;
  transactionid++;

  topvia = osip_list_get (request->vias, 0);
  if (topvia == NULL)
    goto ti_error_1;

  i = __osip_transaction_set_topvia (*transaction, topvia);
  if (i != 0)
    goto ti_error_1;

  /* In some situation, some of those informtions might
     be useless. Mostly, I prefer to keep them in all case
     for backward compatibility. */
  i = __osip_transaction_set_from (*transaction, request->from);
  if (i != 0)
    goto ti_error_2;
  i = __osip_transaction_set_to (*transaction, request->to);
  if (i != 0)
    goto ti_error_3;
  i = __osip_transaction_set_call_id (*transaction, request->call_id);
  if (i != 0)
    goto ti_error_4;
  i = __osip_transaction_set_cseq (*transaction, request->cseq);
  if (i != 0)
    goto ti_error_5;
  /* RACE conditions can happen for server transactions */
  /* (*transaction)->orig_request = request; */
  (*transaction)->orig_request = NULL;

  (*transaction)->config = osip;

  (*transaction)->transactionff =
    (osip_fifo_t *) osip_malloc (sizeof (osip_fifo_t));
  if ((*transaction)->transactionff == NULL)
    goto ti_error_6;
  osip_fifo_init ((*transaction)->transactionff);

  (*transaction)->ctx_type = ctx_type;
  (*transaction)->ict_context = NULL;
  (*transaction)->ist_context = NULL;
  (*transaction)->nict_context = NULL;
  (*transaction)->nist_context = NULL;
  if (ctx_type == ICT)
    {
      (*transaction)->state = ICT_PRE_CALLING;
      i = __osip_ict_init (&((*transaction)->ict_context), osip, request);
      if (i != 0)
	goto ti_error_7;
      __osip_add_ict (osip, *transaction);
    }
  else if (ctx_type == IST)
    {
      (*transaction)->state = IST_PRE_PROCEEDING;
      i = __osip_ist_init (&((*transaction)->ist_context), osip, request);
      if (i != 0)
	goto ti_error_7;
      __osip_add_ist (osip, *transaction);
    }
  else if (ctx_type == NICT)
    {
      (*transaction)->state = NICT_PRE_TRYING;
      i = __osip_nict_init (&((*transaction)->nict_context), osip, request);
      if (i != 0)
	goto ti_error_7;
      __osip_add_nict (osip, *transaction);
    }
  else
    {
      (*transaction)->state = NIST_PRE_TRYING;
      i = __osip_nist_init (&((*transaction)->nist_context), osip, request);
      if (i != 0)
	goto ti_error_7;
      __osip_add_nist (osip, *transaction);
    }
  return 0;


ti_error_7:
  osip_fifo_free ((*transaction)->transactionff);
ti_error_6:
  osip_cseq_free ((*transaction)->cseq);
ti_error_5:
  osip_call_id_free ((*transaction)->callid);
ti_error_4:
  osip_to_free ((*transaction)->to);
ti_error_3:
  osip_from_free ((*transaction)->from);
ti_error_2:
  osip_via_free ((*transaction)->topvia);
ti_error_1:
  osip_free (*transaction);
  return -1;
}

/* This method automaticly remove the transaction context from
   the osip stack. This task is required for proper operation
   when a transaction goes in the TERMINATED STATE.
   However the user might want to just take the context out of
   the SIP stack andf keep it for future use without freeing
   all ressource.... This way the transaction context can be
   kept without being used by the oSIP stack.

   new methods that replace this one:
   osip_remove_transaction
   +
   osip_transaction_free2();

 */
int
osip_transaction_free (osip_transaction_t * transaction)
{
  int i;

  if (transaction == NULL)
    return -1;
  i = osip_remove_transaction (transaction->config, transaction);

  if (i != 0)			/* yet removed ??? */
    {
      OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_BUG, NULL,
			      "transaction already removed from list %i!\n",
			      transaction->transactionid));
    }

  return osip_transaction_free2 (transaction);
}

/* same as osip_transaction_free() but assume the transaction is
   already removed from the list of transaction in the osip stack */
int
osip_transaction_free2 (osip_transaction_t * transaction)
{
  osip_event_t *evt;

  if (transaction == NULL)
    return -1;
  if (transaction->orig_request != NULL
      &&transaction->orig_request->call_id!=NULL
      &&transaction->orig_request->call_id->number!=NULL)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_INFO2, NULL,
		   "free transaction ressource %i %s\n",
		   transaction->transactionid,
		   transaction->orig_request->call_id->number));
    }
  if (transaction->ctx_type == ICT)
    {
      __osip_ict_free (transaction->ict_context);
    }
  else if (transaction->ctx_type == IST)
    {
      __osip_ist_free (transaction->ist_context);
    }
  else if (transaction->ctx_type == NICT)
    {
      __osip_nict_free (transaction->nict_context);
    }
  else
    {
      __osip_nist_free (transaction->nist_context);
    }

  /* empty the fifo */
  evt = osip_fifo_tryget (transaction->transactionff);
  while (evt != NULL)
    {
      osip_message_free (evt->sip);
      osip_free (evt);
      evt = osip_fifo_tryget (transaction->transactionff);
    }
  osip_fifo_free (transaction->transactionff);

  osip_message_free (transaction->orig_request);
  osip_message_free (transaction->last_response);
  osip_message_free (transaction->ack);

  osip_via_free (transaction->topvia);
  osip_from_free (transaction->from);
  osip_to_free (transaction->to);
  osip_call_id_free (transaction->callid);
  osip_cseq_free (transaction->cseq);

  osip_free (transaction);
  return 0;
}

int
osip_transaction_add_event (osip_transaction_t * transaction,
			    osip_event_t * evt)
{
  if (evt == NULL)
    return -1;
  if (transaction == NULL)
    return -1;
  evt->transactionid = transaction->transactionid;
  osip_fifo_add (transaction->transactionff, evt);
  return 0;
}

int
osip_transaction_execute (osip_transaction_t * transaction,
			  osip_event_t * evt)
{
  osip_statemachine_t *statemachine;

  /* to kill the process, simply send this type of event. */
  if (EVT_IS_KILL_TRANSACTION (evt))
    {
      /* MAJOR CHANGE!
         TRANSACTION MUST NOW BE RELEASED BY END-USER:
         So Any usefull data can be save and re-used */
      /* osip_transaction_free(transaction);
         osip_free(transaction); */
      osip_free (evt);
      return 0;
    }

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO4, NULL,
	       "sipevent tr->transactionid: %i\n",
	       transaction->transactionid));
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO4, NULL,
	       "sipevent tr->state: %i\n", transaction->state));
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO4, NULL,
	       "sipevent evt->type: %i\n", evt->type));
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO4, NULL,
	       "sipevent evt->sip: %x\n", evt->sip));

  if (transaction->ctx_type == ICT)
    statemachine = __ict_get_fsm ();
  else if (transaction->ctx_type == IST)
    statemachine = __ist_get_fsm ();
  else if (transaction->ctx_type == NICT)
    statemachine = __nict_get_fsm ();
  else
    statemachine = __nist_get_fsm ();


  if (-1 == fsm_callmethod (evt->type,
			    transaction->state, statemachine, evt,
			    transaction))
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_INFO3, NULL, "USELESS event!\n"));
      /* message is useless. */
      if (EVT_IS_MSG (evt))
	{
	  if (evt->sip != NULL)
	    {
	      osip_message_free (evt->sip);
	    }
	}
    }
  else
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_INFO4, NULL,
		   "sipevent evt: method called!\n"));
    }
  osip_free (evt);		/* this is the ONLY place for freeing event!! */
  return 1;
}

int
osip_transaction_get_destination (osip_transaction_t * transaction, char **ip,
				  int *port)
{
  *ip = NULL;
  *port = 0;
  if (transaction == NULL)
    return -1;
  if (transaction->ict_context != NULL)
    {
      *ip = transaction->ict_context->destination;
      *port = transaction->ict_context->port;
      return 0;
    }
  else if (transaction->nict_context != NULL)
    {
      *ip = transaction->nict_context->destination;
      *port = transaction->nict_context->port;
      return 0;
    }
  return -1;
}

int
osip_transaction_set_your_instance (osip_transaction_t * transaction,
				    void *instance)
{
  if (transaction == NULL)
    return -1;
  transaction->your_instance = instance;
  return 0;
}

void *
osip_transaction_get_your_instance (osip_transaction_t * transaction)
{
  if (transaction == NULL)
    return NULL;
  return transaction->your_instance;
}

int
__osip_transaction_set_state (osip_transaction_t * transaction, state_t state)
{
  if (transaction == NULL)
    return -1;
  transaction->state = state;
  return 0;
}

int
osip_transaction_set_in_socket (osip_transaction_t * transaction, int sock)
{
  if (transaction == NULL)
    return -1;
  transaction->in_socket = sock;
  return 0;
}

int
osip_transaction_set_out_socket (osip_transaction_t * transaction, int sock)
{
  if (transaction == NULL)
    return -1;
  transaction->out_socket = sock;
  return 0;
}

int
__osip_transaction_matching_response_osip_to_xict_17_1_3 (osip_transaction_t *
							  tr,
							  osip_message_t *
							  response)
{
  osip_generic_param_t *b_request;
  osip_generic_param_t *b_response;
  osip_via_t *topvia_response;

  /* some checks to avoid crashing on bad requests */
  if (tr == NULL || (tr->ict_context == NULL && tr->nict_context == NULL) ||
      /* only ict and nict can match a response */
      response == NULL || response->cseq == NULL
      || response->cseq->method == NULL)
    return -1;

  topvia_response = osip_list_get (response->vias, 0);
  if (topvia_response == NULL)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "Remote UA is not compliant: missing a Via header!\n"));
      return -1;
    }
  osip_via_param_get_byname (tr->topvia, "branch", &b_request);
  if (b_request == NULL)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_BUG, NULL,
		   "You created a transaction without any branch! THIS IS NOT ALLOWED\n"));
      return -1;
    }
  osip_via_param_get_byname (topvia_response, "branch", &b_response);
  if (b_response == NULL)
    {
#ifdef FWDSUPPORT
      /* the from tag (unique) */
      if (from_tag_match (tr->from, response->from) != 0)
	return -1;
      /* the Cseq field */
      if (cseq_match (tr->cseq, response->cseq) != 0)
	return -1;
      /* the To field */
      if (response->to->url->username == NULL
	  && tr->from->url->username != NULL)
	return -1;
      if (response->to->url->username != NULL
	  && tr->from->url->username == NULL)
	return -1;
      if (response->to->url->username != NULL
	  && tr->from->url->username != NULL)
	{
	  if (strcmp (response->to->url->host, tr->from->url->host) ||
	      strcmp (response->to->url->username, tr->from->url->username))
	    return -1;
	}
      else
	{
	  if (strcmp (response->to->url->host, tr->from->url->host))
	    return -1;
	}

      /* the Call-ID field */
      if (call_id_match (tr->callid, response->call_id) != 0)
	return -1;
      return 0;
#else
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_BUG, NULL,
		   "Remote UA is not compliant: missing a branch parameter in  Via header!\n"));
      return -1;
#endif
    }

  /*
     A response matches a client transaction under two
     conditions:

     1.   If the response has the same value of the branch parameter
     in the top Via header field as the branch parameter in the
     top Via header field of the request that created the
     transaction.
   */
  if (0 != strcmp (b_request->gvalue, b_response->gvalue))
    return -1;
  /*  
     2.   If the method parameter in the CSeq header field matches
     the method of the request that created the transaction. The
     method is needed since a CANCEL request constitutes a
     different transaction, but shares the same value of the
     branch parameter.
     AMD NOTE: cseq->method is ALWAYS the same than the METHOD of the request.
   */
  if (0 == strcmp (response->cseq->method, tr->cseq->method))	/* general case */
    return 0;
  return -1;
}

int
__osip_transaction_matching_request_osip_to_xist_17_2_3 (osip_transaction_t *
							 tr,
							 osip_message_t *
							 request)
{
  osip_generic_param_t *b_origrequest;
  osip_generic_param_t *b_request;
  osip_via_t *topvia_request;
  size_t length_br;
  size_t length_br2;

  /* some checks to avoid crashing on bad requests */
  if (tr == NULL || (tr->ist_context == NULL && tr->nist_context == NULL) ||
      /* only ist and nist can match a request */
      request == NULL || request->cseq == NULL
      || request->cseq->method == NULL)
    return -1;

  topvia_request = osip_list_get (request->vias, 0);
  if (topvia_request == NULL)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "Remote UA is not compliant: missing a Via header!\n"));
      return -1;
    }
  osip_via_param_get_byname (topvia_request, "branch", &b_request);
  osip_via_param_get_byname (tr->topvia, "branch", &b_origrequest);

  if ((b_origrequest == NULL && b_request != NULL) ||
      (b_origrequest != NULL && b_request == NULL))
    return -1;			/* one request is compliant, the other one is not... */

  /* Section 17.2.3 Matching Requests to Server Transactions:
     "The branch parameter in the topmost Via header field of the request
     is examined. If it is present and begins with the magic cookie
     "z9hG4bK", the request was generated by a client transaction
     compliant to this specification."
   */

  if (b_origrequest != NULL && b_request != NULL)
    /* case where both request contains a branch */
    {
      length_br = strlen (b_origrequest->gvalue);
      length_br2 = strlen (b_request->gvalue);
      if (length_br != length_br2)
	return -1;		/* can't be the same */
      if (0 == strncmp (b_origrequest->gvalue, "z9hG4bK", 7)
	  && 0 == strncmp (b_request->gvalue, "z9hG4bK", 7))
	{
	  /* both request comes from a compliant UA */
	  /* The request matches a transaction if the branch parameter
	     in the request is equal to the one in the top Via header
	     field of the request that created the transaction, the
	     sent-by value in the top Via of the request is equal to
	     the one in the request that created the transaction, and in
	     the case of a CANCEL request, the method of the request
	     that created the transaction was also CANCEL.
	   */
	  if (0 != strcmp (b_origrequest->gvalue, b_request->gvalue))
	    return -1;		/* branch param does not match */
	  {
	    /* check the sent-by values */
	    char *b_port = via_get_port (topvia_request);
	    char *b_origport = via_get_port (tr->topvia);
	    char *b_host = via_get_host (topvia_request);
	    char *b_orighost = via_get_host (tr->topvia);
	    if ((b_host == NULL || b_orighost == NULL))
	      return -1;
	    if (0 != strcmp (b_orighost, b_host))
	      return -1;

	    if (b_port != NULL && b_origport == NULL
		&& 0 != strcmp (b_port, "5060"))
	      return -1;
	    else if (b_origport != NULL && b_port == NULL
		     && 0 != strcmp (b_origport, "5060"))
	      return -1;
	    else if (b_origport != NULL && b_port != NULL
		     && 0 != strcmp (b_origport, b_port))
	      return -1;
	  }
#ifdef AC_BUG
	  /* audiocodes bug (MP108-fxs-SIP-4-0-282-380) */
	  if (0 != osip_from_tag_match (tr->from, request->from))
	    return -1;
#endif
	  if (			/* MSG_IS_CANCEL(request)&& <<-- BUG from the spec?
				   I always check the CSeq */
	       (!(0 == strcmp (tr->cseq->method, "INVITE") &&
		  0 == strcmp (request->cseq->method, "ACK")))
	       && 0 != strcmp (tr->cseq->method, request->cseq->method))
	    return -1;
	  return 0;
	}
    }

  /* Back to the old backward compatibilty mechanism for matching requests */
  if (0 != osip_call_id_match (tr->callid, request->call_id))
    return -1;
  if (MSG_IS_ACK (request))
    {
      osip_generic_param_t *tag_from1;
      osip_generic_param_t *tag_from2;

      osip_from_param_get_byname (tr->to, "tag", &tag_from1);
      osip_from_param_get_byname (request->to, "tag", &tag_from2);
      if (tag_from1 == NULL && tag_from2 != NULL)
	{			/* do not check it as it can be a new tag when the final
				   answer has a tag while an INVITE doesn't have one */
	}
      else if (tag_from1 != NULL && tag_from2 == NULL)
	{
	  return -1;
	}
      else
	{
	  if (0 != osip_to_tag_match (tr->to, request->to))
	    return -1;
	}
    }
  else
    {
      if (0 != osip_to_tag_match (tr->to, request->to))
	return -1;
    }
  if (0 != osip_from_tag_match (tr->from, request->from))
    return -1;
  if (0 != osip_cseq_match (tr->cseq, request->cseq))
    return -1;
  if (0 != osip_via_match (tr->topvia, topvia_request))
    return -1;
  return 0;
}

#if 0

int
callleg_match (osip_to_t * to1, osip_from_t * from1, osip_to_t * to2,
	       osip_from_t * from2)
{
  if (to1 == NULL || to2 == NULL)
    return -1;
  if (from1 == NULL || from2 == NULL)
    return -1;

  if (0 == osip_from_compare ((osip_from_t *) to1, (osip_from_t *) to2)
      && 0 == osip_from_compare (from1, from2))
    return 0;
  return -1;
}

#endif
