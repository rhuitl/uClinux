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

/* Create a sipevent according to the SIP message buf. */
/* INPUT : char *buf | message as a string.            */
/* return NULL  if message cannot be parsed            */
osip_event_t *
osip_parse (const char *buf, size_t length)
{
  osip_event_t *se = __osip_event_new (UNKNOWN_EVT, 0);
  int i;

#ifdef TEST_PARSER_SPEED
  {
    int kk;
    int pstime1, pstime;
    struct timespec tv1;

    clock_get_time (CLOCK_REALTIME, &tv1);
    pstime = ((tv1.tv_sec * 1000) + (tv1.tv_nsec / 1000000));
    for (kk = 0; kk < 10000; kk++)
      {

	i = osip_message_init (&(se->sip));

	if (osip_message_parse (se->sip, buf, length) == -1)
	  {
	    fprintf (stdout, "osip_message_parse retrun -1\n");
	    osip_message_free (se->sip);
	  }
	else
	  {			/* msg is parsed */
	    osip_message_free (se->sip);
	  }
      }
    clock_get_time (CLOCK_REALTIME, &tv1);
    pstime1 = ((tv1.tv_sec * 1000) + (tv1.tv_nsec / 1000000));
    fprintf (stdout, "CPU clock ticks for 10000 messages - T1: %i - T2: %i\n",
	     pstime1, pstime);
    fprintf (stdout, "CPU time for 10000 messages - %d\n",
	     (pstime1 - pstime));
  }
  osip_free (se);
  return NULL;
#endif
  /* parse message and set up an event */
  i = osip_message_init (&(se->sip));
  if (osip_message_parse (se->sip, buf, length) == -1)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "could not parse message\n"));
      osip_message_free (se->sip);
      osip_free (se);
      return NULL;
    }
  else
    {
      if (se->sip->call_id != NULL && se->sip->call_id->number != NULL)
	{
	  OSIP_TRACE (osip_trace
		      (__FILE__, __LINE__, OSIP_INFO3, NULL,
		       "MESSAGE REC. CALLID:%s\n", se->sip->call_id->number));
	}

      if (MSG_IS_REQUEST (se->sip))
	{
	  if (se->sip->sip_method == NULL || se->sip->req_uri == NULL)
	    {
	      osip_message_free (se->sip);
	      osip_free (se);
	      return NULL;
	    }
	}

      se->type = evt_set_type_incoming_sipmessage (se->sip);
      return se;
    }
}


/* allocates an event from retransmitter.             */
/* USED ONLY BY THE STACK.                            */
/* INPUT : int transactionid | id of the transaction. */
/* INPUT : type_t type | type of event.               */
/* returns null on error. */
osip_event_t *
__osip_event_new (type_t type, int transactionid)
{
  osip_event_t *sipevent;

  sipevent = (osip_event_t *) osip_malloc (sizeof (osip_event_t));
  if (sipevent == NULL)
    return NULL;
  sipevent->type = type;
  sipevent->sip = NULL;
  sipevent->transactionid = transactionid;
  return sipevent;
}

/* allocates an event from user.                      */
/* USED ONLY BY THE USER.                             */
/* INPUT : osip_message_t *sip | sip message for transaction.  */
/* returns null on error. */
osip_event_t *
osip_new_outgoing_sipmessage (osip_message_t * sip)
{
  osip_event_t *sipevent;

  if (sip == NULL)
    return NULL;
  if (MSG_IS_REQUEST (sip))
    {
      if (sip->sip_method == NULL)
	return NULL;
      if (sip->req_uri == NULL)
	return NULL;
    }
  sipevent = (osip_event_t *) osip_malloc (sizeof (osip_event_t));
  if (sipevent == NULL)
    return NULL;

  sipevent->sip = sip;
  sipevent->type = evt_set_type_outgoing_sipmessage (sip);
  sipevent->transactionid = 0;
  return sipevent;
}

type_t
evt_set_type_incoming_sipmessage (osip_message_t * sip)
{
  if (MSG_IS_REQUEST (sip))
    {
      if (MSG_IS_INVITE (sip))
	return RCV_REQINVITE;
      else if (MSG_IS_ACK (sip))
	return RCV_REQACK;
      return RCV_REQUEST;
    }
  else
    {
      if (MSG_IS_STATUS_1XX (sip))
	return RCV_STATUS_1XX;
      else if (MSG_IS_STATUS_2XX (sip))
	return RCV_STATUS_2XX;
      return RCV_STATUS_3456XX;
    }
}

type_t
evt_set_type_outgoing_sipmessage (osip_message_t * sip)
{

  if (MSG_IS_REQUEST (sip))
    {
      if (MSG_IS_INVITE (sip))
	return SND_REQINVITE;
      if (MSG_IS_ACK (sip))
	return SND_REQACK;
      return SND_REQUEST;
    }
  else
    {
      if (MSG_IS_STATUS_1XX (sip))
	return SND_STATUS_1XX;
      else if (MSG_IS_STATUS_2XX (sip))
	return SND_STATUS_2XX;
      return SND_STATUS_3456XX;
    }
}

void
osip_event_free (osip_event_t * event)
{
  if (event != NULL)
    {
      osip_message_free (event->sip);
      osip_free (event);
    }
}
