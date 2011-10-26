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

int
__osip_nist_init (osip_nist_t ** nist, osip_t * osip, osip_message_t * invite)
{
  int i;

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL,
	       "allocating NIST context\n"));

  *nist = (osip_nist_t *) osip_malloc (sizeof (osip_nist_t));
  if (*nist == NULL)
    return -1;
  memset (*nist, 0, sizeof (osip_nist_t));
  /* for INVITE retransmissions */
  {
    osip_via_t *via;
    char *proto;

    i = osip_message_get_via (invite, 0, &via);	/* get top via */
    if (i != 0)
      goto ii_error_1;
    proto = via_get_protocol (via);
    if (proto == NULL)
      goto ii_error_1;

    if (osip_strcasecmp (proto, "TCP") != 0
	&& osip_strcasecmp (proto, "TLS") !=0
	&& osip_strcasecmp (proto, "SCTP") !=0)
      {
	(*nist)->timer_j_length = 64 * DEFAULT_T1;
	(*nist)->timer_j_start.tv_sec = -1;	/* not started */
      }
    else
      {				/* reliable protocol is used: */
	(*nist)->timer_j_length = 0;	/* MUST do the transition immediatly */
	(*nist)->timer_j_start.tv_sec = -1;	/* not started */
      }
  }

  return 0;

ii_error_1:
  osip_free (*nist);
  return -1;
}

int
__osip_nist_free (osip_nist_t * nist)
{
  if (nist == NULL)
    return -1;
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL,
	       "free nist ressource\n"));

  osip_free (nist);
  return 0;
}



osip_event_t *
__osip_nist_need_timer_j_event (osip_nist_t * nist, state_t state, int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (nist == NULL)
    return NULL;
  if (state == NIST_COMPLETED)
    {
      if (nist->timer_j_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &nist->timer_j_start, >))
	return __osip_event_new (TIMEOUT_J, transactionid);
    }
  return NULL;
}

