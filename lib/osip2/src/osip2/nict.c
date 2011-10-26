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
__osip_nict_init (osip_nict_t ** nict, osip_t * osip,
		  osip_message_t * request)
{
  osip_route_t *route;
  int i;
  time_t now;

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL,
	       "allocating NICT context\n"));

  *nict = (osip_nict_t *) osip_malloc (sizeof (osip_nict_t));
  if (*nict == NULL)
    return -1;
  now = time (NULL);
  memset (*nict, 0, sizeof (osip_nict_t));
  /* for REQUEST retransmissions */
  {
    osip_via_t *via;
    char *proto;

    i = osip_message_get_via (request, 0, &via);	/* get top via */
    if (i != 0)
      goto ii_error_1;
    proto = via_get_protocol (via);
    if (proto == NULL)
      goto ii_error_1;

    if (osip_strcasecmp (proto, "TCP") != 0
	&& osip_strcasecmp (proto, "TLS") !=0
	&& osip_strcasecmp (proto, "SCTP") !=0)
      {
	(*nict)->timer_e_length = DEFAULT_T1;
	(*nict)->timer_k_length = DEFAULT_T4;
	osip_gettimeofday (&(*nict)->timer_e_start, NULL);
	add_gettimeofday (&(*nict)->timer_e_start, (*nict)->timer_e_length);
	(*nict)->timer_k_start.tv_sec = -1;	/* not started */
      }
    else
      {				/* reliable protocol is used: */
	(*nict)->timer_e_length = -1;	/* E is not ACTIVE */
	(*nict)->timer_k_length = 0;	/* MUST do the transition immediatly */
	(*nict)->timer_e_start.tv_sec = -1;
	(*nict)->timer_k_start.tv_sec = -1;	/* not started */
      }
  }

  /* for PROXY, the destination MUST be set by the application layer,
     this one may not be correct. */
  osip_message_get_route (request, 0, &route);
  if (route != NULL)
    {
      int port = 5060;

      if (route->url->port != NULL)
	port = osip_atoi (route->url->port);
      osip_nict_set_destination ((*nict), osip_strdup (route->url->host),
				 port);
    }
  else
    (*nict)->port = 5060;

  (*nict)->timer_f_length = 64 * DEFAULT_T1;
  osip_gettimeofday (&(*nict)->timer_f_start, NULL);
  add_gettimeofday (&(*nict)->timer_f_start, (*nict)->timer_f_length);

  /* Oups! a Bug! */
  /*  (*nict)->port  = 5060; */

  return 0;

ii_error_1:
  osip_free (*nict);
  return -1;
}

int
__osip_nict_free (osip_nict_t * nict)
{
  if (nict == NULL)
    return -1;
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL,
	       "free nict ressource\n"));

  osip_free (nict->destination);
  osip_free (nict);
  return 0;
}

int
osip_nict_set_destination (osip_nict_t * nict, char *destination, int port)
{
  if (nict == NULL)
    return -1;
  if (nict->destination != NULL)
    osip_free (nict->destination);
  nict->destination = destination;
  nict->port = port;
  return 0;
}

osip_event_t *
__osip_nict_need_timer_e_event (osip_nict_t * nict, state_t state, int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (nict == NULL)
    return NULL;
  if (state == NICT_PROCEEDING || state == NICT_TRYING)
    {
      if (nict->timer_e_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &nict->timer_e_start, >))
	return __osip_event_new (TIMEOUT_E, transactionid);
    }
  return NULL;
}

osip_event_t *
__osip_nict_need_timer_f_event (osip_nict_t * nict, state_t state,
				int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (nict == NULL)
    return NULL;
  if (state == NICT_PROCEEDING || state == NICT_TRYING)
    {
      if (nict->timer_f_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &nict->timer_f_start, >))
	return __osip_event_new (TIMEOUT_F, transactionid);
    }
  return NULL;
}

osip_event_t *
__osip_nict_need_timer_k_event (osip_nict_t * nict, state_t state,
				int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (nict == NULL)
    return NULL;
  if (state == NICT_COMPLETED)
    {
      if (nict->timer_k_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &nict->timer_k_start, >))
	return __osip_event_new (TIMEOUT_K, transactionid);
    }
  return NULL;
}

