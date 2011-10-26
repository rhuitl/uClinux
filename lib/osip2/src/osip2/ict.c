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
__osip_ict_init (osip_ict_t ** ict, osip_t * osip, osip_message_t * invite)
{
  osip_route_t *route;
  int i;
  time_t now;

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL,
	       "allocating ICT context\n"));

  *ict = (osip_ict_t *) osip_malloc (sizeof (osip_ict_t));
  if (*ict == NULL)
    return -1;

  now = time (NULL);
  memset (*ict, 0, sizeof (osip_ict_t));
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
      {				/* for other reliable protocol than TCP, the timer
				   must be desactived by the external application */
	(*ict)->timer_a_length = DEFAULT_T1;
	if (64 * DEFAULT_T1 < 32000)
	  (*ict)->timer_d_length = 32000;
	else
	  (*ict)->timer_d_length = 64 * DEFAULT_T1;
	osip_gettimeofday (&(*ict)->timer_a_start, NULL);
	add_gettimeofday (&(*ict)->timer_a_start, (*ict)->timer_a_length);
	(*ict)->timer_d_start.tv_sec = -1;	/* not started */
      }
    else
      {				/* reliable protocol is used: */
	(*ict)->timer_a_length = -1;	/* A is not ACTIVE */
	(*ict)->timer_d_length = 0;	/* MUST do the transition immediatly */
	(*ict)->timer_a_start.tv_sec = -1;	/* not started */
	(*ict)->timer_d_start.tv_sec = -1;	/* not started */
      }
  }

  /* for PROXY, the destination MUST be set by the application layer,
     this one may not be correct. */
  osip_message_get_route (invite, 0, &route);
  if (route != NULL)
    {
      int port = 5060;

      if (route->url->port != NULL)
	port = osip_atoi (route->url->port);
      osip_ict_set_destination ((*ict), osip_strdup (route->url->host), port);
    }
  else
    (*ict)->port = 5060;

  (*ict)->timer_b_length = 64 * DEFAULT_T1;
  osip_gettimeofday (&(*ict)->timer_b_start, NULL);
  add_gettimeofday (&(*ict)->timer_b_start, (*ict)->timer_b_length);

  /* Oups! A bug! */
  /*  (*ict)->port  = 5060; */

  return 0;

ii_error_1:
  osip_free (*ict);
  return -1;
}

int
__osip_ict_free (osip_ict_t * ict)
{
  if (ict == NULL)
    return -1;
  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, OSIP_INFO2, NULL, "free ict ressource\n"));

  osip_free (ict->destination);
  osip_free (ict);
  return 0;
}

int
osip_ict_set_destination (osip_ict_t * ict, char *destination, int port)
{
  if (ict == NULL)
    return -1;
  if (ict->destination != NULL)
    osip_free (ict->destination);
  ict->destination = destination;
  ict->port = port;
  return 0;
}

osip_event_t *
__osip_ict_need_timer_a_event (osip_ict_t * ict, state_t state, int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (ict == NULL)
    return NULL;
  if (state == ICT_CALLING)
    {
      /* may need timer A */
      if (ict->timer_a_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &ict->timer_a_start, >))
	return __osip_event_new (TIMEOUT_A, transactionid);
    }
  return NULL;
}

osip_event_t *
__osip_ict_need_timer_b_event (osip_ict_t * ict, state_t state,
			       int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (ict == NULL)
    return NULL;
  if (state == ICT_CALLING)
    {
      /* may need timer B */
      if (ict->timer_b_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &ict->timer_b_start, >))
	return __osip_event_new (TIMEOUT_B, transactionid);
    }
  return NULL;
}

osip_event_t *
__osip_ict_need_timer_d_event (osip_ict_t * ict, state_t state,
			       int transactionid)
{
  struct timeval now;
  osip_gettimeofday (&now, NULL);

  if (ict == NULL)
    return NULL;
  if (state == ICT_COMPLETED)
    {
      /* may need timer D */
      if (ict->timer_d_start.tv_sec == -1)
	return NULL;
      if (osip_timercmp (&now, &ict->timer_d_start, >))
	return __osip_event_new (TIMEOUT_D, transactionid);
    }
  return NULL;
}

