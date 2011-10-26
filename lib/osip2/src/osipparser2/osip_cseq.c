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
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>

int
osip_cseq_init (osip_cseq_t ** cseq)
{
  *cseq = (osip_cseq_t *) osip_malloc (sizeof (osip_cseq_t));
  if (*cseq == NULL)
    return -1;
  (*cseq)->method = NULL;
  (*cseq)->number = NULL;
  return 0;
}

/* fills the cseq header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_cseq (osip_message_t * sip, const char *hvalue)
{
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  if (sip->cseq != NULL)
    return -1;
  i = osip_cseq_init (&(sip->cseq));
  if (i != 0)
    return -1;
  sip->message_property = 2;
  i = osip_cseq_parse (sip->cseq, hvalue);
  if (i != 0)
    {
      osip_cseq_free (sip->cseq);
      sip->cseq = NULL;
      return -1;
    }
  return 0;
}

/* fills the cseq strucuture.                      */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_cseq_parse (osip_cseq_t * cseq, const char *hvalue)
{
  char *method = NULL;
  const char *end = NULL;

  cseq->number = NULL;
  cseq->method = NULL;

  method = strchr (hvalue, ' ');	/* SEARCH FOR SPACE */
  end = hvalue + strlen (hvalue);

  if (method == NULL)
    return -1;

  if (method - hvalue + 1 < 2)
    return -1;
  cseq->number = (char *) osip_malloc (method - hvalue + 1);
  if (cseq->number == NULL)
    return -1;
  osip_strncpy (cseq->number, hvalue, method - hvalue);
  osip_clrspace (cseq->number);

  if (end - method + 1 < 2)
    return -1;
  cseq->method = (char *) osip_malloc (end - method + 1);
  if (cseq->method == NULL)
    return -1;
  osip_strncpy (cseq->method, method + 1, end - method);
  osip_clrspace (cseq->method);

  return 0;			/* ok */
}

/* returns the cseq header.            */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
osip_cseq_t *
osip_message_get_cseq (const osip_message_t * sip)
{
  return sip->cseq;
}

char *
osip_cseq_get_number (osip_cseq_t * cseq)
{
  return cseq->number;
}

char *
osip_cseq_get_method (osip_cseq_t * cseq)
{
  return cseq->method;
}

void
osip_cseq_set_number (osip_cseq_t * cseq, char *number)
{
  cseq->number = (char *) number;
}

void
osip_cseq_set_method (osip_cseq_t * cseq, char *method)
{
  cseq->method = (char *) method;
}

/* returns the cseq header as a string.          */
/* INPUT : osip_cseq_t *cseq | cseq header.  */
/* returns null on error. */
int
osip_cseq_to_str (const osip_cseq_t * cseq, char **dest)
{
  size_t len;

  *dest = NULL;
  if ((cseq == NULL) || (cseq->number == NULL) || (cseq->method == NULL))
    return -1;
  len = strlen (cseq->method) + strlen (cseq->number) + 2;
  *dest = (char *) osip_malloc (len);
  if (*dest == NULL)
    return -1;
  sprintf (*dest, "%s %s", cseq->number, cseq->method);
  return 0;
}

/* deallocates a osip_cseq_t structure.  */
/* INPUT : osip_cseq_t *cseq | cseq. */
void
osip_cseq_free (osip_cseq_t * cseq)
{
  if (cseq == NULL)
    return;
  osip_free (cseq->method);
  osip_free (cseq->number);
  osip_free (cseq);
}

int
osip_cseq_clone (const osip_cseq_t * cseq, osip_cseq_t ** dest)
{
  int i;
  osip_cseq_t *cs;

  *dest = NULL;
  if (cseq == NULL)
    return -1;
  if (cseq->method == NULL)
    return -1;
  if (cseq->number == NULL)
    return -1;

  i = osip_cseq_init (&cs);
  if (i != 0)
    {
      osip_cseq_free (cs);
      return -1;
    }
  cs->method = osip_strdup (cseq->method);
  cs->number = osip_strdup (cseq->number);

  *dest = cs;
  return 0;
}

int
osip_cseq_match (osip_cseq_t * cseq1, osip_cseq_t * cseq2)
{
  if (cseq1 == NULL || cseq2 == NULL)
    return -1;
  if (cseq1->number == NULL || cseq2->number == NULL
      || cseq1->method == NULL || cseq2->method == NULL)
    return -1;

  if (0 == strcmp (cseq1->number, cseq2->number))
    {
      if (0 == strcmp (cseq2->method, "INVITE")
	  || 0 == strcmp (cseq2->method, "ACK"))
	{
	  if (0 == strcmp (cseq1->method, "INVITE") ||
	      0 == strcmp (cseq1->method, "ACK"))
	    return 0;
	}
      else
	{
	  if (0 == strcmp (cseq1->method, cseq2->method))
	    return 0;
	}
    }
  return -1;
}
