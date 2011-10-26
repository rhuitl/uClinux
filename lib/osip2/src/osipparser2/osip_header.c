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


/* Add a header to a SIP message.                           */
/* INPUT :  char *hname | pointer to a header name.         */
/* INPUT :  char *hvalue | pointer to a header value.       */
/* OUTPUT: osip_message_t *sip | structure to save results.          */
/* returns -1 on error. */
int
osip_message_set_header (osip_message_t * sip, const char *hname,
			 const char *hvalue)
{
  osip_header_t *h;
  int i;

  if (hname == NULL)
    return -1;

  i = osip_header_init (&h);
  if (i != 0)
    return -1;

  h->hname = (char *) osip_malloc (strlen (hname) + 1);

  if (h->hname == NULL)
    {
      osip_header_free (h);
      return -1;
    }
  osip_strncpy (h->hname, hname, strlen (hname));
  osip_clrspace (h->hname);

  if (hvalue != NULL)
    {				/* some headers can be null ("subject:") */
      h->hvalue = (char *) osip_malloc (strlen (hvalue) + 1);
      if (h->hvalue == NULL)
	{
	  osip_header_free (h);
	  return -1;
	}
      osip_strncpy (h->hvalue, hvalue, strlen (hvalue));
      osip_clrspace (h->hvalue);
    }
  else
    h->hvalue = NULL;
  sip->message_property = 2;
  osip_list_add (sip->headers, h, -1);
  return 0;			/* ok */
}

/* Add a header to a SIP message at the top of the list.    */
/* INPUT :  char *hname | pointer to a header name.         */
/* INPUT :  char *hvalue | pointer to a header value.       */
/* OUTPUT: osip_message_t *sip | structure to save results.          */
/* returns -1 on error. */
int
osip_message_set_topheader (osip_message_t * sip, const char *hname,
			    const char *hvalue)
{
  osip_header_t *h;
  int i;

  if (hname == NULL)
    return -1;

  i = osip_header_init (&h);
  if (i != 0)
    return -1;

  h->hname = (char *) osip_malloc (strlen (hname) + 1);

  if (h->hname == NULL)
    {
      osip_header_free (h);
      return -1;
    }
  osip_strncpy (h->hname, hname, strlen (hname));
  osip_clrspace (h->hname);

  if (hvalue != NULL)
    {				/* some headers can be null ("subject:") */
      h->hvalue = (char *) osip_malloc (strlen (hvalue) + 1);
      if (h->hvalue == NULL)
	{
	  osip_header_free (h);
	  return -1;
	}
      osip_strncpy (h->hvalue, hvalue, strlen (hvalue));
      osip_clrspace (h->hvalue);
    }
  else
    h->hvalue = NULL;
  sip->message_property = 2;
  osip_list_add (sip->headers, h, 0);
  return 0;			/* ok */
}

/* Get a header in a SIP message.                       */
/* INPUT : int pos | position of number in message.     */
/* OUTPUT: osip_message_t *sip | structure to scan for a header .*/
/* return null on error. */
int
osip_message_get_header (const osip_message_t * sip, int pos,
			 osip_header_t ** dest)
{
  *dest = NULL;
  if (osip_list_size (sip->headers) <= pos)
    return -1;			/* NULL */
  *dest = (osip_header_t *) osip_list_get (sip->headers, pos);
  return 0;
}

/* Get a header in a SIP message.                       */
/* INPUT : int pos | position where we start the search */
/* OUTPUT: osip_message_t *sip | structure to look for header.   */
/* return the current position of the header found      */
/* and -1 on error. */
int
osip_message_header_get_byname (const osip_message_t * sip, const char *hname,
				int pos, osip_header_t ** dest)
{
  int i;
  osip_header_t *tmp;

  *dest = NULL;
  i = pos;
  if (osip_list_size (sip->headers) <= pos)
    return -1;			/* NULL */
  while (osip_list_size (sip->headers) > i)
    {
      tmp = (osip_header_t *) osip_list_get (sip->headers, i);
      if (osip_strcasecmp (tmp->hname, hname) == 0)
	{
	  *dest = tmp;
	  return i;
	}
      i++;
    }
  return -1;			/* not found */
}

int
osip_header_init (osip_header_t ** header)
{
  *header = (osip_header_t *) osip_malloc (sizeof (osip_header_t));
  if (*header == NULL)
    return -1;
  (*header)->hname = NULL;
  (*header)->hvalue = NULL;
  return 0;
}

void
osip_header_free (osip_header_t * header)
{
  if (header == NULL)
    return;
  osip_free (header->hname);
  osip_free (header->hvalue);
  header->hname = NULL;
  header->hvalue = NULL;

  osip_free (header);
}

/* returns the header as a string.    */
/* INPUT : osip_header_t *header | header. */
/* returns null on error. */
int
osip_header_to_str (const osip_header_t * header, char **dest)
{
  size_t len;

  *dest = NULL;
  if ((header == NULL) || (header->hname == NULL))
    return -1;

  len = 0;
  if (header->hvalue != NULL)
    len = strlen (header->hvalue);

  *dest = (char *) osip_malloc (strlen (header->hname) + len + 3);
  if (*dest == NULL)
    return -1;

  if (header->hvalue != NULL)
    sprintf (*dest, "%s: %s", header->hname, header->hvalue);
  else
    sprintf (*dest, "%s: ", header->hname);

  if (*dest[0] > 'a' && *dest[0] < 'z')
    *dest[0] = (*dest[0]-32);
  return 0;
}

char *
osip_header_get_name (const osip_header_t * header)
{
  if (header == NULL)
    return NULL;
  return header->hname;
}

void
osip_header_set_name (osip_header_t * header, char *name)
{
  header->hname = name;
}

char *
osip_header_get_value (const osip_header_t * header)
{
  if (header == NULL)
    return NULL;
  return header->hvalue;
}

void
osip_header_set_value (osip_header_t * header, char *value)
{
  header->hvalue = value;
}

int
osip_header_clone (const osip_header_t * header, osip_header_t ** dest)
{
  int i;
  osip_header_t *he;

  *dest = NULL;
  if (header == NULL)
    return -1;
  if (header->hname == NULL)
    return -1;

  i = osip_header_init (&he);
  if (i != 0)
    return -1;
  he->hname = osip_strdup (header->hname);
  if (header->hvalue != NULL)
    he->hvalue = osip_strdup (header->hvalue);

  *dest = he;
  return 0;
}
