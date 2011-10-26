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

#include <stdio.h>
#include <stdlib.h>

#include <osipparser2/osip_port.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_body.h>
#include "parser.h"

static int osip_body_parse_header (osip_body_t * body,
				   const char *start_of_osip_body_header,
				   const char **next_body);

int
osip_body_init (osip_body_t ** body)
{
  *body = (osip_body_t *) osip_malloc (sizeof (osip_body_t));
  if (*body == NULL)
    return -1;
  (*body)->body = NULL;
  (*body)->content_type = NULL;
  (*body)->length = 0;

  (*body)->headers = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  if ((*body)->headers == NULL)
    {
      osip_free (*body);
      *body = NULL;
      return -1;
    }
  osip_list_init ((*body)->headers);
  return 0;
}

/**
 * Fill the body of message.
 * @param sip The structure to store results.
 * @param buf The pointer to the start of body.
 * @param length The length of body;
 */
int
osip_message_set_body (osip_message_t * sip, const char *buf, size_t length)
{
  osip_body_t *body;
  int i;

  i = osip_body_init (&body);
  if (i != 0)
    return -1;
  i = osip_body_parse (body, buf, length);
  if (i != 0)
    {
      osip_body_free (body);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->bodies, body, -1);
  return 0;
}

int
osip_body_clone (const osip_body_t * body, osip_body_t ** dest)
{
  int pos;
  int i;
  osip_body_t *copy;

  if (body == NULL || body->length<=0)
    return -1;

  i = osip_body_init (&copy);
  if (i != 0)
    return -1;

  
  copy->body = (char*)osip_malloc(body->length+2);
  copy->length = body->length;
  memcpy(copy->body,body->body,body->length);
  copy->body[body->length]='\0';

  if (body->content_type != NULL)
    {
      i = osip_content_type_clone (body->content_type, &(copy->content_type));
      if (i != 0)
	goto bc_error1;
    }

  {
    osip_header_t *header;
    osip_header_t *header2;

    pos = 0;
    while (!osip_list_eol (body->headers, pos))
      {
	header = (osip_header_t *) osip_list_get (body->headers, pos);
	i = osip_header_clone (header, &header2);
	if (i != 0)
	  goto bc_error1;
	osip_list_add (copy->headers, header2, -1);	/* insert as last element */
	pos++;
      }
  }

  *dest = copy;
  return 0;
bc_error1:
  osip_body_free (copy);
  return -1;
}

/* returns the pos of body header.                   */
/* INPUT : int pos | pos of body header.             */
/* INPUT : osip_message_t *sip | sip message.                 */
/* OUTPUT: osip_body_t *body | structure to save results. */
/* returns -1 on error. */
int
osip_message_get_body (const osip_message_t * sip, int pos,
		       osip_body_t ** dest)
{
  osip_body_t *body;

  *dest = NULL;
  if (osip_list_size (sip->bodies) <= pos)
    return -1;			/* does not exist */
  body = (osip_body_t *) osip_list_get (sip->bodies, pos);
  *dest = body;
  return pos;
}

int
osip_body_set_contenttype (osip_body_t * body, const char *hvalue)
{
  int i;

  if (body == NULL)
    return -1;
  if (hvalue == NULL)
    return -1;

  i = osip_content_type_init (&(body->content_type));
  if (i != 0)
    return -1;
  i = osip_content_type_parse (body->content_type, hvalue);
  if (i != 0)
    {
      osip_content_type_free (body->content_type);
      body->content_type = NULL;
      return -1;
    }
  return 0;
}

int
osip_body_set_header (osip_body_t * body, const char *hname,
		      const char *hvalue)
{
  osip_header_t *h;
  int i;

  if (body == NULL)
    return -1;
  if (hname == NULL)
    return -1;
  if (hvalue == NULL)
    return -1;

  i = osip_header_init (&h);
  if (i != 0)
    return -1;

  h->hname = osip_strdup (hname);
  h->hvalue = osip_strdup (hvalue);

  osip_list_add (body->headers, h, -1);
  return 0;
}

/* fill the body of message.                              */
/* INPUT : char *buf | pointer to the start of body.      */
/* OUTPUT: osip_message_t *sip | structure to save results.        */
/* returns -1 on error. */
int
osip_message_set_body_mime (osip_message_t * sip, const char *buf, size_t length)
{
  osip_body_t *body;
  int i;

  i = osip_body_init (&body);
  if (i != 0)
    return -1;
  i = osip_body_parse_mime (body, buf, length);
  if (i != 0)
    {
      osip_body_free (body);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->bodies, body, -1);
  return 0;
}

static int
osip_body_parse_header (osip_body_t * body,
			const char *start_of_osip_body_header,
			const char **next_body)
{
  const char *start_of_line;
  const char *end_of_line;
  const char *colon_index;
  char *hname;
  char *hvalue;
  int i;

  *next_body = NULL;
  start_of_line = start_of_osip_body_header;
  for (;;)
    {
      i = __osip_find_next_crlf (start_of_line, &end_of_line);
      if (i == -1)
	return -1;		/* error case: no end of body found */

      /* find the headere name */
      colon_index = strchr (start_of_line, ':');
      if (colon_index == NULL)
	return -1;		/* this is also an error case */

      if (colon_index - start_of_line + 1 < 2)
	return -1;
      hname = (char *) osip_malloc (colon_index - start_of_line + 1);
      if (hname == NULL)
	return -1;
      osip_strncpy (hname, start_of_line, colon_index - start_of_line);
      osip_clrspace (hname);

      if ((end_of_line - 2) - colon_index < 2)
	return -1;
      hvalue = (char *) osip_malloc ((end_of_line - 2) - colon_index);
      if (hvalue == NULL)
	{
	  osip_free (hname);
	  return -1;
	}
      osip_strncpy (hvalue, colon_index + 1,
		    (end_of_line - 2) - colon_index - 1);
      osip_clrspace (hvalue);

      /* really store the header in the sip structure */
      if (osip_strncasecmp (hname, "content-type", 12) == 0)
	i = osip_body_set_contenttype (body, hvalue);
      else
	i = osip_body_set_header (body, hname, hvalue);
      osip_free (hname);
      osip_free (hvalue);
      if (i == -1)
	return -1;

      if (strncmp (end_of_line, CRLF, 2) == 0
	  || strncmp (end_of_line, "\n", 1) == 0
	  || strncmp (end_of_line, "\r", 1) == 0)
	{
	  *next_body = end_of_line;
	  return 0;
	}
      start_of_line = end_of_line;
    }
}

int
osip_body_parse (osip_body_t * body, const char *start_of_body, size_t length)
{
  if (body == NULL)
    return -1;
  if (start_of_body == NULL)
    return -1;
  if (body->headers == NULL)
    return -1;

  body->body = (char *) osip_malloc (length + 1);
  if (body->body == NULL)
    return -1;
  memcpy(body->body,start_of_body,length);
  body->body[length]='\0';
  body->length = length;
  return 0;
}

int
osip_body_parse_mime (osip_body_t * body, const char *start_of_body, size_t length)
{
  const char *end_of_osip_body_header;
  const char *start_of_osip_body_header;
  int i;

  if (body == NULL)
    return -1;
  if (start_of_body == NULL)
    return -1;
  if (body->headers == NULL)
    return -1;

  start_of_osip_body_header = start_of_body;

  i =
    osip_body_parse_header (body, start_of_osip_body_header,
			    &end_of_osip_body_header);
  if (i == -1)
    return -1;

  start_of_osip_body_header = end_of_osip_body_header;
  /* set the real start of body */
  if (strncmp (start_of_osip_body_header, CRLF, 2) == 0)
    start_of_osip_body_header = start_of_osip_body_header + 2;
  else
    {
      if ((strncmp (start_of_osip_body_header, "\n", 1) == 0)
	  || (strncmp (start_of_osip_body_header, "\r", 1) == 0))
	start_of_osip_body_header = start_of_osip_body_header + 1;
      else
	return -1;		/* message does not end with CRLFCRLF, CRCR or LFLF */
    }

  end_of_osip_body_header = start_of_body + length;
  if (end_of_osip_body_header-start_of_osip_body_header<=0)
    return -1;
  body->body =
    (char *) osip_malloc (end_of_osip_body_header -
			  start_of_osip_body_header + 1);
  if (body->body == NULL)
    return -1;
  memcpy (body->body, start_of_osip_body_header,
	  end_of_osip_body_header - start_of_osip_body_header);
  body->length = end_of_osip_body_header - start_of_osip_body_header;

  return 0;

}

/* returns the body as a string.          */
/* INPUT : osip_body_t *body | body.  */
/* returns null on error. */
int
osip_body_to_str (const osip_body_t * body, char **dest, size_t *str_length)
{
  char *tmp_body;
  char *tmp;
  char *ptr;
  int pos;
  int i;
  size_t length;

  *dest = NULL;
  *str_length = 0;
  if (body == NULL)
    return -1;
  if (body->body == NULL)
    return -1;
  if (body->headers == NULL)
    return -1;
  if (body->length <= 0)
    return -1;

  length = body->length + (osip_list_size (body->headers) * 40);
  tmp_body = (char *) osip_malloc (length);
  if (tmp_body == NULL)
    return -1;
  ptr = tmp_body;		/* save the initial address of the string */

  if (body->content_type != NULL)
    {
      osip_strncpy (tmp_body, "content-type: ", 14);
      tmp_body = tmp_body + strlen (tmp_body);
      i = osip_content_type_to_str (body->content_type, &tmp);
      if (i == -1)
	{
	  osip_free (ptr);
	  return -1;
	}
      if (length < tmp_body - ptr + strlen (tmp) + 4)
	{
	  size_t len;

	  len = tmp_body - ptr;
	  length = length + strlen (tmp) + 4;
	  ptr = osip_realloc (ptr, length);
	  tmp_body = ptr + len;
	}

      osip_strncpy (tmp_body, tmp, strlen (tmp));
      osip_free (tmp);
      tmp_body = tmp_body + strlen (tmp_body);
      osip_strncpy (tmp_body, CRLF, 2);
      tmp_body = tmp_body + 2;
    }

  pos = 0;
  while (!osip_list_eol (body->headers, pos))
    {
      osip_header_t *header;

      header = (osip_header_t *) osip_list_get (body->headers, pos);
      i = osip_header_to_str (header, &tmp);
      if (i == -1)
	{
	  osip_free (ptr);
	  return -1;
	}
      if (length < tmp_body - ptr + strlen (tmp) + 4)
	{
	  size_t len;

	  len = tmp_body - ptr;
	  length = length + strlen (tmp) + 4;
	  ptr = osip_realloc (ptr, length);
	  tmp_body = ptr + len;
	}
      osip_strncpy (tmp_body, tmp, strlen (tmp));
      osip_free (tmp);
      tmp_body = tmp_body + strlen (tmp_body);
      osip_strncpy (tmp_body, CRLF, 2);
      tmp_body = tmp_body + 2;
      pos++;
    }

  if ((osip_list_size (body->headers) > 0) || (body->content_type != NULL))
    {
      osip_strncpy (tmp_body, CRLF, 2);
      tmp_body = tmp_body + 2;
    }
  if (length < tmp_body - ptr + body->length + 4)
    {
      size_t len;

      len = tmp_body - ptr;
      length = length + body->length + 4;
      ptr = osip_realloc (ptr, length);
      tmp_body = ptr + len;
    }
  memcpy(tmp_body,body->body,body->length);
  tmp_body = tmp_body + body->length;

  /* end of this body */
  if (str_length!=NULL)
     *str_length = tmp_body - ptr;
  *dest = ptr;
  return 0;

}

/* deallocates a body structure.  */
/* INPUT : osip_body_t *body | body.  */
void
osip_body_free (osip_body_t * body)
{
  if (body == NULL)
    return;
  osip_free (body->body);
  if (body->content_type != NULL)
    {
      osip_content_type_free (body->content_type);
    }

  {
    osip_header_t *header;

    while (!osip_list_eol (body->headers, 0))
      {
	header = (osip_header_t *) osip_list_get (body->headers, 0);
	osip_list_remove (body->headers, 0);
	osip_header_free (header);
      }
    osip_free (body->headers);
  }
  osip_free (body);
}
