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
#include "parser.h"


/* Accept-Encoding = token
   token possible values are gzip,compress,deflate,identity
*/
int
osip_message_set_accept_encoding (osip_message_t * sip, const char *hvalue)
{
  osip_accept_encoding_t *accept_encoding;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  i = osip_accept_encoding_init (&accept_encoding);
  if (i != 0)
    return -1;
  i = osip_accept_encoding_parse (accept_encoding, hvalue);
  if (i != 0)
    {
      osip_accept_encoding_free (accept_encoding);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->accept_encodings, accept_encoding, -1);
  return 0;
}

int
osip_message_get_accept_encoding (const osip_message_t * sip, int pos,
				  osip_accept_encoding_t ** dest)
{
  osip_accept_encoding_t *accept_encoding;

  *dest = NULL;
  if (osip_list_size (sip->accept_encodings) <= pos)
    return -1;			/* does not exist */
  accept_encoding =
    (osip_accept_encoding_t *) osip_list_get (sip->accept_encodings, pos);
  *dest = accept_encoding;
  return pos;
}

int
osip_accept_encoding_init (osip_accept_encoding_t ** accept_encoding)
{
  *accept_encoding =
    (osip_accept_encoding_t *) osip_malloc (sizeof (osip_accept_encoding_t));
  if (*accept_encoding == NULL)
    return -1;
  (*accept_encoding)->element = NULL;

  (*accept_encoding)->gen_params =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  if ((*accept_encoding)->gen_params == NULL)
    {
      osip_free (*accept_encoding);
      *accept_encoding = NULL;
      return -1;
    }
  osip_list_init ((*accept_encoding)->gen_params);

  return 0;
}

int
osip_accept_encoding_parse (osip_accept_encoding_t * accept_encoding,
			    const char *hvalue)
{
  const char *osip_accept_encoding_params;

  osip_accept_encoding_params = strchr (hvalue, ';');

  if (osip_accept_encoding_params != NULL)
    {
      if (__osip_generic_param_parseall (accept_encoding->gen_params,
					 osip_accept_encoding_params) == -1)
	return -1;
    }
  else
    osip_accept_encoding_params = hvalue + strlen (hvalue);

  if (osip_accept_encoding_params - hvalue + 1 < 2)
    return -1;
  accept_encoding->element =
    (char *) osip_malloc (osip_accept_encoding_params - hvalue + 1);
  if (accept_encoding->element == NULL)
    return -1;
  osip_strncpy (accept_encoding->element, hvalue,
		osip_accept_encoding_params - hvalue);
  osip_clrspace (accept_encoding->element);

  return 0;
}

/* returns the accept_encoding header as a string.  */
/* INPUT : osip_accept_encoding_t *accept_encoding | accept_encoding header.   */
/* returns null on error. */
int
osip_accept_encoding_to_str (const osip_accept_encoding_t * accept_encoding,
			     char **dest)
{
  char *buf;
  char *tmp;
  size_t len;

  *dest = NULL;
  if ((accept_encoding == NULL) || (accept_encoding->element == NULL))
    return -1;

  len = strlen (accept_encoding->element) + 2;
  buf = (char *) osip_malloc (len);
  if (buf == NULL)
    return -1;

  sprintf (buf, "%s", accept_encoding->element);
  {
    int pos = 0;
    size_t plen;
    osip_generic_param_t *u_param;

    while (!osip_list_eol (accept_encoding->gen_params, pos))
      {
	u_param =
	  (osip_generic_param_t *) osip_list_get (accept_encoding->gen_params,
						  pos);
	if (u_param->gvalue == NULL)
	  plen = strlen (u_param->gname) + 2;
	else
	  plen = strlen (u_param->gname) + strlen (u_param->gvalue) + 3;
	len = len + plen;
	buf = (char *) osip_realloc (buf, len);
	tmp = buf;
	tmp = tmp + strlen (tmp);
	if (u_param->gvalue == NULL)
	  sprintf (tmp, ";%s", u_param->gname);
	else
	  sprintf (tmp, ";%s=%s", u_param->gname, u_param->gvalue);
	pos++;
      }
  }
  *dest = buf;
  return 0;
}

/* deallocates a osip_accept_encoding_t structure.  */
/* INPUT : osip_accept_encoding_t *accept_encoding | accept_encoding. */
void
osip_accept_encoding_free (osip_accept_encoding_t * accept_encoding)
{
  if (accept_encoding == NULL)
    return;
  osip_free (accept_encoding->element);

  osip_generic_param_freelist (accept_encoding->gen_params);

  accept_encoding->element = NULL;
  accept_encoding->gen_params = NULL;
  osip_free (accept_encoding);
}

int
osip_accept_encoding_clone (const osip_accept_encoding_t * ctt,
			    osip_accept_encoding_t ** dest)
{
  int i;
  osip_accept_encoding_t *ct;

  *dest = NULL;
  if (ctt == NULL)
    return -1;
  if (ctt->element == NULL)
    return -1;

  i = osip_accept_encoding_init (&ct);
  if (i != 0)			/* allocation failed */
    return -1;
  ct->element = osip_strdup (ctt->element);
  if (ctt->element != NULL && ct->element == NULL)
    {
      osip_accept_encoding_free (ct);
      return -1;
    }
  {
    int pos = 0;
    osip_generic_param_t *u_param;
    osip_generic_param_t *dest_param;

    while (!osip_list_eol (ctt->gen_params, pos))
      {
	u_param =
	  (osip_generic_param_t *) osip_list_get (ctt->gen_params, pos);
	i = osip_generic_param_clone (u_param, &dest_param);
	if (i != 0)
	  {
	    osip_accept_encoding_free (ct);
	    return -1;
	  }
	osip_list_add (ct->gen_params, dest_param, -1);
	pos++;
      }
  }
  *dest = ct;
  return 0;
}


char *
osip_accept_encoding_get_element (const osip_accept_encoding_t * ae)
{
  return ae->element;
}

void
osip_accept_encoding_set_element (osip_accept_encoding_t * ae, char *element)
{
  ae->element = element;
}
