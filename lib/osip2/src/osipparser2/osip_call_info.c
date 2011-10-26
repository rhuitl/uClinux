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

int
osip_message_set_call_info (osip_message_t * sip, const char *hvalue)
{
  osip_call_info_t *call_info;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  i = osip_call_info_init (&call_info);
  if (i != 0)
    return -1;
  i = osip_call_info_parse (call_info, hvalue);
  if (i != 0)			/* allocation failed */
    {
      osip_call_info_free (call_info);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->call_infos, call_info, -1);
  return 0;
}

int
osip_message_get_call_info (const osip_message_t * sip, int pos,
			    osip_call_info_t ** dest)
{
  osip_call_info_t *call_info;

  *dest = NULL;
  if (osip_list_size (sip->call_infos) <= pos)
    return -1;			/* does not exist */
  call_info = (osip_call_info_t *) osip_list_get (sip->call_infos, pos);
  *dest = call_info;
  return pos;
}

int
osip_call_info_init (osip_call_info_t ** call_info)
{
  *call_info = (osip_call_info_t *) osip_malloc (sizeof (osip_call_info_t));
  if (*call_info == NULL)
    return -1;

  (*call_info)->element = NULL;

  (*call_info)->gen_params =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  if ((*call_info)->gen_params == NULL)
    {
      osip_free (*call_info);
      *call_info = NULL;
      return -1;
    }
  osip_list_init ((*call_info)->gen_params);

  return 0;
}

int
osip_call_info_parse (osip_call_info_t * call_info, const char *hvalue)
{
  const char *osip_call_info_params;

  osip_call_info_params = strchr (hvalue, '<');
  if (osip_call_info_params == NULL)
    return -1;

  osip_call_info_params = strchr (osip_call_info_params + 1, '>');
  if (osip_call_info_params == NULL)
    return -1;

  osip_call_info_params = strchr (osip_call_info_params + 1, ';');

  if (osip_call_info_params != NULL)
    {
      if (__osip_generic_param_parseall
	  (call_info->gen_params, osip_call_info_params) == -1)
	return -1;
    }
  else
    osip_call_info_params = hvalue + strlen (hvalue);

  if (osip_call_info_params - hvalue + 1 < 2)
    return -1;
  call_info->element =
    (char *) osip_malloc (osip_call_info_params - hvalue + 1);
  if (call_info->element == NULL)
    return -1;
  osip_strncpy (call_info->element, hvalue, osip_call_info_params - hvalue);
  osip_clrspace (call_info->element);

  return 0;
}

/* returns the call_info header as a string.  */
/* INPUT : osip_call_info_t *call_info | call_info header.   */
/* returns null on error. */
int
osip_call_info_to_str (const osip_call_info_t * call_info, char **dest)
{
  char *buf;
  char *tmp;
  size_t len;
  size_t plen;

  *dest = NULL;
  if ((call_info == NULL) || (call_info->element == NULL))
    return -1;

  len = strlen (call_info->element) + 2;
  buf = (char *) osip_malloc (len);
  if (buf == NULL)
    return -1;
  *dest = buf;

  sprintf (buf, "%s", call_info->element);

  {
    int pos = 0;
    osip_generic_param_t *u_param;

    while (!osip_list_eol (call_info->gen_params, pos))
      {
	u_param =
	  (osip_generic_param_t *) osip_list_get (call_info->gen_params, pos);
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


/* deallocates a osip_call_info_t structure.  */
/* INPUT : osip_call_info_t *call_info | call_info. */
void
osip_call_info_free (osip_call_info_t * call_info)
{
  if (call_info == NULL)
    return;
  osip_free (call_info->element);

  osip_generic_param_freelist (call_info->gen_params);

  call_info->element = NULL;
  call_info->gen_params = NULL;

  osip_free (call_info);
}

int
osip_call_info_clone (const osip_call_info_t * ctt, osip_call_info_t ** dest)
{
  int i;
  osip_call_info_t *ct;

  *dest = NULL;
  if (ctt == NULL)
    return -1;
  if (ctt->element == NULL)
    return -1;

  i = osip_call_info_init (&ct);
  if (i != 0)			/* allocation failed */
    return -1;
  ct->element = osip_strdup (ctt->element);

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
	    osip_call_info_free (ct);
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
osip_call_info_get_uri (osip_call_info_t * ae)
{
  return ae->element;
}

void
osip_call_info_set_uri (osip_call_info_t * ae, char *uri)
{
  ae->element = uri;
}
