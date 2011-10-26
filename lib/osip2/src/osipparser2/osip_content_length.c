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
osip_content_length_init (osip_content_length_t ** cl)
{
  *cl =
    (osip_content_length_t *) osip_malloc (sizeof (osip_content_length_t));
  if (*cl == NULL)
    return -1;
  (*cl)->value = NULL;
  return 0;
}

/* adds the content_length header to message.       */
/* INPUT : const char *hvalue | value of header.    */
/* OUTPUT: osip_message_t *sip | structure to save results.  */
/* returns -1 on error. */
int
osip_message_set_content_length (osip_message_t * sip, const char *hvalue)
{
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  if (sip->content_length != NULL)
    return -1;
  i = osip_content_length_init (&(sip->content_length));
  if (i != 0)
    return -1;
  sip->message_property = 2;
  i = osip_content_length_parse (sip->content_length, hvalue);
  if (i != 0)
    {
      osip_content_length_free (sip->content_length);
      sip->content_length = NULL;
      return -1;
    }

  return 0;
}

int
osip_content_length_parse (osip_content_length_t * content_length,
			   const char *hvalue)
{
  if (strlen (hvalue) + 1 < 2)
    return -1;
  content_length->value = (char *) osip_malloc (strlen (hvalue) + 1);
  if (content_length->value == NULL)
    return -1;
  osip_strncpy (content_length->value, hvalue, strlen (hvalue));
  return 0;
}

/* returns the content_length header.            */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
osip_content_length_t *
osip_message_get_content_length (const osip_message_t * sip)
{
  return sip->content_length;
}

/* returns the content_length header as a string.          */
/* INPUT : osip_content_length_t *content_length | content_length header.  */
/* returns null on error. */
int
osip_content_length_to_str (const osip_content_length_t * cl, char **dest)
{
  if (cl == NULL)
    return -1;
  *dest = osip_strdup (cl->value);
  return 0;
}

/* deallocates a osip_content_length_t strcture.  */
/* INPUT : osip_content_length_t *content_length | content_length header. */
void
osip_content_length_free (osip_content_length_t * content_length)
{
  if (content_length == NULL)
    return;
  osip_free (content_length->value);
  osip_free (content_length);
}

int
osip_content_length_clone (const osip_content_length_t * ctl,
			   osip_content_length_t ** dest)
{
  int i;
  osip_content_length_t *cl;

  *dest = NULL;
  if (ctl == NULL)
    return -1;
  /*
     empty headers are allowed:
     if (ctl->value==NULL) return -1;
   */
  i = osip_content_length_init (&cl);
  if (i == -1)			/* allocation failed */
    return -1;
  if (ctl->value != NULL)
    cl->value = osip_strdup (ctl->value);

  *dest = cl;
  return 0;
}
