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

/* content-Encoding = token
   token possible values are gzip,compress,deflate
*/
int
osip_message_set_content_encoding (osip_message_t * sip, const char *hvalue)
{
  osip_content_encoding_t *content_encoding;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  i = osip_content_encoding_init (&content_encoding);
  if (i != 0)
    return -1;
  i = osip_content_encoding_parse (content_encoding, hvalue);
  if (i != 0)
    {
      osip_content_encoding_free (content_encoding);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->content_encodings, content_encoding, -1);
  return 0;
}

int
osip_message_get_content_encoding (const osip_message_t * sip, int pos,
				   osip_content_encoding_t ** dest)
{
  osip_content_encoding_t *ce;

  *dest = NULL;
  if (osip_list_size (sip->content_encodings) <= pos)
    return -1;			/* does not exist */
  ce =
    (osip_content_encoding_t *) osip_list_get (sip->content_encodings, pos);
  *dest = ce;
  return pos;
}
