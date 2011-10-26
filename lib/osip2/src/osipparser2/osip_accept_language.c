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
osip_message_set_accept_language (osip_message_t * sip, const char *hvalue)
{
  osip_accept_language_t *accept_language;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  i = osip_accept_language_init (&accept_language);
  if (i != 0)
    return -1;
  i = osip_accept_language_parse (accept_language, hvalue);
  if (i != 0)
    {
      osip_accept_language_free (accept_language);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->accept_languages, accept_language, -1);
  return 0;
}

int
osip_message_get_accept_language (const osip_message_t * sip, int pos,
				  osip_accept_language_t ** dest)
{
  osip_accept_language_t *accept_language;

  *dest = NULL;
  if (osip_list_size (sip->accept_languages) <= pos)
    return -1;			/* does not exist */
  accept_language =
    (osip_accept_language_t *) osip_list_get (sip->accept_languages, pos);
  *dest = accept_language;
  return pos;
}
