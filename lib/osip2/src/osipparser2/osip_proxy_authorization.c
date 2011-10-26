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


/* fills the proxy_authorization header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_proxy_authorization (osip_message_t * sip,
				      const char *hvalue)
{
  osip_proxy_authorization_t *proxy_authorization;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  i = osip_proxy_authorization_init (&proxy_authorization);
  if (i != 0)
    return -1;
  i = osip_proxy_authorization_parse (proxy_authorization, hvalue);
  if (i != 0)
    {
      osip_proxy_authorization_free (proxy_authorization);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->proxy_authorizations, proxy_authorization, -1);
  return 0;
}

int
osip_message_get_proxy_authorization (const osip_message_t * sip, int pos,
				      osip_proxy_authorization_t ** dest)
{
  osip_proxy_authorization_t *proxy_authorization;

  *dest = NULL;
  if (osip_list_size (sip->proxy_authorizations) <= pos)
    return -1;			/* does not exist */
  proxy_authorization =
    (osip_proxy_authorization_t *) osip_list_get (sip->proxy_authorizations,
						  pos);
  *dest = proxy_authorization;
  return pos;
}
