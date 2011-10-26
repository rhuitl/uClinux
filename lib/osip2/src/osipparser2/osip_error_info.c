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
osip_message_set_error_info (osip_message_t * sip, const char *hvalue)
{
  osip_error_info_t *error_info;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  i = osip_error_info_init (&error_info);
  if (i != 0)
    return -1;
  i = osip_error_info_parse (error_info, hvalue);
  if (i != 0)
    {
      osip_error_info_free (error_info);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->error_infos, error_info, -1);
  return 0;
}

int
osip_message_get_error_info (const osip_message_t * sip, int pos,
			     osip_error_info_t ** dest)
{
  osip_error_info_t *error_info;

  *dest = NULL;
  if (osip_list_size (sip->error_infos) <= pos)
    return -1;			/* does not exist */
  error_info = (osip_error_info_t *) osip_list_get (sip->error_infos, pos);
  *dest = error_info;
  return pos;
}
