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
osip_authentication_info_init (osip_authentication_info_t ** dest)
{
  *dest = (osip_authentication_info_t *) osip_malloc (sizeof (osip_authentication_info_t));
  if (*dest == NULL)
    return -1;
  (*dest)->nextnonce = NULL;
  (*dest)->qop_options = NULL;
  (*dest)->rspauth = NULL;
  (*dest)->cnonce = NULL;
  (*dest)->nonce_count = NULL;
  return 0;
}

/* fills the www-authenticate header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_authentication_info (osip_message_t * sip, const char *hvalue)
{
  osip_authentication_info_t *authentication_info;
  int i;

  if (hvalue==NULL || hvalue[0]=='\0')
    return 0;

  if (sip == NULL || sip->authentication_infos == NULL)
    return -1;
  i = osip_authentication_info_init (&authentication_info);
  if (i != 0)
    return -1;
  i = osip_authentication_info_parse (authentication_info, hvalue);
  if (i != 0)
    {
      osip_authentication_info_free (authentication_info);
      return -1;
    }
#ifdef USE_TMP_BUFFER
  sip->message_property = 2;
#endif
  osip_list_add (sip->authentication_infos, authentication_info, -1);
  return 0;
}

/* fills the authentication_info strucuture.                      */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int
osip_authentication_info_parse (osip_authentication_info_t * ainfo, const char *hvalue)
{
  const char *space;
  const char *next = NULL;

  space = hvalue;

  for (;;)
    {
      int parse_ok = 0;

      if (__osip_quoted_string_set ("nextnonce", space, &(ainfo->nextnonce), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("cnonce", space, &(ainfo->cnonce), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("rspauth", space, &(ainfo->rspauth), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("nc", space, &(ainfo->nonce_count), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("qop", space, &(ainfo->qop_options), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (0 == parse_ok)
	{
	  char *quote1, *quote2, *tmp;

	  /* CAUTION */
	  /* parameter not understood!!! I'm too lazy to handle IT */
	  /* let's simply bypass it */
	  if (strlen (space) < 1)
	    return 0;
	  tmp = strchr (space + 1, ',');
	  if (tmp == NULL)	/* it was the last header */
	    return 0;
	  quote1 = __osip_quote_find (space);
	  if ((quote1 != NULL) && (quote1 < tmp))	/* this may be a quoted string! */
	    {
	      quote2 = __osip_quote_find (quote1 + 1);
	      if (quote2 == NULL)
		return -1;	/* bad header format... */
	      if (tmp < quote2)	/* the comma is inside the quotes! */
		space = strchr (quote2, ',');
	      else
		space = tmp;
	      if (space == NULL)	/* it was the last header */
		return 0;
	    }
	  else
	    space = tmp;
	  /* continue parsing... */
	}
    }
  return 0;			/* ok */
}

/* returns the authentication_info header.            */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int
osip_message_get_authentication_info (const osip_message_t * sip, int pos,
			 osip_authentication_info_t ** dest)
{
  osip_authentication_info_t *authentication_info;

  *dest = NULL;
  if (osip_list_size (sip->authentication_infos) <= pos)
    return -1;			/* does not exist */

  authentication_info =
    (osip_authentication_info_t *) osip_list_get (sip->authentication_infos, pos);

  *dest = authentication_info;
  return pos;
}

char *
osip_authentication_info_get_nextnonce (osip_authentication_info_t * authentication_info)
{
  return authentication_info->nextnonce;
}

void
osip_authentication_info_set_nextnonce (osip_authentication_info_t * authentication_info,
			       char *nextnonce)
{
  authentication_info->nextnonce = (char *) nextnonce;
}

char *
osip_authentication_info_get_cnonce (osip_authentication_info_t * authentication_info)
{
  return authentication_info->cnonce;
}

void
osip_authentication_info_set_cnonce (osip_authentication_info_t * authentication_info, char *cnonce)
{
  authentication_info->cnonce = (char *) cnonce;
}

char *
osip_authentication_info_get_rspauth (osip_authentication_info_t * authentication_info)
{
  return authentication_info->rspauth;
}

void
osip_authentication_info_set_rspauth (osip_authentication_info_t * authentication_info,
			    char *rspauth)
{
  authentication_info->rspauth = (char *) rspauth;
}

char *
osip_authentication_info_get_nonce_count (osip_authentication_info_t * authentication_info)
{
  return authentication_info->nonce_count;
}

void
osip_authentication_info_set_nonce_count (osip_authentication_info_t * authentication_info, char *nonce_count)
{
  authentication_info->nonce_count = (char *) nonce_count;
}

char *
osip_authentication_info_get_qop_options (osip_authentication_info_t * authentication_info)
{
  return authentication_info->qop_options;
}

void
osip_authentication_info_set_qop_options (osip_authentication_info_t * authentication_info,
				 char *qop_options)
{
  authentication_info->qop_options = (char *) qop_options;
}



/* returns the authentication_info header as a string.          */
/* INPUT : osip_authentication_info_t *authentication_info | authentication_info header.  */
/* returns null on error. */
int
osip_authentication_info_to_str (const osip_authentication_info_t * ainfo, char **dest)
{
  int len;
  char *tmp;

  *dest = NULL;
  if (ainfo == NULL)
    return -1;

  len = 0;
  if (ainfo->nextnonce != NULL)
    len = len + strlen (ainfo->nextnonce) + 11;
  if (ainfo->rspauth != NULL)
    len = len + strlen (ainfo->rspauth) + 10;
  if (ainfo->cnonce != NULL)
    len = len + strlen (ainfo->cnonce) + 9;
  if (ainfo->nonce_count != NULL)
    len = len + strlen (ainfo->nonce_count) + 5;
  if (ainfo->qop_options != NULL)
    len = len + strlen (ainfo->qop_options) + 6;

  tmp = (char *) osip_malloc (len);
  if (tmp == NULL)
    return -1;
  *dest = tmp;

  if (ainfo->qop_options != NULL)
    {
      osip_strncpy (tmp, "qop=", 4);
      tmp = tmp + 4;
      osip_strncpy (tmp, ainfo->qop_options, strlen (ainfo->qop_options));
      tmp = tmp + strlen (tmp);
    }
  if (ainfo->nextnonce != NULL)
    {
      if (tmp!=*dest)
	{
	  osip_strncpy (tmp, ", ", 2);
	  tmp = tmp + 2;
	}      
      osip_strncpy (tmp, "nextnonce=", 10);
      tmp = tmp + 10;
      osip_strncpy (tmp, ainfo->nextnonce, strlen (ainfo->nextnonce));
      tmp = tmp + strlen (tmp);
    }
  if (ainfo->rspauth != NULL)
    {
      if (tmp!=*dest)
	{
	  osip_strncpy (tmp, ", ", 2);
	  tmp = tmp + 2;
	}      
      osip_strncpy (tmp, "rspauth=", 8);
      tmp = tmp + 8;
      osip_strncpy (tmp, ainfo->rspauth, strlen (ainfo->rspauth));
      tmp = tmp + strlen (tmp);
    }
  if (ainfo->cnonce != NULL)
    {
      if (tmp!=*dest)
	{
	  osip_strncpy (tmp, ", ", 2);
	  tmp = tmp + 2;
	}      
      osip_strncpy (tmp, "cnonce=", 7);
      tmp = tmp + 7;
      osip_strncpy (tmp, ainfo->cnonce, strlen (ainfo->cnonce));
      tmp = tmp + strlen (tmp);
    }
  if (ainfo->nonce_count != NULL)
    {
      if (tmp!=*dest)
	{
	  osip_strncpy (tmp, ", ", 2);
	  tmp = tmp + 2;
	}      
      osip_strncpy (tmp, "nc=", 3);
      tmp = tmp + 3;
      osip_strncpy (tmp, ainfo->nonce_count, strlen (ainfo->nonce_count));
      tmp = tmp + strlen (tmp);
    }

  return 0;
}

/* deallocates a osip_authentication_info_t structure.  */
/* INPUT : osip_authentication_info_t *authentication_info | authentication_info. */
void
osip_authentication_info_free (osip_authentication_info_t * authentication_info)
{
  if (authentication_info == NULL)
    return;

  osip_free (authentication_info->nextnonce);
  osip_free (authentication_info->rspauth);
  osip_free (authentication_info->cnonce);
  osip_free (authentication_info->nonce_count);
  osip_free (authentication_info->qop_options);
  osip_free (authentication_info);
}

int
osip_authentication_info_clone (const osip_authentication_info_t * ainfo,
			osip_authentication_info_t ** dest)
{
  int i;
  osip_authentication_info_t *wa;

  *dest = NULL;
  if (ainfo == NULL)
    return -1;

  i = osip_authentication_info_init (&wa);
  if (i == -1)			/* allocation failed */
    return -1;
  if (ainfo->nextnonce != NULL)
    wa->nextnonce = osip_strdup (ainfo->nextnonce);
  if (ainfo->cnonce != NULL)
    wa->cnonce = osip_strdup (ainfo->cnonce);
  if (ainfo->rspauth != NULL)
    wa->rspauth = osip_strdup (ainfo->rspauth);
  if (ainfo->nonce_count != NULL)
    wa->nonce_count = osip_strdup (ainfo->nonce_count);
  if (ainfo->qop_options != NULL)
    wa->qop_options = osip_strdup (ainfo->qop_options);

  *dest = wa;
  return 0;
}
