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
osip_www_authenticate_init (osip_www_authenticate_t ** dest)
{
  *dest =
    (osip_www_authenticate_t *)
    osip_malloc (sizeof (osip_www_authenticate_t));
  if (*dest == NULL)
    return -1;
  (*dest)->auth_type = NULL;
  (*dest)->realm = NULL;
  (*dest)->domain = NULL;	/* optionnal */
  (*dest)->nonce = NULL;
  (*dest)->opaque = NULL;	/* optionnal */
  (*dest)->stale = NULL;	/* optionnal */
  (*dest)->algorithm = NULL;	/* optionnal */
  (*dest)->qop_options = NULL;	/* optionnal (contains a list of qop-value) */
  (*dest)->auth_param = NULL;
  return 0;
}

/* fills the www-authenticate header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_www_authenticate (osip_message_t * sip, const char *hvalue)
{
  osip_www_authenticate_t *www_authenticate;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  if (sip == NULL || sip->www_authenticates == NULL)
    return -1;
  i = osip_www_authenticate_init (&www_authenticate);
  if (i != 0)
    return -1;
  i = osip_www_authenticate_parse (www_authenticate, hvalue);
  if (i != 0)
    {
      osip_www_authenticate_free (www_authenticate);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->www_authenticates, www_authenticate, -1);
  return 0;
}

int
__osip_quoted_string_set (const char *name, const char *str,
			  char **result, const char **next)
{
  *next = str;
  if (*result != NULL)
    return 0;			/* already parsed */
  *next = NULL;
  while ((' ' == *str) || ('\t' == *str) || (',' == *str))
    if (*str)
      str++;
    else
      return -1;		/* bad header format */

  if (strlen (str) <= strlen (name))
    return -1;			/* bad header format... */
  if (osip_strncasecmp (name, str, strlen (name)) == 0)
    {
      const char *quote1;
      const char *quote2;
      const char *tmp;
      const char *hack = strchr (str, '=');
      
      if (hack == NULL)
        return -1;

      while (' ' == *(hack - 1))	/* get rid of extra spaces */
	hack--;
      if ((size_t) (hack - str) != strlen (name))
	{
	  *next = str;
	  return 0;
	}

      quote1 = __osip_quote_find (str);
      if (quote1 == NULL)
	return -1;		/* bad header format... */
      quote2 = __osip_quote_find (quote1 + 1);
      if (quote2 == NULL)
	return -1;		/* bad header format... */
      if (quote2 - quote1 == 1)
	{
	  /* this is a special case! The quote contains nothing! */
	  /* example:   Digest opaque="",cnonce=""               */
	  /* in this case, we just forget the parameter... this  */
	  /* this should prevent from user manipulating empty    */
	  /* strings */
	  tmp = quote2 + 1;	/* next element start here */
	  for (; *tmp == ' ' || *tmp == '\t'; tmp++)
	    {
	    }
	  for (; *tmp == '\n' || *tmp == '\r'; tmp++)
	    {
	    }			/* skip LWS */
	  *next = NULL;
	  if (*tmp == '\0')	/* end of header detected */
	    return 0;
	  if (*tmp != '\t' && *tmp != ' ')
	    /* LWS here ? */
	    *next = tmp;
	  else
	    {			/* it is: skip it... */
	      for (; *tmp == ' ' || *tmp == '\t'; tmp++)
		{
		}
	      if (*tmp == '\0')	/* end of header detected */
		return 0;
	      *next = tmp;
	    }
	  return 0;
	}
      *result = (char *) osip_malloc (quote2 - quote1 + 3);
      if (*result == NULL)
	return -1;
      osip_strncpy (*result, quote1, quote2 - quote1 + 1);
      tmp = quote2 + 1;		/* next element start here */
      for (; *tmp == ' ' || *tmp == '\t'; tmp++)
	{
	}
      for (; *tmp == '\n' || *tmp == '\r'; tmp++)
	{
	}			/* skip LWS */
      *next = NULL;
      if (*tmp == '\0')		/* end of header detected */
	return 0;
      if (*tmp != '\t' && *tmp != ' ')
	/* LWS here ? */
	*next = tmp;
      else
	{			/* it is: skip it... */
	  for (; *tmp == ' ' || *tmp == '\t'; tmp++)
	    {
	    }
	  if (*tmp == '\0')	/* end of header detected */
	    return 0;
	  *next = tmp;
	}
    }
  else
    *next = str;		/* wrong header asked! */
  return 0;
}

int
__osip_token_set (const char *name, const char *str, char **result,
		  const char **next)
{
  const char *beg;
  const char *tmp;

  *next = str;
  if (*result != NULL)
    return 0;			/* already parsed */
  *next = NULL;

  beg = strchr (str, '=');
  if (beg == NULL)
    return -1;			/* bad header format... */

  if (strlen (str) < 6)
    return 0;			/* end of header... */

  while ((' ' == *str) || ('\t' == *str) || (',' == *str))
    if (*str)
      str++;
    else
      return -1;		/* bad header format */

  if (osip_strncasecmp (name, str, strlen (name)) == 0)
    {
      const char *end;

      end = strchr (str, ',');
      if (end == NULL)
	end = str + strlen (str);	/* This is the end of the header */

      if (end - beg < 2)
	return -1;
      *result = (char *) osip_malloc (end - beg);
      if (*result == NULL)
	return -1;
      osip_strncpy (*result, beg + 1, end - beg - 1);
      osip_clrspace (*result);

      /* make sure the element does not contain more parameter */
      tmp = (*end) ? (end + 1) : end;
      for (; *tmp == ' ' || *tmp == '\t'; tmp++)
	{
	}
      for (; *tmp == '\n' || *tmp == '\r'; tmp++)
	{
	}			/* skip LWS */
      *next = NULL;
      if (*tmp == '\0')		/* end of header detected */
	return 0;
      if (*tmp != '\t' && *tmp != ' ')
	/* LWS here ? */
	*next = tmp;
      else
	{			/* it is: skip it... */
	  for (; *tmp == ' ' || *tmp == '\t'; tmp++)
	    {
	    }
	  if (*tmp == '\0')	/* end of header detected */
	    return 0;
	  *next = tmp;
	}
    }
  else
    *next = str;		/* next element start here */
  return 0;
}

/* fills the www-authenticate strucuture.                      */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int
osip_www_authenticate_parse (osip_www_authenticate_t * wwwa,
			     const char *hvalue)
{
  const char *space;
  const char *next = NULL;

  space = strchr (hvalue, ' ');	/* SEARCH FOR SPACE */
  if (space == NULL)
    return -1;

  if (space - hvalue + 1 < 2)
    return -1;
  wwwa->auth_type = (char *) osip_malloc (space - hvalue + 1);
  if (wwwa->auth_type == NULL)
    return -1;
  osip_strncpy (wwwa->auth_type, hvalue, space - hvalue);

  for (;;)
    {
      int parse_ok = 0;

      if (__osip_quoted_string_set ("realm", space, &(wwwa->realm), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("domain", space, &(wwwa->domain), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("nonce", space, &(wwwa->nonce), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("opaque", space, &(wwwa->opaque), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("stale", space, &(wwwa->stale), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("algorithm", space, &(wwwa->algorithm), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set
	  ("qop", space, &(wwwa->qop_options), &next))
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

/* returns the www_authenticate header.            */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int
osip_message_get_www_authenticate (const osip_message_t * sip, int pos,
				   osip_www_authenticate_t ** dest)
{
  osip_www_authenticate_t *www_authenticate;

  *dest = NULL;
  if (osip_list_size (sip->www_authenticates) <= pos)
    return -1;			/* does not exist */

  www_authenticate =
    (osip_www_authenticate_t *) osip_list_get (sip->www_authenticates, pos);

  *dest = www_authenticate;
  return pos;
}

char *
osip_www_authenticate_get_auth_type (osip_www_authenticate_t *
				     www_authenticate)
{
  return www_authenticate->auth_type;
}

void
osip_www_authenticate_set_auth_type (osip_www_authenticate_t *
				     www_authenticate, char *auth_type)
{
  www_authenticate->auth_type = (char *) auth_type;
}

char *
osip_www_authenticate_get_realm (osip_www_authenticate_t * www_authenticate)
{
  return www_authenticate->realm;
}

void
osip_www_authenticate_set_realm (osip_www_authenticate_t * www_authenticate,
				 char *realm)
{
  www_authenticate->realm = (char *) realm;
}

char *
osip_www_authenticate_get_domain (osip_www_authenticate_t * www_authenticate)
{
  return www_authenticate->domain;
}

void
osip_www_authenticate_set_domain (osip_www_authenticate_t * www_authenticate,
				  char *domain)
{
  www_authenticate->domain = (char *) domain;
}

char *
osip_www_authenticate_get_nonce (osip_www_authenticate_t * www_authenticate)
{
  return www_authenticate->nonce;
}

void
osip_www_authenticate_set_nonce (osip_www_authenticate_t * www_authenticate,
				 char *nonce)
{
  www_authenticate->nonce = (char *) nonce;
}

char *
osip_www_authenticate_get_stale (osip_www_authenticate_t * www_authenticate)
{
  return www_authenticate->stale;
}

void
osip_www_authenticate_set_stale (osip_www_authenticate_t * www_authenticate,
				 char *stale)
{
  www_authenticate->stale = (char *) stale;
}

char *
osip_www_authenticate_get_opaque (osip_www_authenticate_t * www_authenticate)
{
  return www_authenticate->opaque;
}

void
osip_www_authenticate_set_opaque (osip_www_authenticate_t * www_authenticate,
				  char *opaque)
{
  www_authenticate->opaque = (char *) opaque;
}

char *
osip_www_authenticate_get_algorithm (osip_www_authenticate_t *
				     www_authenticate)
{
  return www_authenticate->algorithm;
}

void
osip_www_authenticate_set_algorithm (osip_www_authenticate_t *
				     www_authenticate, char *algorithm)
{
  www_authenticate->algorithm = (char *) algorithm;
}

char *
osip_www_authenticate_get_qop_options (osip_www_authenticate_t *
				       www_authenticate)
{
  return www_authenticate->qop_options;
}

void
osip_www_authenticate_set_qop_options (osip_www_authenticate_t *
				       www_authenticate, char *qop_options)
{
  www_authenticate->qop_options = (char *) qop_options;
}



/* returns the www_authenticate header as a string.          */
/* INPUT : osip_www_authenticate_t *www_authenticate | www_authenticate header.  */
/* returns null on error. */
int
osip_www_authenticate_to_str (const osip_www_authenticate_t * wwwa,
			      char **dest)
{
  size_t len;
  char *tmp;

  *dest = NULL;
  if ((wwwa == NULL) || (wwwa->auth_type == NULL) || (wwwa->realm == NULL)
      || (wwwa->nonce == NULL))
    return -1;

  len = strlen (wwwa->auth_type) + 1;

  if (wwwa->realm != NULL)
    len = len + strlen (wwwa->realm) + 7;
  if (wwwa->nonce != NULL)
    len = len + strlen (wwwa->nonce) + 8;
  len = len + 2;
  if (wwwa->domain != NULL)
    len = len + strlen (wwwa->domain) + 9;
  if (wwwa->opaque != NULL)
    len = len + strlen (wwwa->opaque) + 9;
  if (wwwa->stale != NULL)
    len = len + strlen (wwwa->stale) + 8;
  if (wwwa->algorithm != NULL)
    len = len + strlen (wwwa->algorithm) + 12;
  if (wwwa->qop_options != NULL)
    len = len + strlen (wwwa->qop_options) + 6;

  tmp = (char *) osip_malloc (len);
  if (tmp == NULL)
    return -1;
  *dest = tmp;

  osip_strncpy (tmp, wwwa->auth_type, strlen (wwwa->auth_type));
  tmp = tmp + strlen (tmp);

  if (wwwa->realm != NULL)
    {
      osip_strncpy (tmp, " realm=", 7);
      tmp = tmp + 7;
      osip_strncpy (tmp, wwwa->realm, strlen (wwwa->realm));
      tmp = tmp + strlen (tmp);
    }
  if (wwwa->domain != NULL)
    {
      osip_strncpy (tmp, ", domain=", 9);
      tmp = tmp + 9;
      osip_strncpy (tmp, wwwa->domain, strlen (wwwa->domain));
      tmp = tmp + strlen (tmp);
    }
  if (wwwa->nonce != NULL)
    {
      osip_strncpy (tmp, ", nonce=", 8);
      tmp = tmp + 8;
      osip_strncpy (tmp, wwwa->nonce, strlen (wwwa->nonce));
      tmp = tmp + strlen (tmp);
    }
  if (wwwa->opaque != NULL)
    {
      osip_strncpy (tmp, ", opaque=", 9);
      tmp = tmp + 9;
      osip_strncpy (tmp, wwwa->opaque, strlen (wwwa->opaque));
      tmp = tmp + strlen (tmp);
    }
  if (wwwa->stale != NULL)
    {
      osip_strncpy (tmp, ", stale=", 8);
      tmp = tmp + 8;
      osip_strncpy (tmp, wwwa->stale, strlen (wwwa->stale));
      tmp = tmp + strlen (tmp);
    }
  if (wwwa->algorithm != NULL)
    {
      osip_strncpy (tmp, ", algorithm=", 12);
      tmp = tmp + 12;
      osip_strncpy (tmp, wwwa->algorithm, strlen (wwwa->algorithm));
      tmp = tmp + strlen (tmp);
    }
  if (wwwa->qop_options != NULL)
    {
      osip_strncpy (tmp, ", qop=", 6);
      tmp = tmp + 6;
      osip_strncpy (tmp, wwwa->qop_options, strlen (wwwa->qop_options));
      tmp = tmp + strlen (tmp);
    }

  return 0;
}

/* deallocates a osip_www_authenticate_t structure.  */
/* INPUT : osip_www_authenticate_t *www_authenticate | www_authenticate. */
void
osip_www_authenticate_free (osip_www_authenticate_t * www_authenticate)
{
  if (www_authenticate == NULL)
    return;

  osip_free (www_authenticate->auth_type);
  osip_free (www_authenticate->realm);
  osip_free (www_authenticate->domain);
  osip_free (www_authenticate->nonce);
  osip_free (www_authenticate->opaque);
  osip_free (www_authenticate->stale);
  osip_free (www_authenticate->algorithm);
  osip_free (www_authenticate->qop_options);

  osip_free (www_authenticate);
}

int
osip_www_authenticate_clone (const osip_www_authenticate_t * wwwa,
			     osip_www_authenticate_t ** dest)
{
  int i;
  osip_www_authenticate_t *wa;

  *dest = NULL;
  if (wwwa == NULL)
    return -1;
  if (wwwa->auth_type == NULL)
    return -1;
  if (wwwa->realm == NULL)
    return -1;
  if (wwwa->nonce == NULL)
    return -1;

  i = osip_www_authenticate_init (&wa);
  if (i == -1)			/* allocation failed */
    return -1;
  wa->auth_type = osip_strdup (wwwa->auth_type);
  wa->realm = osip_strdup (wwwa->realm);
  if (wwwa->domain != NULL)
    wa->domain = osip_strdup (wwwa->domain);
  wa->nonce = osip_strdup (wwwa->nonce);
  if (wwwa->opaque != NULL)
    wa->opaque = osip_strdup (wwwa->opaque);
  if (wwwa->stale != NULL)
    wa->stale = osip_strdup (wwwa->stale);
  if (wwwa->algorithm != NULL)
    wa->algorithm = osip_strdup (wwwa->algorithm);
  if (wwwa->qop_options != NULL)
    wa->qop_options = osip_strdup (wwwa->qop_options);

  *dest = wa;
  return 0;
}
