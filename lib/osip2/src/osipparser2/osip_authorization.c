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
osip_authorization_init (osip_authorization_t ** dest)
{
  *dest =
    (osip_authorization_t *) osip_malloc (sizeof (osip_authorization_t));
  if (*dest == NULL)
    return -1;
  (*dest)->auth_type = NULL;
  (*dest)->username = NULL;
  (*dest)->realm = NULL;
  (*dest)->nonce = NULL;
  (*dest)->uri = NULL;
  (*dest)->response = NULL;
  (*dest)->digest = NULL;	/* DO NOT USE IT IN AUTHORIZATION_T HEADER?? */
  (*dest)->algorithm = NULL;	/* optionnal, default is "md5" */
  (*dest)->cnonce = NULL;	/* optionnal */
  (*dest)->opaque = NULL;	/* optionnal */
  (*dest)->message_qop = NULL;	/* optionnal */
  (*dest)->nonce_count = NULL;	/* optionnal */
  (*dest)->auth_param = NULL;	/* for other headers --NOT IMPLEMENTED-- */
  return 0;
}

/* fills the www-authenticate header of message.               */
/* INPUT :  char *hvalue | value of header.   */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
int
osip_message_set_authorization (osip_message_t * sip, const char *hvalue)
{
  osip_authorization_t *authorization;
  int i;

  if (hvalue == NULL || hvalue[0] == '\0')
    return 0;

  if (sip == NULL || sip->authorizations == NULL)
    return -1;
  i = osip_authorization_init (&authorization);
  if (i != 0)
    return -1;
  i = osip_authorization_parse (authorization, hvalue);
  if (i != 0)
    {
      osip_authorization_free (authorization);
      return -1;
    }
  sip->message_property = 2;
  osip_list_add (sip->authorizations, authorization, -1);
  return 0;
}

/* fills the www-authenticate structure.           */
/* INPUT : char *hvalue | value of header.         */
/* OUTPUT: osip_message_t *sip | structure to save results. */
/* returns -1 on error. */
/* TODO:
   digest-challenge tken has no order preference??
   verify many situations (extra SP....)
*/
int
osip_authorization_parse (osip_authorization_t * auth, const char *hvalue)
{
  const char *space;
  const char *next = NULL;

  space = strchr (hvalue, ' ');	/* SEARCH FOR SPACE */
  if (space == NULL)
    return -1;

  if (space - hvalue < 1)
    return -1;
  auth->auth_type = (char *) osip_malloc (space - hvalue + 1);
  osip_strncpy (auth->auth_type, hvalue, space - hvalue);

  for (;;)
    {
      int parse_ok = 0;

      if (__osip_quoted_string_set
	  ("username", space, &(auth->username), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("realm", space, &(auth->realm), &next))
	return -1;
      if (next == NULL)
	return 0;
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("nonce", space, &(auth->nonce), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("uri", space, &(auth->uri), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set
	  ("response", space, &(auth->response), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("digest", space, &(auth->digest), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("algorithm", space, &(auth->algorithm), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("cnonce", space, &(auth->cnonce), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_quoted_string_set ("opaque", space, &(auth->opaque), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("qop", space, &(auth->message_qop), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      if (__osip_token_set ("nc", space, &(auth->nonce_count), &next))
	return -1;
      if (next == NULL)
	return 0;		/* end of header detected! */
      else if (next != space)
	{
	  space = next;
	  parse_ok++;
	}
      /* nothing was recognized:
         here, we should handle a list of unknown tokens where:
         token1 = ( token2 | quoted_text ) */
      /* TODO */

      if (0 == parse_ok)
	{
	  const char *quote1, *quote2, *tmp;

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

/* returns the authorization header.   */
/* INPUT : osip_message_t *sip | sip message.   */
/* returns null on error. */
int
osip_message_get_authorization (const osip_message_t * sip, int pos,
				osip_authorization_t ** dest)
{
  osip_authorization_t *authorization;

  *dest = NULL;
  if (osip_list_size (sip->authorizations) <= pos)
    return -1;			/* does not exist */
  authorization =
    (osip_authorization_t *) osip_list_get (sip->authorizations, pos);
  *dest = authorization;
  return pos;
}

char *
osip_authorization_get_auth_type (const osip_authorization_t * authorization)
{
  return authorization->auth_type;
}

void
osip_authorization_set_auth_type (osip_authorization_t * authorization,
				  char *auth_type)
{
  authorization->auth_type = (char *) auth_type;
}

char *
osip_authorization_get_username (osip_authorization_t * authorization)
{
  return authorization->username;
}

void
osip_authorization_set_username (osip_authorization_t * authorization,
				 char *username)
{
  authorization->username = (char *) username;
}

char *
osip_authorization_get_realm (osip_authorization_t * authorization)
{
  return authorization->realm;
}

void
osip_authorization_set_realm (osip_authorization_t * authorization,
			      char *realm)
{
  authorization->realm = (char *) realm;
}

char *
osip_authorization_get_nonce (osip_authorization_t * authorization)
{
  return authorization->nonce;
}

void
osip_authorization_set_nonce (osip_authorization_t * authorization,
			      char *nonce)
{
  authorization->nonce = (char *) nonce;
}

char *
osip_authorization_get_uri (osip_authorization_t * authorization)
{
  return authorization->uri;
}

void
osip_authorization_set_uri (osip_authorization_t * authorization, char *uri)
{
  authorization->uri = (char *) uri;
}

char *
osip_authorization_get_response (osip_authorization_t * authorization)
{
  return authorization->response;
}

void
osip_authorization_set_response (osip_authorization_t * authorization,
				 char *response)
{
  authorization->response = (char *) response;
}

char *
osip_authorization_get_digest (osip_authorization_t * authorization)
{
  return authorization->digest;
}

void
osip_authorization_set_digest (osip_authorization_t * authorization,
			       char *digest)
{
  authorization->digest = (char *) digest;
}

char *
osip_authorization_get_algorithm (osip_authorization_t * authorization)
{
  return authorization->algorithm;
}

void
osip_authorization_set_algorithm (osip_authorization_t * authorization,
				  char *algorithm)
{
  authorization->algorithm = (char *) algorithm;
}

char *
osip_authorization_get_cnonce (osip_authorization_t * authorization)
{
  return authorization->cnonce;
}

void
osip_authorization_set_cnonce (osip_authorization_t * authorization,
			       char *cnonce)
{
  authorization->cnonce = (char *) cnonce;
}

char *
osip_authorization_get_opaque (osip_authorization_t * authorization)
{
  return authorization->opaque;
}

void
osip_authorization_set_opaque (osip_authorization_t * authorization,
			       char *opaque)
{
  authorization->opaque = (char *) opaque;
}

char *
osip_authorization_get_message_qop (osip_authorization_t * authorization)
{
  return authorization->message_qop;
}

void
osip_authorization_set_message_qop (osip_authorization_t * authorization,
				    char *message_qop)
{
  authorization->message_qop = (char *) message_qop;
}

char *
osip_authorization_get_nonce_count (osip_authorization_t * authorization)
{
  return authorization->nonce_count;
}

void
osip_authorization_set_nonce_count (osip_authorization_t * authorization,
				    char *nonce_count)
{
  authorization->nonce_count = (char *) nonce_count;
}


/* returns the authorization header as a string.          */
/* INPUT : osip_authorization_t *authorization | authorization header.  */
/* returns null on error. */
int
osip_authorization_to_str (const osip_authorization_t * auth, char **dest)
{
  size_t len;
  char *tmp;

  *dest = NULL;
  /* DO NOT REALLY KNOW THE LIST OF MANDATORY PARAMETER: Please HELP! */
  if ((auth == NULL) || (auth->auth_type == NULL) || (auth->realm == NULL)
      || (auth->nonce == NULL))
    return -1;

  len = strlen (auth->auth_type) + 1;
  if (auth->username != NULL)
    len = len + 10 + strlen (auth->username);
  if (auth->realm != NULL)
    len = len + 8 + strlen (auth->realm);
  if (auth->nonce != NULL)
    len = len + 8 + strlen (auth->nonce);
  if (auth->uri != NULL)
    len = len + 6 + strlen (auth->uri);
  if (auth->response != NULL)
    len = len + 11 + strlen (auth->response);
  len = len + 2;
  if (auth->digest != NULL)
    len = len + strlen (auth->digest) + 9;
  if (auth->algorithm != NULL)
    len = len + strlen (auth->algorithm) + 12;
  if (auth->cnonce != NULL)
    len = len + strlen (auth->cnonce) + 9;
  if (auth->opaque != NULL)
    len = len + 9 + strlen (auth->opaque);
  if (auth->nonce_count != NULL)
    len = len + strlen (auth->nonce_count) + 5;
  if (auth->message_qop != NULL)
    len = len + strlen (auth->message_qop) + 6;

  tmp = (char *) osip_malloc (len);
  if (tmp == NULL)
    return -1;
  *dest = tmp;

  osip_strncpy (tmp, auth->auth_type, strlen (auth->auth_type));
  tmp = tmp + strlen (tmp);

  if (auth->username != NULL)
    {
      osip_strncpy (tmp, " username=", 10);
      tmp = tmp + 10;
      /* !! username-value must be a quoted string !! */
      osip_strncpy (tmp, auth->username, strlen (auth->username));
      tmp = tmp + strlen (tmp);
    }

  if (auth->realm != NULL)
    {
      osip_strncpy (tmp, ", realm=", 8);
      tmp = tmp + 8;
      /* !! realm-value must be a quoted string !! */
      osip_strncpy (tmp, auth->realm, strlen (auth->realm));
      tmp = tmp + strlen (tmp);
    }
  if (auth->nonce != NULL)
    {
      osip_strncpy (tmp, ", nonce=", 8);
      tmp = tmp + 8;
      /* !! nonce-value must be a quoted string !! */
      osip_strncpy (tmp, auth->nonce, strlen (auth->nonce));
      tmp = tmp + strlen (tmp);
    }

  if (auth->uri != NULL)
    {
      osip_strncpy (tmp, ", uri=", 6);
      tmp = tmp + 6;
      /* !! domain-value must be a list of URI in a quoted string !! */
      osip_strncpy (tmp, auth->uri, strlen (auth->uri));
      tmp = tmp + strlen (tmp);
    }
  if (auth->response != NULL)
    {
      osip_strncpy (tmp, ", response=", 11);
      tmp = tmp + 11;
      /* !! domain-value must be a list of URI in a quoted string !! */
      osip_strncpy (tmp, auth->response, strlen (auth->response));
      tmp = tmp + strlen (tmp);
    }

  if (auth->digest != NULL)
    {
      osip_strncpy (tmp, ", digest=", 9);
      tmp = tmp + 9;
      /* !! domain-value must be a list of URI in a quoted string !! */
      osip_strncpy (tmp, auth->digest, strlen (auth->digest));
      tmp = tmp + strlen (tmp);
    }
  if (auth->algorithm != NULL)
    {
      osip_strncpy (tmp, ", algorithm=", 12);
      tmp = tmp + 12;
      osip_strncpy (tmp, auth->algorithm, strlen (auth->algorithm));
      tmp = tmp + strlen (tmp);
    }
  if (auth->cnonce != NULL)
    {
      osip_strncpy (tmp, ", cnonce=", 9);
      tmp = tmp + 9;
      osip_strncpy (tmp, auth->cnonce, strlen (auth->cnonce));
      tmp = tmp + strlen (tmp);
    }
  if (auth->opaque != NULL)
    {
      osip_strncpy (tmp, ", opaque=", 9);
      tmp = tmp + 9;
      osip_strncpy (tmp, auth->opaque, strlen (auth->opaque));
      tmp = tmp + strlen (tmp);
    }
  if (auth->message_qop != NULL)
    {
      osip_strncpy (tmp, ", qop=", 6);
      tmp = tmp + 6;
      osip_strncpy (tmp, auth->message_qop, strlen (auth->message_qop));
      tmp = tmp + strlen (tmp);
    }
  if (auth->nonce_count != NULL)
    {
      osip_strncpy (tmp, ", nc=", 5);
      tmp = tmp + 5;
      osip_strncpy (tmp, auth->nonce_count, strlen (auth->nonce_count));
      tmp = tmp + strlen (tmp);
    }
  return 0;
}

/* deallocates a osip_authorization_t structure.  */
/* INPUT : osip_authorization_t *authorization | authorization. */
void
osip_authorization_free (osip_authorization_t * authorization)
{
  if (authorization == NULL)
    return;
  osip_free (authorization->auth_type);
  osip_free (authorization->username);
  osip_free (authorization->realm);
  osip_free (authorization->nonce);
  osip_free (authorization->uri);
  osip_free (authorization->response);
  osip_free (authorization->digest);
  osip_free (authorization->algorithm);
  osip_free (authorization->cnonce);
  osip_free (authorization->opaque);
  osip_free (authorization->message_qop);
  osip_free (authorization->nonce_count);
  osip_free (authorization);
}

int
osip_authorization_clone (const osip_authorization_t * auth,
			  osip_authorization_t ** dest)
{
  int i;
  osip_authorization_t *au;

  *dest = NULL;
  if (auth == NULL)
    return -1;
  /* to be removed?
     if (auth->auth_type==NULL) return -1;
     if (auth->username==NULL) return -1;
     if (auth->realm==NULL) return -1;
     if (auth->nonce==NULL) return -1;
     if (auth->uri==NULL) return -1;
     if (auth->response==NULL) return -1;
     if (auth->opaque==NULL) return -1;
   */

  i = osip_authorization_init (&au);
  if (i == -1)			/* allocation failed */
    return -1;
  if (auth->auth_type != NULL)
    {
      au->auth_type = osip_strdup (auth->auth_type);
      if (au->auth_type == NULL)
	goto ac_error;
    }
  if (auth->username != NULL)
    {
      au->username = osip_strdup (auth->username);
      if (au->username == NULL)
	goto ac_error;
    }
  if (auth->realm != NULL)
    {
      au->realm = osip_strdup (auth->realm);
      if (auth->realm == NULL)
	goto ac_error;
    }
  if (auth->nonce != NULL)
    {
      au->nonce = osip_strdup (auth->nonce);
      if (auth->nonce == NULL)
	goto ac_error;
    }
  if (auth->uri != NULL)
    {
      au->uri = osip_strdup (auth->uri);
      if (au->uri == NULL)
	goto ac_error;
    }
  if (auth->response != NULL)
    {
      au->response = osip_strdup (auth->response);
      if (auth->response == NULL)
	goto ac_error;
    }
  if (auth->digest != NULL)
    {
      au->digest = osip_strdup (auth->digest);
      if (au->digest == NULL)
	goto ac_error;
    }
  if (auth->algorithm != NULL)
    {
      au->algorithm = osip_strdup (auth->algorithm);
      if (auth->algorithm == NULL)
	goto ac_error;
    }
  if (auth->cnonce != NULL)
    {
      au->cnonce = osip_strdup (auth->cnonce);
      if (au->cnonce == NULL)
	goto ac_error;
    }
  if (auth->opaque != NULL)
    {
      au->opaque = osip_strdup (auth->opaque);
      if (auth->opaque == NULL)
	goto ac_error;
    }
  if (auth->message_qop != NULL)
    {
      au->message_qop = osip_strdup (auth->message_qop);
      if (auth->message_qop == NULL)
	goto ac_error;
    }
  if (auth->nonce_count != NULL)
    {
      au->nonce_count = osip_strdup (auth->nonce_count);
      if (auth->nonce_count == NULL)
	goto ac_error;
    }

  *dest = au;
  return 0;

ac_error:
  osip_authorization_free (au);
  osip_free (au);
  return -1;
}
