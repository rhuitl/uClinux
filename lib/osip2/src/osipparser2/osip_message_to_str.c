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


#include <stdio.h>
#include <stdlib.h>

#include <osipparser2/osip_port.h>
#include <osipparser2/osip_parser.h>

extern const char *osip_protocol_version;

static int strcat_simple_header (char **_string, size_t * malloc_size,
				 char **_message, void *ptr_header,
				 char *header_name, size_t size_of_header,
				 int (*xxx_to_str) (void *, char **),
				 char **next);
static int strcat_headers_one_per_line (char **_string, size_t * malloc_size,
					char **_message,
					osip_list_t * headers, char *header,
					size_t size_of_header,
					int (*xxx_to_str) (void *, char **),
					char **next);
static int strcat_headers_all_on_one_line (char **_string,
					   size_t * malloc_size,
					   char **_message,
					   osip_list_t * headers,
					   char *header,
					   size_t size_of_header,
					   int (*xxx_to_str) (void *,
							      char **),
					   char **next);

static int
__osip_message_startline_to_strreq (osip_message_t * sip, char **dest)
{
  const char *sip_version;
  char *tmp;
  char *rquri;
  int i;

  *dest = NULL;
  if ((sip == NULL) || (sip->req_uri == NULL) || (sip->sip_method == NULL))
    return -1;

  i = osip_uri_to_str (sip->req_uri, &rquri);
  if (i != 0)
    return -1;

  if (sip->sip_version == NULL)
    sip_version = osip_protocol_version;
  else
    sip_version = sip->sip_version;

  *dest = (char *) osip_malloc (strlen (sip->sip_method)
				+ strlen (rquri) + strlen (sip_version) + 3);
  tmp = *dest;
  osip_strncpy (tmp, sip->sip_method, strlen (sip->sip_method));
  tmp = tmp + strlen (sip->sip_method);
  osip_strncpy (tmp, " ", 1);
  tmp = tmp + 1;
  osip_strncpy (tmp, rquri, strlen (rquri));
  tmp = tmp + strlen (rquri);
  osip_strncpy (tmp, " ", 1);
  tmp = tmp + 1;
  osip_strncpy (tmp, sip_version, strlen (sip_version));

  osip_free (rquri);
  return 0;
}

static int
__osip_message_startline_to_strresp (osip_message_t * sip, char **dest)
{
  char *tmp;
  const char *sip_version;
  char status_code[5];

  *dest = NULL;
  if ((sip == NULL) || (sip->reason_phrase == NULL)
      || (sip->status_code < 100) || (sip->status_code > 699))
    return -1;

  if (sip->sip_version == NULL)
    sip_version = osip_protocol_version;
  else
    sip_version = sip->sip_version;

  sprintf (status_code, "%u", sip->status_code);

  *dest = (char *) osip_malloc (strlen (sip_version)
				+ 3 + strlen (sip->reason_phrase) + 4);
  tmp = *dest;

  osip_strncpy (tmp, sip_version, strlen (sip_version));
  tmp = tmp + strlen (sip_version);
  osip_strncpy (tmp, " ", 1);
  tmp = tmp + 1;
  osip_strncpy (tmp, status_code, 3);
  tmp = tmp + 3;
  osip_strncpy (tmp, " ", 1);
  tmp = tmp + 1;
  osip_strncpy (tmp, sip->reason_phrase, strlen (sip->reason_phrase));

  return 0;
}

static int
__osip_message_startline_to_str (osip_message_t * sip, char **dest)
{

  if (sip->sip_method != NULL)
    return __osip_message_startline_to_strreq (sip, dest);
  if (sip->status_code != 0)
    return __osip_message_startline_to_strresp (sip, dest);

  OSIP_TRACE (osip_trace
	      (__FILE__, __LINE__, TRACE_LEVEL1, NULL,
	       "ERROR method has no value or status code is 0!\n"));
  return -1;			/* should never come here */
}

char *
osip_message_get_reason_phrase (const osip_message_t * sip)
{
  return sip->reason_phrase;
}

int
osip_message_get_status_code (const osip_message_t * sip)
{
  return sip->status_code;
}

char *
osip_message_get_method (const osip_message_t * sip)
{
  return sip->sip_method;
}

char *
osip_message_get_version (const osip_message_t * sip)
{
  return sip->sip_version;
}

osip_uri_t *
osip_message_get_uri (const osip_message_t * sip)
{
  return sip->req_uri;
}

static int
strcat_simple_header (char **_string, size_t * malloc_size,
		      char **_message, void *ptr_header, char *header_name,
		      size_t size_of_header, int (*xxx_to_str) (void *,
								char **),
		      char **next)
{
  char *string;
  char *message;
  char *tmp;
  int i;

  string = *_string;
  message = *_message;

  if (ptr_header != NULL)
    {
      if (*malloc_size < message - string + 100 + size_of_header)
	/* take some memory avoid to osip_realloc too much often */
	{			/* should not happen often */
	  size_t size = message - string;
	  *malloc_size = message - string + size_of_header + 100;
	  string = osip_realloc (string, *malloc_size);
	  if (string == NULL)
	    {
	      *_string = NULL;
	      *_message = NULL;
	      return -1;
	    }
	  message = string + size;
	}
      osip_strncpy (message, header_name, size_of_header);
      message = message + strlen (message);
      i = xxx_to_str (ptr_header, &tmp);
      if (i == -1)
	{
	  *_string = string;
	  *_message = message;
	  *next = NULL;
	  return -1;
	}
      if (*malloc_size < message - string + strlen (tmp) + 100)
	{
	  size_t size = message - string;
	  *malloc_size = message - string + strlen (tmp) + 100;
	  string = osip_realloc (string, *malloc_size);
	  if (string == NULL)
	    {
	      *_string = NULL;
	      *_message = NULL;
	      return -1;
	    }
	  message = string + size;
	}
      osip_strncpy (message, tmp, strlen (tmp));
      osip_free (tmp);
      message = message + strlen (message);
      osip_strncpy (message, CRLF, 2);
      message = message + 2;
    }
  *_string = string;
  *_message = message;
  *next = message;
  return 0;
}

static int
strcat_headers_one_per_line (char **_string, size_t * malloc_size,
			     char **_message, osip_list_t * headers,
			     char *header, size_t size_of_header,
			     int (*xxx_to_str) (void *, char **), char **next)
{
  char *string;
  char *message;
  char *tmp;
  int pos = 0;
  int i;

  string = *_string;
  message = *_message;

  while (!osip_list_eol (headers, pos))
    {
      void *elt;

      elt = (void *) osip_list_get (headers, pos);

      if (*malloc_size < message - string + 100 + size_of_header)
	/* take some memory avoid to osip_realloc too much often */
	{			/* should not happen often */
	  size_t size = message - string;
	  *malloc_size = message - string + size_of_header + 100;
	  string = osip_realloc (string, *malloc_size);
	  if (string == NULL)
	    {
	      *_string = NULL;
	      *_message = NULL;
	      return -1;
	    }
	  message = string + size;
	}
      osip_strncpy (message, header, size_of_header);
      i = xxx_to_str (elt, &tmp);
      if (i == -1)
	{
	  *_string = string;
	  *_message = message;
	  *next = NULL;
	  return -1;
	}
      message = message + strlen (message);

      if (*malloc_size < message - string + strlen (tmp) + 100)
	{
	  size_t size = message - string;
	  *malloc_size = message - string + strlen (tmp) + 100;
	  string = osip_realloc (string, *malloc_size);
	  if (string == NULL)
	    {
	      *_string = NULL;
	      *_message = NULL;
	      return -1;
	    }
	  message = string + size;
	}
      osip_strncpy (message, tmp, strlen (tmp));
      osip_free (tmp);
      message = message + strlen (message);
      osip_strncpy (message, CRLF, 2);
      message = message + 2;
      pos++;
    }
  *_string = string;
  *_message = message;
  *next = message;
  return 0;
}

static int
strcat_headers_all_on_one_line (char **_string, size_t * malloc_size,
				char **_message, osip_list_t * headers,
				char *header, size_t size_of_header,
				int (*xxx_to_str) (void *, char **),
				char **next)
{
  char *string;
  char *message;
  char *tmp;
  int pos = 0;
  int i;

  string = *_string;
  message = *_message;

  pos = 0;
  while (!osip_list_eol (headers, pos))
    {
      if (*malloc_size < message - string + 100 + size_of_header)
	/* take some memory avoid to osip_realloc too much often */
	{			/* should not happen often */
	  size_t size = message - string;
	  *malloc_size = message - string + size_of_header + 100;
	  string = osip_realloc (string, *malloc_size);
	  if (string == NULL)
	    {
	      *_string = NULL;
	      *_message = NULL;
	      return -1;
	    }
	  message = string + size;
	}
      osip_strncpy (message, header, size_of_header);
      message = message + strlen (message);

      while (!osip_list_eol (headers, pos))
	{
	  void *elt;

	  elt = (void *) osip_list_get (headers, pos);
	  i = xxx_to_str (elt, &tmp);
	  if (i == -1)
	    {
	      *_string = string;
	      *_message = message;
	      *next = NULL;
	      return -1;
	    }
	  if (*malloc_size < message - string + strlen (tmp) + 100)
	    {
	      size_t size = message - string;
	      *malloc_size = message - string + (int) strlen (tmp) + 100;
	      string = osip_realloc (string, *malloc_size);
	      if (string == NULL)
		{
		  *_string = NULL;
		  *_message = NULL;
		  return -1;
		}
	      message = string + size;
	    }
	  osip_strncpy (message, tmp, strlen (tmp));
	  osip_free (tmp);
	  message = message + strlen (message);
	  pos++;
	  if (!osip_list_eol (headers, pos))
	    {
	      strncpy (message, ", ", 2);
	      message = message + 2;
	    }
	}
      osip_strncpy (message, CRLF, 2);
      message = message + 2;
    }
  *_string = string;
  *_message = message;
  *next = message;
  return 0;
}

 /* return values:
    1: structure and buffer "message" are identical.
    2: buffer "message" is not up to date with the structure info (call osip_message_to_str to update it).
    -1 on error.
  */
int
osip_message_get__property (const osip_message_t * sip)
{
  if (sip == NULL)
    return -1;
  return sip->message_property;
}

int
osip_message_force_update (osip_message_t * sip)
{
  if (sip == NULL)
    return -1;
  sip->message_property = 2;
  return 0;
}

int
osip_message_to_str (osip_message_t * sip, char **dest, size_t *message_length)
{
  size_t malloc_size;
  size_t total_length = 0;
  /* Added at SIPit day1 */
  char *start_of_bodies;
  char *content_length_to_modify = NULL;

  char *message;
  char *next;
  char *tmp;
  int pos;
  int i;
  malloc_size = SIP_MESSAGE_MAX_LENGTH;

  *dest = NULL;
  if ((sip == NULL) || (sip->to == NULL) || (sip->from == NULL))
    return -1;

  {
    if (1 == osip_message_get__property (sip))
      {				/* message is already available in "message" */

	*dest = osip_malloc(sip->message_length+1);
	if (*dest==NULL)
	  return -1;
	memcpy(*dest, sip->message, sip->message_length);
	(*dest)[sip->message_length]='\0';
	if (message_length!=NULL)
	  *message_length = sip->message_length;
	return 0;
      }
    else
      {
	/* message should be rebuilt: delete the old one if exists. */
	osip_free (sip->message);
	sip->message = NULL;
      }
  }

  message = (char *) osip_malloc (SIP_MESSAGE_MAX_LENGTH);	/* ???? message could be > 4000  */
  *dest = message;

  /* add the first line of message */
  i = __osip_message_startline_to_str (sip, &tmp);
  if (i == -1)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  osip_strncpy (message, tmp, strlen (tmp));
  osip_free (tmp);
  message = message + strlen (message);
  osip_strncpy (message, CRLF, 2);
  message = message + 2;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message, sip->vias,
				 "Via: ", 5,
				 ((int (*)(void *, char **))
				  &osip_via_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->record_routes, "Record-Route: ", 14,
				 ((int (*)(void *, char **))
				  &osip_record_route_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message, sip->routes,
				 "Route: ", 7,
				 ((int (*)(void *, char **))
				  &osip_route_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_simple_header (dest, &malloc_size, &message,
			    sip->from, "From: ", 6,
			    ((int (*)(void *, char **)) &osip_from_to_str),
			    &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_simple_header (dest, &malloc_size, &message,
			    sip->to, "To: ", 4,
			    ((int (*)(void *, char **)) &osip_to_to_str),
			    &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_simple_header (dest, &malloc_size, &message,
			    sip->call_id, "Call-ID: ", 9,
			    ((int (*)(void *, char **)) &osip_call_id_to_str),
			    &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_simple_header (dest, &malloc_size, &message,
			    sip->cseq, "CSeq: ", 6,
			    ((int (*)(void *, char **)) &osip_cseq_to_str),
			    &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message, sip->contacts,
				 "Contact: ", 9,
				 ((int (*)(void *, char **))
				  &osip_contact_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_headers_one_per_line (dest, &malloc_size, &message,
				   sip->authorizations, "Authorization: ", 15,
				   ((int (*)(void *, char **))
				    &osip_authorization_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->www_authenticates, "WWW-Authenticate: ",
				 18,
				 ((int (*)(void *, char **))
				  &osip_www_authenticate_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->proxy_authenticates,
				 "Proxy-Authenticate: ", 20,
				 ((int (*)(void *, char **))
				  &osip_www_authenticate_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->proxy_authorizations,
				 "Proxy-Authorization: ", 21,
				 ((int (*)(void *, char **))
				  &osip_authorization_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  pos = 0;
  while (!osip_list_eol (sip->headers, pos))
    {
      osip_header_t *header;

      header = (osip_header_t *) osip_list_get (sip->headers, pos);
      i = osip_header_to_str (header, &tmp);
      if (i == -1)
	{
	  osip_free (*dest);
	  *dest = NULL;
	  return -1;
	}

      if (malloc_size < (size_t) (message - *dest + 100 + 16))
	{
	  size_t size = message - *dest;
	  malloc_size = message - *dest + 16 + 100;
	  *dest = osip_realloc (*dest, malloc_size);
	  if (*dest == NULL)
	    return -1;
	  message = *dest + size;
	}

      osip_strncpy (message, tmp, strlen (tmp));
      osip_free (tmp);
      message = message + strlen (message);
      osip_strncpy (message, CRLF, 2);
      message = message + 2;

      pos++;
    }

  i =
    strcat_headers_all_on_one_line (dest, &malloc_size, &message, sip->allows,
				    "Allow: ", 7,
				    ((int (*)(void *, char **))
				     &osip_content_length_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_simple_header (dest, &malloc_size, &message,
			    sip->content_type, "Content-Type: ", 14,
			    ((int (*)(void *, char **))
			     &osip_content_type_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_all_on_one_line (dest, &malloc_size, &message,
				    sip->content_encodings,
				    "Content-Encoding: ", 18,
				    ((int (*)(void *, char **))
				     &osip_content_length_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i = strcat_simple_header (dest, &malloc_size, &message,
			    sip->mime_version, "Mime-Version: ", 14,
			    ((int (*)(void *, char **))
			     &osip_content_length_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->call_infos, "Call-Info: ", 11,
				 ((int (*)(void *, char **))
				  &osip_call_info_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->alert_infos, "Alert-Info: ", 12,
				 ((int (*)(void *, char **))
				  &osip_call_info_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->error_infos, "Error-Info: ", 12,
				 ((int (*)(void *, char **))
				  &osip_call_info_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_all_on_one_line (dest, &malloc_size, &message,
				    sip->accepts, "Accept: ", 8,
				    ((int (*)(void *, char **))
				     &osip_content_type_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_all_on_one_line (dest, &malloc_size, &message,
				    sip->accept_encodings,
				    "Accept-Encoding: ", 17,
				    ((int (*)(void *, char **))
				     &osip_accept_encoding_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_all_on_one_line (dest, &malloc_size, &message,
				    sip->accept_languages,
				    "Accept-Language: ", 17,
				    ((int (*)(void *, char **))
				     &osip_accept_encoding_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->authentication_infos,
				 "Authentication-Info: ", 21,
				 ((int (*)(void *, char **))
				  &osip_authentication_info_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;

  i =
    strcat_headers_one_per_line (dest, &malloc_size, &message,
				 sip->proxy_authentication_infos,
				 "Proxy-Authentication-Info: ", 27,
				 ((int (*)(void *, char **))
				  &osip_authentication_info_to_str), &next);
  if (i != 0)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }
  message = next;


  /* we have to create the body before adding the contentlength */
  /* add enough lenght for "Content-Length: " */
  if (malloc_size < (size_t) (message - *dest + 100 + 16))
    {
      size_t size = message - *dest;
      malloc_size = message - *dest + 16 + 100;
      *dest = osip_realloc (*dest, malloc_size);
      if (*dest == NULL)
	return -1;
      message = *dest + size;
    }

  osip_strncpy (message, "Content-Length: ", 16);
  message = message + strlen (message);

  /* SIPit Day1
     ALWAYS RECALCULATE?
     if (sip->contentlength!=NULL)
     {
     i = osip_content_length_to_str(sip->contentlength, &tmp);
     if (i==-1) {
     osip_free(*dest);
     *dest = NULL;
     return -1;
     }
     osip_strncpy(message,tmp,strlen(tmp));
     osip_free(tmp);
     }
     else
     { */
  if (osip_list_eol (sip->bodies, 0))	/* no body */
    osip_strncpy (message, "0", 1);
  else
    {
      /* BUG: p130 (rfc2543bis-04)
         "No SP after last token or quoted string"

         In fact, if extra spaces exist: the stack can't be used
         to make user-agent that wants to make authentication...
         This should be changed...
       */

      osip_strncpy (message, "     ", 5);
      content_length_to_modify = message;
    }
  /*  } */
  message = message + strlen (message);
  osip_strncpy (message, CRLF, 2);
  message = message + 2;


  /* end of headers */
  osip_strncpy (message, CRLF, 2);
  message = message + 2;

  start_of_bodies = message;
  total_length = start_of_bodies - *dest;

  if (osip_list_eol (sip->bodies, 0))
    {
      /* same remark as at the beginning of the method */
      sip->message_property = 1;
      sip->message = osip_strdup (*dest);
      sip->message_length = total_length;
      if (message_length!=NULL)
	*message_length = total_length;

      return 0;			/* it's all done */
    }

  pos = 0;
  while (!osip_list_eol (sip->bodies, pos))
    {
      osip_body_t *body;
      size_t body_length;

      body = (osip_body_t *) osip_list_get (sip->bodies, pos);

      if (sip->mime_version != NULL)
	{
	  osip_strncpy (message, "--++", strlen ("--++"));
	  message = message + strlen (message);
	  osip_strncpy (message, CRLF, 2);
	  message = message + 2;
	}

      i = osip_body_to_str (body, &tmp, &body_length);
      if (i != 0)
	{
	  osip_free (*dest);
	  *dest = NULL;
	  return -1;
	}

      if (malloc_size < message - *dest + 100 + body_length)
	{
	  size_t size = message - *dest;
	  int offset_of_body;
	  int offset_content_length_to_modify = 0;
	  offset_of_body = start_of_bodies - *dest;
	  if (content_length_to_modify != NULL)
	    offset_content_length_to_modify = content_length_to_modify - *dest;
	  malloc_size = message - *dest + body_length + 100;
	  *dest = osip_realloc (*dest, malloc_size);
	  if (*dest == NULL)
	    return -1;
	  start_of_bodies = *dest + offset_of_body;
	  if (content_length_to_modify != NULL)
	    content_length_to_modify = *dest + offset_content_length_to_modify;
	  message = *dest + size;
	}

      memcpy (message, tmp, body_length);
      message[body_length]='\0';
      osip_free (tmp);
      message = message + body_length;

      pos++;
    }

  if (sip->mime_version != NULL)
    {
      osip_strncpy (message, "--++--", strlen ("--++--"));
      message = message + strlen (message);
      osip_strncpy (message, CRLF, 2);
      message = message + 2;
      /* ADDED at SIPit day1:  Is this needed for MIME type?
         osip_strncpy(message,CRLF,2);
         message = message + 2;
         strncpy(message,"\0",1); */
    }

  if (content_length_to_modify == NULL)
    {
      osip_free (*dest);
      *dest = NULL;
      return -1;
    }

  /* we NOW have the length of bodies: */
  {
    size_t size = message - start_of_bodies;
    char tmp2[15];
    total_length += size;
    sprintf (tmp2, "%i", size);
    /* do not use osip_strncpy here! */
    strncpy (content_length_to_modify + 5 - strlen (tmp2), tmp2, strlen (tmp2));
  }

  /* same remark as at the beginning of the method */
  sip->message_property = 1;
  sip->message=osip_malloc(total_length+1);
  if(sip->message!=NULL)
    {
      memcpy(sip->message,*dest,total_length);
      sip->message[total_length]='\0';
      sip->message_length = total_length;
      if(message_length!=NULL)
	*message_length = total_length;
    }
  return 0;
}
