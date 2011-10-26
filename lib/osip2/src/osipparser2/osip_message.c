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
#include <osipparser2/osip_message.h>

/* enable logging of memory accesses */

const char *osip_protocol_version = "SIP/2.0";


int
osip_message_init (osip_message_t ** sip)
{
  *sip = (osip_message_t *) osip_malloc (sizeof (osip_message_t));
  if (*sip==NULL)
    return -1;
  memset(*sip, 0, sizeof(osip_message_t));

  (*sip)->accepts = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->accepts);
  (*sip)->accept_encodings =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->accept_encodings);
  (*sip)->accept_languages =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));

  osip_list_init ((*sip)->accept_languages);
  (*sip)->alert_infos = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->alert_infos);
  (*sip)->allows = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->allows);
  (*sip)->authentication_infos = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->authentication_infos);
  (*sip)->authorizations = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->authorizations);
  (*sip)->call_id = NULL;
  (*sip)->call_infos = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->call_infos);
  (*sip)->contacts = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->contacts);

  /* forget it: this field is not suported */
  (*sip)->content_dispositions = NULL;

  (*sip)->content_encodings =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->content_encodings);
  (*sip)->content_length = NULL;
  (*sip)->content_type = NULL;
  (*sip)->cseq = NULL;
  (*sip)->error_infos = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->error_infos);
  (*sip)->from = NULL;
  (*sip)->mime_version = NULL;
  (*sip)->proxy_authenticates =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->proxy_authenticates);
  (*sip)->proxy_authentication_infos =
	(osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->proxy_authentication_infos);
  (*sip)->proxy_authorizations =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->proxy_authorizations);
  (*sip)->record_routes = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->record_routes);
  (*sip)->routes = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->routes);
  (*sip)->to = NULL;
  (*sip)->vias = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->vias);
  (*sip)->www_authenticates =
    (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->www_authenticates);

  (*sip)->bodies = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->bodies);

  (*sip)->headers = (osip_list_t *) osip_malloc (sizeof (osip_list_t));
  osip_list_init ((*sip)->headers);

  (*sip)->message_property = 3;
  (*sip)->message = NULL;	/* buffer to avoid calling osip_message_to_str many times (for retransmission) */
  (*sip)->message_length = 0;

  (*sip)->application_data = NULL;
  return 0;			/* ok */
}


void
osip_message_set_reason_phrase (osip_message_t * sip, char *reason)
{
  sip->reason_phrase = reason;
}

void
osip_message_set_status_code (osip_message_t * sip, int status_code)
{
  sip->status_code = status_code;
}

void
osip_message_set_method (osip_message_t * sip, char *sip_method)
{
  sip->sip_method = sip_method;
}

void
osip_message_set_version (osip_message_t * sip, char *sip_version)
{
  sip->sip_version = sip_version;
}

void
osip_message_set_uri (osip_message_t * sip, osip_uri_t * url)
{
  sip->req_uri = url;
}

void
osip_message_free (osip_message_t * sip)
{
  int pos = 0;

  if (sip == NULL)
    return;

  osip_free (sip->sip_method);
  osip_free (sip->sip_version);
  if (sip->req_uri != NULL)
    {
      osip_uri_free (sip->req_uri);
    }
  osip_free (sip->reason_phrase);

  {
    osip_accept_t *accept;

    while (!osip_list_eol (sip->accepts, pos))
      {
	accept = (osip_accept_t *) osip_list_get (sip->accepts, pos);
	osip_list_remove (sip->accepts, pos);
	osip_accept_free (accept);
      }
    osip_free (sip->accepts);
  }
  {
    osip_accept_encoding_t *accept_encoding;

    while (!osip_list_eol (sip->accept_encodings, pos))
      {
	accept_encoding =
	  (osip_accept_encoding_t *) osip_list_get (sip->accept_encodings,
						    pos);
	osip_list_remove (sip->accept_encodings, pos);
	osip_accept_encoding_free (accept_encoding);
      }
    osip_free (sip->accept_encodings);
  }
  {
    osip_accept_language_t *accept_language;

    while (!osip_list_eol (sip->accept_languages, pos))
      {
	accept_language =
	  (osip_accept_language_t *) osip_list_get (sip->accept_languages,
						    pos);
	osip_list_remove (sip->accept_languages, pos);
	osip_accept_language_free (accept_language);
      }
    osip_free (sip->accept_languages);
  }
  {
    osip_alert_info_t *alert_info;

    while (!osip_list_eol (sip->alert_infos, pos))
      {
	alert_info =
	  (osip_alert_info_t *) osip_list_get (sip->alert_infos, pos);
	osip_list_remove (sip->alert_infos, pos);
	osip_alert_info_free (alert_info);
      }
    osip_free (sip->alert_infos);
  }
  {
    osip_allow_t *al;

    while (!osip_list_eol (sip->allows, pos))
      {
	al = (osip_allow_t *) osip_list_get (sip->allows, pos);
	osip_list_remove (sip->allows, pos);
	osip_allow_free (al);
      }
    osip_free (sip->allows);
  }
  {
    osip_authentication_info_t *al;

    while (!osip_list_eol (sip->authentication_infos, pos))
      {
	al = (osip_authentication_info_t *) osip_list_get (sip->authentication_infos, pos);
	osip_list_remove (sip->authentication_infos, pos);
	osip_authentication_info_free (al);
      }
    osip_free (sip->authentication_infos);
  }
  {
    osip_authorization_t *al;

    while (!osip_list_eol (sip->authorizations, pos))
      {
	al =
	  (osip_authorization_t *) osip_list_get (sip->authorizations, pos);
	osip_list_remove (sip->authorizations, pos);
	osip_authorization_free (al);
      }
    osip_free (sip->authorizations);
  }
  if (sip->call_id != NULL)
    {
      osip_call_id_free (sip->call_id);
    }
  {
    osip_call_info_t *call_info;

    while (!osip_list_eol (sip->call_infos, pos))
      {
	call_info = (osip_call_info_t *) osip_list_get (sip->call_infos, pos);
	osip_list_remove (sip->call_infos, pos);
	osip_call_info_free (call_info);
      }
    osip_free (sip->call_infos);
  }
  {
    osip_contact_t *contact;

    while (!osip_list_eol (sip->contacts, pos))
      {
	contact = (osip_contact_t *) osip_list_get (sip->contacts, pos);
	osip_list_remove (sip->contacts, pos);
	osip_contact_free (contact);
      }
    osip_free (sip->contacts);
  }
  {
    osip_content_encoding_t *ce;

    while (!osip_list_eol (sip->content_encodings, pos))
      {
	ce =
	  (osip_content_encoding_t *) osip_list_get (sip->content_encodings,
						     pos);
	osip_list_remove (sip->content_encodings, pos);
	osip_content_encoding_free (ce);
      }
    osip_free (sip->content_encodings);
  }
  if (sip->content_length != NULL)
    {
      osip_content_length_free (sip->content_length);
    }
  if (sip->content_type != NULL)
    {
      osip_content_type_free (sip->content_type);
    }
  if (sip->cseq != NULL)
    {
      osip_cseq_free (sip->cseq);
    }
  {
    osip_error_info_t *error_info;

    while (!osip_list_eol (sip->error_infos, pos))
      {
	error_info =
	  (osip_error_info_t *) osip_list_get (sip->error_infos, pos);
	osip_list_remove (sip->error_infos, pos);
	osip_error_info_free (error_info);
      }
    osip_free (sip->error_infos);
  }
  if (sip->from != NULL)
    {
      osip_from_free (sip->from);
    }
  if (sip->mime_version != NULL)
    {
      osip_mime_version_free (sip->mime_version);
    }
  {
    osip_proxy_authenticate_t *al;

    while (!osip_list_eol (sip->proxy_authenticates, pos))
      {
	al =
	  (osip_proxy_authenticate_t *) osip_list_get (sip->
						       proxy_authenticates,
						       pos);
	osip_list_remove (sip->proxy_authenticates, pos);
	osip_proxy_authenticate_free (al);
      }
    osip_free (sip->proxy_authenticates);
  }
  {
    osip_proxy_authentication_info_t *al;

    while (!osip_list_eol (sip->proxy_authentication_infos, pos))
      {
	al = (osip_proxy_authentication_info_t *) osip_list_get (sip->proxy_authentication_infos, pos);
	osip_list_remove (sip->proxy_authentication_infos, pos);
	osip_proxy_authentication_info_free (al);
      }
    osip_free (sip->proxy_authentication_infos);
  }
  {
    osip_proxy_authorization_t *proxy_authorization;

    while (!osip_list_eol (sip->proxy_authorizations, pos))
      {
	proxy_authorization =
	  (osip_proxy_authorization_t *) osip_list_get (sip->
							proxy_authorizations,
							pos);
	osip_list_remove (sip->proxy_authorizations, pos);
	osip_proxy_authorization_free (proxy_authorization);
      }
    osip_free (sip->proxy_authorizations);
  }
  {
    osip_record_route_t *record_route;

    while (!osip_list_eol (sip->record_routes, pos))
      {
	record_route =
	  (osip_record_route_t *) osip_list_get (sip->record_routes, pos);
	osip_list_remove (sip->record_routes, pos);
	osip_record_route_free (record_route);
      }
    osip_free (sip->record_routes);
  }
  {
    osip_route_t *route;

    while (!osip_list_eol (sip->routes, pos))
      {
	route = (osip_route_t *) osip_list_get (sip->routes, pos);
	osip_list_remove (sip->routes, pos);
	osip_route_free (route);
      }
    osip_free (sip->routes);
  }
  if (sip->to != NULL)
    {
      osip_to_free (sip->to);
    }
  {
    osip_via_t *via;

    while (!osip_list_eol (sip->vias, pos))
      {
	via = (osip_via_t *) osip_list_get (sip->vias, pos);
	osip_list_remove (sip->vias, pos);
	osip_via_free (via);
      }
    osip_free (sip->vias);
  }
  {
    osip_www_authenticate_t *al;

    while (!osip_list_eol (sip->www_authenticates, pos))
      {
	al =
	  (osip_www_authenticate_t *) osip_list_get (sip->www_authenticates,
						     pos);
	osip_list_remove (sip->www_authenticates, pos);
	osip_www_authenticate_free (al);
      }
    osip_free (sip->www_authenticates);
  }

  {
    osip_header_t *header;

    while (!osip_list_eol (sip->headers, pos))
      {
	header = (osip_header_t *) osip_list_get (sip->headers, pos);
	osip_list_remove (sip->headers, pos);
	osip_header_free (header);
      }
    osip_free (sip->headers);
  }

  {
    osip_body_t *body;

    while (!osip_list_eol (sip->bodies, pos))
      {
	body = (osip_body_t *) osip_list_get (sip->bodies, pos);
	osip_list_remove (sip->bodies, pos);
	osip_body_free (body);
      }
    osip_free (sip->bodies);
  }
  osip_free (sip->message);
  osip_free (sip);
}


int
osip_message_clone (const osip_message_t * sip, osip_message_t ** dest)
{
  osip_message_t *copy;
  int pos = 0;
  int i;

  if (sip == NULL)
    return -1;
  *dest = NULL;

  i = osip_message_init (&copy);
  if (i != 0)
    return -1;

  copy->sip_method = osip_strdup (sip->sip_method);
  copy->sip_version = osip_strdup (sip->sip_version);
  copy->status_code = sip->status_code;
  copy->reason_phrase = osip_strdup (sip->reason_phrase);
  if (sip->req_uri != NULL)
    {
      i = osip_uri_clone (sip->req_uri, &(copy->req_uri));
      if (i != 0)
	goto mc_error1;
    }

  {
    osip_accept_t *accept;
    osip_accept_t *accept2;

    pos = 0;
    while (!osip_list_eol (sip->accepts, pos))
      {
	accept = (osip_accept_t *) osip_list_get (sip->accepts, pos);
	i = osip_accept_clone (accept, &accept2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->accepts, accept2, -1);	/* insert as last element */
	pos++;
      }
  }
  {
    osip_accept_encoding_t *accept_encoding;
    osip_accept_encoding_t *accept_encoding2;

    pos = 0;
    while (!osip_list_eol (sip->accept_encodings, pos))
      {
	accept_encoding =
	  (osip_accept_encoding_t *) osip_list_get (sip->accept_encodings,
						    pos);
	i = osip_accept_encoding_clone (accept_encoding, &accept_encoding2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->accept_encodings, accept_encoding2, -1);
	pos++;
      }
  }
  {
    osip_accept_language_t *accept_language;
    osip_accept_language_t *accept_language2;

    pos = 0;
    while (!osip_list_eol (sip->accept_languages, pos))
      {
	accept_language =
	  (osip_accept_language_t *) osip_list_get (sip->accept_languages,
						    pos);
	i = osip_accept_language_clone (accept_language, &accept_language2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->accept_languages, accept_language2, -1);
	pos++;
      }
  }
  {
    osip_alert_info_t *alert_info;
    osip_alert_info_t *alert_info2;

    pos = 0;
    while (!osip_list_eol (sip->alert_infos, pos))
      {
	alert_info =
	  (osip_alert_info_t *) osip_list_get (sip->alert_infos, pos);
	i = osip_alert_info_clone (alert_info, &alert_info2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->alert_infos, alert_info2, -1);
	pos++;
      }
  }
  {
    osip_allow_t *allow;
    osip_allow_t *allow2;

    pos = 0;
    while (!osip_list_eol (sip->allows, pos))
      {
	allow = (osip_allow_t *) osip_list_get (sip->allows, pos);
	i = osip_allow_clone (allow, &allow2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->allows, allow2, -1);
	pos++;
      }
  }
  {
    osip_authentication_info_t *authentication_info;
    osip_authentication_info_t *authentication_info2;

    pos = 0;
    while (!osip_list_eol (sip->authentication_infos, pos))
      {
	authentication_info =
	  (osip_authentication_info_t *) osip_list_get (sip->authentication_infos, pos);
	i = osip_authentication_info_clone (authentication_info, &authentication_info2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->authentication_infos, authentication_info2, -1);
	pos++;
      }
  }
  {
    osip_authorization_t *authorization;
    osip_authorization_t *authorization2;

    pos = 0;
    while (!osip_list_eol (sip->authorizations, pos))
      {
	authorization =
	  (osip_authorization_t *) osip_list_get (sip->authorizations, pos);
	i = osip_authorization_clone (authorization, &authorization2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->authorizations, authorization2, -1);
	pos++;
      }
  }
  if (sip->call_id != NULL)
    {
      i = osip_call_id_clone (sip->call_id, &(copy->call_id));
      if (i != 0)
	goto mc_error1;
    }
  {
    osip_call_info_t *call_info;
    osip_call_info_t *call_info2;

    pos = 0;
    while (!osip_list_eol (sip->call_infos, pos))
      {
	call_info = (osip_call_info_t *) osip_list_get (sip->call_infos, pos);
	i = osip_call_info_clone (call_info, &call_info2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->call_infos, call_info2, -1);
	pos++;
      }
  }
  {
    osip_contact_t *contact;
    osip_contact_t *contact2;

    pos = 0;
    while (!osip_list_eol (sip->contacts, pos))
      {
	contact = (osip_contact_t *) osip_list_get (sip->contacts, pos);
	i = osip_contact_clone (contact, &contact2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->contacts, contact2, -1);
	pos++;
      }
  }
  {
    osip_content_encoding_t *content_encoding;
    osip_content_encoding_t *content_encoding2;

    pos = 0;
    while (!osip_list_eol (sip->content_encodings, pos))
      {
	content_encoding =
	  (osip_content_encoding_t *) osip_list_get (sip->content_encodings,
						     pos);
	i =
	  osip_content_encoding_clone (content_encoding, &content_encoding2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->content_encodings, content_encoding2, -1);
	pos++;
      }
  }
  if (sip->content_length != NULL)
    {
      i =
	osip_content_length_clone (sip->content_length,
				   &(copy->content_length));
      if (i != 0)
	goto mc_error1;
    }
  if (sip->content_type != NULL)
    {
      i = osip_content_type_clone (sip->content_type, &(copy->content_type));
      if (i != 0)
	goto mc_error1;
    }
  if (sip->cseq != NULL)
    {
      i = osip_cseq_clone (sip->cseq, &(copy->cseq));
      if (i != 0)
	goto mc_error1;
    }
  {
    osip_error_info_t *error_info;
    osip_error_info_t *error_info2;

    pos = 0;
    while (!osip_list_eol (sip->error_infos, pos))
      {
	error_info =
	  (osip_error_info_t *) osip_list_get (sip->error_infos, pos);
	i = osip_error_info_clone (error_info, &error_info2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->error_infos, error_info2, -1);
	pos++;
      }
  }
  if (sip->from != NULL)
    {
      i = osip_from_clone (sip->from, &(copy->from));
      if (i != 0)
	goto mc_error1;
    }
  if (sip->mime_version != NULL)
    {
      i = osip_mime_version_clone (sip->mime_version, &(copy->mime_version));
      if (i != 0)
	goto mc_error1;
    }
  {
    osip_proxy_authenticate_t *proxy_authenticate;
    osip_proxy_authenticate_t *proxy_authenticate2;

    pos = 0;
    while (!osip_list_eol (sip->proxy_authenticates, pos))
      {
	proxy_authenticate =
	  (osip_proxy_authenticate_t *) osip_list_get (sip->
						       proxy_authenticates,
						       pos);
	i =
	  osip_proxy_authenticate_clone (proxy_authenticate,
					 &proxy_authenticate2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->proxy_authenticates, proxy_authenticate2, -1);
	pos++;
      }
  }
  {
    osip_proxy_authentication_info_t *proxy_authentication_info;
    osip_proxy_authentication_info_t *proxy_authentication_info2;

    pos = 0;
    while (!osip_list_eol (sip->proxy_authentication_infos, pos))
      {
	proxy_authentication_info =
	  (osip_proxy_authentication_info_t *) osip_list_get (sip->proxy_authentication_infos, pos);
	i =
	  osip_proxy_authentication_info_clone (proxy_authentication_info, &proxy_authentication_info2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->proxy_authentication_infos, proxy_authentication_info2, -1);
	pos++;
      }
  }
  {
    osip_proxy_authorization_t *proxy_authorization;
    osip_proxy_authorization_t *proxy_authorization2;

    pos = 0;
    while (!osip_list_eol (sip->proxy_authorizations, pos))
      {
	proxy_authorization =
	  (osip_proxy_authorization_t *) osip_list_get (sip->
							proxy_authorizations,
							pos);
	i =
	  osip_proxy_authorization_clone (proxy_authorization,
					  &proxy_authorization2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->proxy_authorizations, proxy_authorization2, -1);
	pos++;
      }
  }
  {
    osip_record_route_t *record_route;
    osip_record_route_t *record_route2;

    pos = 0;
    while (!osip_list_eol (sip->record_routes, pos))
      {
	record_route =
	  (osip_record_route_t *) osip_list_get (sip->record_routes, pos);
	i = osip_record_route_clone (record_route, &record_route2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->record_routes, record_route2, -1);
	pos++;
      }
  }
  {
    osip_route_t *route;
    osip_route_t *route2;

    pos = 0;
    while (!osip_list_eol (sip->routes, pos))
      {
	route = (osip_route_t *) osip_list_get (sip->routes, pos);
	i = osip_route_clone (route, &route2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->routes, route2, -1);
	pos++;
      }
  }
  if (sip->to != NULL)
    {
      i = osip_to_clone (sip->to, &(copy->to));
      if (i != 0)
	goto mc_error1;
    }
  {
    osip_via_t *via;
    osip_via_t *via2;

    pos = 0;
    while (!osip_list_eol (sip->vias, pos))
      {
	via = (osip_via_t *) osip_list_get (sip->vias, pos);
	i = osip_via_clone (via, &via2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->vias, via2, -1);
	pos++;
      }
  }
  {
    osip_www_authenticate_t *www_authenticate;
    osip_www_authenticate_t *www_authenticate2;

    pos = 0;
    while (!osip_list_eol (sip->www_authenticates, pos))
      {
	www_authenticate =
	  (osip_www_authenticate_t *) osip_list_get (sip->www_authenticates,
						     pos);
	i =
	  osip_www_authenticate_clone (www_authenticate, &www_authenticate2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->www_authenticates, www_authenticate2, -1);
	pos++;
      }
  }

  {
    osip_header_t *header;
    osip_header_t *header2;

    pos = 0;
    while (!osip_list_eol (sip->headers, pos))
      {
	header = (osip_header_t *) osip_list_get (sip->headers, pos);
	i = osip_header_clone (header, &header2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->headers, header2, -1);
	pos++;
      }
  }

  {
    osip_body_t *body;
    osip_body_t *body2;

    pos = 0;
    while (!osip_list_eol (sip->bodies, pos))
      {
	body = (osip_body_t *) osip_list_get (sip->bodies, pos);
	i = osip_body_clone (body, &body2);
	if (i != 0)
	  goto mc_error1;
	osip_list_add (copy->bodies, body2, -1);
	pos++;
      }
  }

  copy->message_length = sip->message_length;
  copy->message = osip_strdup (sip->message);
  copy->message_property = sip->message_property;

  *dest = copy;
  return 0;
mc_error1:
  osip_message_free (copy);
  return -1;

}
