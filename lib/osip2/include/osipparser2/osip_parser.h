/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003,2004  Aymeric MOIZARD jack@atosc.org
  
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


#ifndef _OSIP_PARSER_H_
#define _OSIP_PARSER_H_

#include <osipparser2/osip_message.h>

/**
 * @file osip_parser.h
 * @brief oSIP SIP Parser additionnal Routines
 *
 */

/**
 * @defgroup oSIP_PARSER oSIP parser Handling
 * @ingroup osip2_parser
 * @{
 */

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Initialise the oSIP parser.
 */
  int parser_init (void);

/**
 * Fix the via header for INCOMING requests only.
 * a copy of ip_addr is done.
 */
  int osip_message_fix_last_via_header (osip_message_t * request,
					const char *ip_addr, int port);


/**
 * define this macro to avoid building several times
 * the message on retransmissions. If you have changed
 * the osip_message_t element since last call of osip_message_to_str() you
 * can call osip_message_force_update() to force a rebuild.
*/
/**
 * Check if the element is already built. (so osip_message_to_str won't build it again)
 * @param sip The element to check.
*/
  int osip_message_get__property (const osip_message_t * sip);

/**
 * Force a osip_message_t element to be rebuild on next osip_message_to_str() call.
 * @param sip The element to work on.
 */
  int osip_message_force_update (osip_message_t * sip);

/**
 * Get the usual reason phrase as defined in SIP for a specific status code.
 * @param status_code A status code.
 */
  const char *osip_message_get_reason (int status_code);

/**
 * Set the Accept header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_accept (osip_message_t * sip, const char *hvalue);
/**
 * Get one Accept header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_accept (const osip_message_t * sip, int pos,
			       osip_accept_t ** dest);
/**
 * Set the Accept-encoding header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_accept_encoding (osip_message_t * sip,
					const char *hvalue);
/**
 * Get one Accept-encoding header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_accept_encoding (const osip_message_t * sip, int pos,
					osip_accept_encoding_t ** dest);
/**
 * Set the Accept-language header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_accept_language (osip_message_t * sip,
					const char *hvalue);
/**
 * Get one Accept header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_accept_language (const osip_message_t * sip, int pos,
					osip_accept_language_t ** dest);
/**
 * Set the Alert-info header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_alert_info (osip_message_t * sip, const char *hvalue);
/**
 * Get one Alert-info header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_alert_info (const osip_message_t * sip, int pos,
				   osip_alert_info_t ** dest);
/**
 * Set the Allow header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_allow (osip_message_t * sip, const char *hvalue);
/**
 * Get one Allow header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_allow (const osip_message_t * sip, int pos,
			      osip_allow_t ** dest);
/**
 * Set the Authentication-info header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_authentication_info (osip_message_t * sip, const char *hvalue);
/**
 * Get one Authentication-info header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_authentication_info (const osip_message_t * sip, int pos,
			       osip_authentication_info_t ** dest);
/**
 * Set the Authorization header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_authorization (osip_message_t * sip,
				      const char *hvalue);
/**
 * Get one Authorization header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_authorization (const osip_message_t * sip, int pos,
				      osip_authorization_t ** dest);
/**
 * Set the Call-id header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_call_id (osip_message_t * sip, const char *hvalue);
/**
 * Get one Call-id header.
 * @param sip The element to work on.
 */
  osip_call_id_t *osip_message_get_call_id (const osip_message_t * sip);
/**
 * Set the Call-info header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_call_info (osip_message_t * sip, const char *hvalue);
/**
 * Get one Call-info header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_call_info (const osip_message_t * sip, int pos,
				  osip_call_info_t ** dest);
/**
 * Set the Contact header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_contact (osip_message_t * sip, const char *hvalue);
/**
 * Get one Contact header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_contact (const osip_message_t * sip, int pos,
				osip_contact_t ** dest);
/**
 * Set the Content-disposition header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_content_disposition (osip_message_t * sip,
					    const char *hvalue);
/**
 * Get one Content-disposition header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_content_disposition (const osip_message_t * sip,
					    int pos,
					    osip_content_disposition_t **
					    dest);
/**
 * Set the Content-encoding header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_content_encoding (osip_message_t * sip,
					 const char *hvalue);
/**
 * Get one Content-encoding header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_content_encoding (const osip_message_t * sip, int pos,
					 osip_content_encoding_t ** dest);
/**
 * Set the Content-length header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_content_length (osip_message_t * sip,
				       const char *hvalue);
/**
 * Get one Content-length header.
 * @param sip The element to work on.
 */
  osip_content_length_t *osip_message_get_content_length (const osip_message_t
							  * sip);
/**
 * Set the Content-type header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_content_type (osip_message_t * sip,
				     const char *hvalue);
/**
 * Get one Content-type header.
 * @param sip The element to work on.
 */
  osip_content_type_t *osip_message_get_content_type (const osip_message_t *
						      sip);
/**
 * Set the Cseq header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_cseq (osip_message_t * sip, const char *hvalue);
/**
 * Get one Cseq header.
 * @param sip The element to work on.
 */
  osip_cseq_t *osip_message_get_cseq (const osip_message_t * sip);
/**
 * Set the Error-info header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_error_info (osip_message_t * sip, const char *hvalue);
/**
 * Get one Error-info header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_error_info (const osip_message_t * sip, int pos,
				   osip_error_info_t ** dest);
/**
 * Set the From header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_from (osip_message_t * sip, const char *hvalue);
/**
 * Get the From header.
 * @param sip The element to work on.
 */
  osip_from_t *osip_message_get_from (const osip_message_t * sip);
/**
 * Set the mime-version header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_mime_version (osip_message_t * sip,
				     const char *hvalue);
/**
 * Get the Mime-version header.
 * @param sip The element to work on.
 */
  osip_mime_version_t *osip_message_get_mime_version (const osip_message_t *
						      sip);
/**
 * Set the Proxy-authenticate header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_proxy_authenticate (osip_message_t * sip,
					   const char *hvalue);
/**
 * Get the Proxy-authenticate header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_proxy_authenticate (const osip_message_t * sip,
					   int pos,
					   osip_proxy_authenticate_t ** dest);
/**
 * Set the Proxy-authorization header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_proxy_authorization (osip_message_t * sip,
					    const char *hvalue);
/**
 * Get one Proxy-authorization header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_proxy_authorization (const osip_message_t * sip,
					    int pos,
					    osip_proxy_authorization_t **
					    dest);
/**
 * Set the Proxy-authentication-info header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_proxy_authentication_info (osip_message_t * sip,
					  const char *hvalue);
/**
 * Get the Proxy-authentication-info header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_proxy_authentication_info (const osip_message_t * sip,
				      int pos,
				      osip_proxy_authentication_info_t ** dest);
/**
 * Set the Record-Route header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_record_route (osip_message_t * sip,
				     const char *hvalue);
/**
 * Get one Record-route header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_record_route (const osip_message_t * sip, int pos,
				     osip_record_route_t ** dest);
/**
 * Set the Route header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_route (osip_message_t * sip, const char *hvalue);
/**
 * Get one Route header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_route (const osip_message_t * sip, int pos,
			      osip_route_t ** dest);
/**
 * Set the To header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_to (osip_message_t * sip, const char *hvalue);
/**
 * Get the To header.
 * @param sip The element to work on.
 */
  osip_to_t *osip_message_get_to (const osip_message_t * sip);
/**
 * Set the Via header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_via (osip_message_t * sip, const char *hvalue);
/**
 * Append a Via header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_append_via (osip_message_t * sip, const char *hvalue);
/**
 * Get one Via header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_via (const osip_message_t * sip, int pos,
			    osip_via_t ** dest);
/**
 * Set the Www-authenticate header.
 * @param sip The element to work on.
 * @param hvalue The string describing the element.
 */
  int osip_message_set_www_authenticate (osip_message_t * sip,
					 const char *hvalue);
/**
 * Get one Www-authenticate header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_www_authenticate (const osip_message_t * sip, int pos,
					 osip_www_authenticate_t ** dest);
/**
 * Allocate and Add an "unknown" header (not defined in oSIP).
 * @param sip The element to work on.
 * @param hname The token name.
 * @param hvalue The token value.
 */
  int osip_message_set_header (osip_message_t * sip, const char *hname,
			       const char *hvalue);
/**
 * Allocate and Add an "unknown" header (not defined in oSIP).
 * The element is add on the top of the unknown header list. 
 * @param sip The element to work on.
 * @param hname The token name.
 * @param hvalue The token value.
 */
  int osip_message_set_topheader (osip_message_t * sip, const char *hname,
				  const char *hvalue);

/**
 * Find an "unknown" header. (not defined in oSIP)
 * @param sip The element to work on.
 * @param hname The name of the header to find.
 * @param pos The index where to start searching for the header.
 * @param dest A pointer to the header found.
 */
  int osip_message_header_get_byname (const osip_message_t * sip,
				      const char *hname, int pos,
				      osip_header_t ** dest);
/**
 * Get one "unknown" header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the header found.
 */
  int osip_message_get_header (const osip_message_t * sip, int pos,
			       osip_header_t ** dest);

/**
 * Set the Body of the SIP message.
 * @param sip The element to work on.
 * @param buf The buffer containing the body.
 * @param length The length of the buffer.
 */
  int osip_message_set_body (osip_message_t * sip, const char *buf, size_t length);
/**
 * Set the Body of the SIP message. (please report bugs)
 * @param sip The element to work on.
 * @param buf the buffer containing the body.
 * @param length The length of the buffer.
 */
  int osip_message_set_body_mime (osip_message_t * sip, const char *buf, size_t length);
/**
 * Get one body header.
 * @param sip The element to work on.
 * @param pos The index of the element to get.
 * @param dest A pointer on the body found.
 */
  int osip_message_get_body (const osip_message_t * sip, int pos,
			     osip_body_t ** dest);



/* trace facilities */
#ifndef DOXYGEN			/* avoid DOXYGEN warning */
#ifdef ENABLE_TRACE
  void msg_logrequest (osip_message_t * sip, char *fmt);
  void msg_logresponse (osip_message_t * sip, char *fmt);
#else
#define msg_logrequest(P,Q) ;
#define msg_logresponse(P,Q) ;
#endif
#endif

/**
 * Allocate and Add a new Date header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_date(sip,value)            osip_message_set_header((osip_message_t *)sip,(const char *)"Date",value)
/**
 * Find a Date header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_date(sip,pos,dest)          osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"date",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Encryption header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_encryption(sip,value)      osip_message_set_header((osip_message_t *)sip,(const char *)"Encryption",value)
/**
 * Find an Encryption header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_encryption(sip,pos,dest)    osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"encryption",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Organization header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_organization(sip,value)    osip_message_set_header((osip_message_t *)sip,(const char *)"Organization",value)
/**
 * Find an Organization header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_organization(sip,pos,dest)  osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"organization",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Require header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_require(sip,value)         osip_message_set_header((osip_message_t *)sip,(const char *)"Require",value)
/**
 * Find a Require header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_require(sip,pos,dest)       osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"require",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Supported header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_supported(sip,value)       osip_message_set_header((osip_message_t *)sip,(const char *)"Supported",value)
/**
 * Find a Supported header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_supported(sip,pos,dest)     osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"supported",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Timestamp header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_timestamp(sip,value)       osip_message_set_header((osip_message_t *)sip,(const char *)"Timestamp",value)
/**
 * Find a Timestamp header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_timestamp(sip,pos,dest)     osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"timestamp",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new User-Agent header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_user_agent(sip,value)      osip_message_set_header((osip_message_t *)sip,(const char *)"User-Agent",value)
/**
 * Find a User-Agent header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_user_agent(sip,pos,dest)    osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"user-agent",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Content-Language header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_content_language(sip,value) osip_message_set_header((osip_message_t *)sip,(const char *)"Content-Language",value)
/**
 * Find a Content-Language header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_content_language(sip,pos,dest) osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"content-language",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Expires header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_expires(sip,value)         osip_message_set_header((osip_message_t *)sip,(const char *)"Expires",value)
/**
 * Find a Expires header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_expires(sip,pos,dest)       osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"expires",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new In-Reply-To header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_in_reply_to(sip,value)     osip_message_set_header((osip_message_t *)sip,(const char *)"In-Reply-To",value)
/**
 * Find a In-Reply-To header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_in_reply_to(sip,pos,dest)   osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"in-reply-to",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Max-Forward header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_max_forwards(sip,value)     osip_message_set_header((osip_message_t *)sip,(const char *)"Max-Forwards",value)
/**
 * Find a Max-Forward header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_max_forwards(sip,pos,dest)   osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"max-forwards",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Priority header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_priority(sip,value)        osip_message_set_header((osip_message_t *)sip,(const char *)"Priority",value)
/**
 * Find a Priority header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_priority(sip,pos,dest)      osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"priority",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Proxy-Require header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_proxy_require(sip,value)   osip_message_set_header((osip_message_t *)sip,(const char *)"Proxy-Require",value)
/**
 * Find a Proxy-Require header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_proxy_require(sip,pos,dest) osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"proxy-require",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Response-Key header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_response_key(sip,value)    osip_message_set_header((osip_message_t *)sip,(const char *)"Response-Key",value)
/**
 * Find a Response-Key header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_response_key(sip,pos,dest)  osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"response-key",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Subject header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_subject(sip,value)         osip_message_set_header((osip_message_t *)sip,(const char *)"Subject",value)
/**
 * Find a Subject header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_subject(sip,pos,dest)       osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"subject",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Retry-After header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_retry_after(sip,value)     osip_message_set_header((osip_message_t *)sip,(const char *)"Retry-After",value)
/**
 * Find a Retry-After header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_retry_after(sip,pos,dest)   osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"retry-after",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Server header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_server(sip,value)          osip_message_set_header((osip_message_t *)sip,(const char *)"Server",value)
/**
 * Find a Server header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_server(sip,pos,dest)        osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"server",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Unsupported header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_unsupported(sip,value)     osip_message_set_header((osip_message_t *)sip,(const char *)"Unsupported",value)
/**
 * Find a Unsupported header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_unsupported(sip,pos,dest)   osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"unsupported",pos,(osip_header_t **)dest)
/**
 * Allocate and Add a new Warning header.
 * @param sip The element to work on.
 * @param value the value of the new header.
 */
#define osip_message_set_warning(sip,value)         osip_message_set_header((osip_message_t *)sip,(const char *)"Warning",value)
/**
 * Find a Warning header.
 * @param sip The element to work on.
 * @param pos The index of the header in the list of unknown header.
 * @param dest A pointer on the element found.
 */
#define osip_message_get_warning(sip,pos,dest)       osip_message_header_get_byname(( osip_message_t *)sip,(const char *)"warning",pos,(osip_header_t **)dest)

/** @} */


#ifdef __cplusplus
}
#endif

#endif
