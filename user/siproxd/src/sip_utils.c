/* -*- Mode: C; c-basic-offset: 3 -*-
    Copyright (C) 2002-2005  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.
    
    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/
#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <pwd.h>

#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_md5.h>

#include "siproxd.h"
#include "digcalc.h"
#include "rewrite_rules.h"
#include "log.h"

static char const ident[]="$Id: sip_utils.c,v 1.38 2005/05/05 08:49:59 hb9xar Exp $";


/* configuration storage */
extern struct siproxd_config configuration;

extern int h_errno;

extern struct urlmap_s urlmap[];		/* URL mapping table     */


/*
 * create a reply template from an given SIP request
 *
 * RETURNS a pointer to osip_message_t
 */
osip_message_t *msg_make_template_reply (sip_ticket_t *ticket, int code) {
   osip_message_t *request=ticket->sipmsg;
   osip_message_t *response;
   int pos;

   osip_message_init (&response);
   response->message=NULL;
   osip_message_set_version (response, osip_strdup ("SIP/2.0"));
   osip_message_set_status_code (response, code);
   osip_message_set_reason_phrase (response, 
                                   osip_strdup(osip_message_get_reason (code)));

   if (request->to==NULL) {
      ERROR("msg_make_template_reply: empty To in request header");
      return NULL;
   }

   if (request->from==NULL) {
      ERROR("msg_make_template_reply: empty From in request header");
      return NULL;
   }

   osip_to_clone (request->to, &response->to);
   osip_from_clone (request->from, &response->from);


   /* via headers */
   pos = 0;
   while (!osip_list_eol (request->vias, pos)) {
      char *tmp;
      osip_via_t *via;
      via = (osip_via_t *) osip_list_get (request->vias, pos);
      osip_via_to_str (via, &tmp);

      osip_message_set_via (response, tmp);
      osip_free (tmp);
      pos++;
   }

   osip_call_id_clone(request->call_id,&response->call_id);
   
   osip_cseq_clone(request->cseq,&response->cseq);

   return response;
}


/*
 * check for a via loop.
 * It checks for the presense of a via entry that holds one of
 * my IP addresses and is *not* the topmost via.
 *
 * RETURNS
 *	STS_TRUE if loop detected
 *	STS_FALSE if no loop
 */
int check_vialoop (sip_ticket_t *ticket) {
/*
!!! actually this is a problematic one.
1) for requests, I must search the whole VIA list
   (topmost via is the previos station in the path)

2) for responses I must skip the topmost via, as this is mine
   (and will be removed later on)

3) What happens if we have 'clashes'  with private addresses??
   From that point of view, siproxd *should* not try to
   check against it's local IF addresses if they are private.
   this then of course again can lead to a endless loop...

   -> Might use a fixed unique part of branch parameter to identify
   that it is MY via
   
*/
   osip_message_t *my_msg=ticket->sipmsg;
   int sts;
   int pos;
   int found_own_via;

   found_own_via=0;
   pos = 1;	/* for detecting a loop, don't check the first entry 
   		   as this is my own VIA! */
   while (!osip_list_eol (my_msg->vias, pos)) {
      osip_via_t *via;
      via = (osip_via_t *) osip_list_get (my_msg->vias, pos);
      sts = is_via_local (via);
      if (sts == STS_TRUE) found_own_via+=1;
      pos++;
   }

   /*
    * what happens if a message is coming back to me legally?
    *  UA1 -->--\       /-->--\
    *            siproxd       Registrar
    *  UA2 --<--/       \--<--/
    *
    * This may also lead to a VIA loop - so I probably must take the branch
    * parameter into count (or a unique part of it) OR just allow at least 2
    * vias of my own.
    */
   return (found_own_via>2)? STS_TRUE : STS_FALSE;
}


/*
 * check if a given osip_via_t is local. I.e. its address is owned
 * by my inbound or outbound interface
 *
 * RETURNS
 *	STS_TRUE if the given VIA is one of my interfaces
 *	STS_FALSE otherwise
 */
int is_via_local (osip_via_t *via) {
   int sts, found;
   struct in_addr addr_via, addr_myself;
   int port;
   int i;

   if (via==NULL) {
      ERROR("called is_via_local with NULL via");
      return STS_FALSE;
   }

   DEBUGC(DBCLASS_BABBLE,"via name %s",via->host);
   if (utils_inet_aton(via->host,&addr_via) == 0) {
      /* need name resolution */
      sts=get_ip_by_host(via->host, &addr_via);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_DNS, "is_via_local: cannot resolve VIA [%s]",
                via->host);
         return STS_FAILURE;
      }
   }   

   found=0;
   for (i=0; i<2; i++) {
      /*
       * search my in/outbound interfaces
       */
      DEBUGC(DBCLASS_BABBLE,"resolving IP of interface %s",
             (i==IF_INBOUND)? "inbound":"outbound");
      if (get_interface_ip(i, &addr_myself) != STS_SUCCESS) {
         continue;
      }

      /* check the extracted VIA against my own host addresses */
      if (via->port) port=atoi(via->port);
      else port=SIP_PORT;

      if ( (memcmp(&addr_myself, &addr_via, sizeof(addr_myself))==0) &&
           (port == configuration.sip_listen_port) ) {
         DEBUG("got address match [%s]", utils_inet_ntoa(addr_via));
         found=1;
	 break;
      }
   }

   return (found)? STS_TRUE : STS_FALSE;
}


/*
 * compares two URLs
 * (by now, only scheme, hostname and username are compared)
 *
 * RETURNS
 *	STS_SUCCESS if equal
 *	STS_FAILURE if non equal or error
 */
int compare_url(osip_uri_t *url1, osip_uri_t *url2) {
   int sts1, sts2;
   struct in_addr addr1, addr2;

   /* sanity checks */
   if ((url1 == NULL) || (url2 == NULL)) {
      ERROR("compare_url: NULL ptr: url1=0x%p, url2=0x%p",url1, url2);
      return STS_FAILURE;
   }

   /* sanity checks: host part is a MUST */
   if ((url1->host == NULL) || (url2->host == NULL)) {
      ERROR("compare_url: NULL ptr: url1->host=0x%p, url2->host=0x%p",
            url1->host, url2->host);
      return STS_FAILURE;
   }

   DEBUGC(DBCLASS_PROXY, "comparing urls: %s:%s@%s -> %s:%s@%s",
         (url1->scheme)   ? url1->scheme :   "(null)",
         (url1->username) ? url1->username : "(null)",
         (url1->host)     ? url1->host :     "(null)",
         (url2->scheme)   ? url2->scheme :   "(null)",
         (url2->username) ? url2->username : "(null)",
         (url2->host)     ? url2->host :     "(null)");

   /* compare SCHEME (if present) case INsensitive */
   if (url1->scheme && url2->scheme) {
      if (osip_strcasecmp(url1->scheme, url2->scheme) != 0) {
         DEBUGC(DBCLASS_PROXY, "compare_url: scheme mismatch");
         return STS_FAILURE;
      }
   } else {
      WARN("compare_url: NULL scheme - ignoring");
   }

   /* compare username (if present) case sensitive */
   if (url1->username && url2->username) {
      if (strcmp(url1->username, url2->username) != 0) {
         DEBUGC(DBCLASS_PROXY, "compare_url: username mismatch");
         return STS_FAILURE;
      }
   } else {
      DEBUGC(DBCLASS_PROXY, "compare_url: NULL username - ignoring");
   }


   /*
    * now, try to resolve the host. If resolveable, compare
    * IP addresses - if not resolveable, compare the host names
    * itselfes
    */

   /* get the IP addresses from the (possible) hostnames */
   sts1=get_ip_by_host(url1->host, &addr1);
   if (sts1 == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY, "compare_url: cannot resolve host [%s]",
             url1->host);
   }

   sts2=get_ip_by_host(url2->host, &addr2);
   if (sts2 == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY, "compare_url: cannot resolve host [%s]",
             url2->host);
   }

   if ((sts1 == STS_SUCCESS) && (sts2 == STS_SUCCESS)) {
      /* compare IP addresses */
      if (memcmp(&addr1, &addr2, sizeof(addr1))!=0) {
         DEBUGC(DBCLASS_PROXY, "compare_url: IP mismatch");
         return STS_FAILURE;
      }
   } else {
      /* compare hostname strings case INsensitive */
      if (osip_strcasecmp(url1->host, url2->host) != 0) {
         DEBUGC(DBCLASS_PROXY, "compare_url: host name mismatch");
         return STS_FAILURE;
      }
   }

   /* the two URLs did pass all tests successfully - MATCH */
   return STS_SUCCESS;
}


/*
 * compares two Call IDs
 * (by now, only hostname and username are compared)
 *
 * RETURNS
 *	STS_SUCCESS if equal
 *	STS_FAILURE if non equal or error
 */
int compare_callid(osip_call_id_t *cid1, osip_call_id_t *cid2) {

   if ((cid1==0) || (cid2==0)) {
      ERROR("compare_callid: NULL ptr: cid1=0x%p, cid2=0x%p",cid1, cid2);
      return STS_FAILURE;
   }

   /*
    * Check number part: if present must be equal, 
    * if not present, must be not present in both cids
    */
   if (cid1->number && cid2->number) {
      /* have both numbers */
      if (strcmp(cid1->number, cid2->number) != 0) goto mismatch;
   } else {
      /* at least one number missing, make sure that both are empty */
      if ( (cid1->number && (cid1->number[0]!='\0')) ||
           (cid2->number && (cid2->number[0]!='\0'))) {
         goto mismatch;
      }
   }

   /*
    * Check host part: if present must be equal, 
    * if not present, must be not present in both cids
    */
   if (cid1->host && cid2->host) {
      /* have both hosts */
      if (strcmp(cid1->host, cid2->host) != 0) goto mismatch;
   } else {
      /* at least one host missing, make sure that both are empty */
      if ( (cid1->host && (cid1->host[0]!='\0')) ||
           (cid2->host && (cid2->host[0]!='\0'))) {
         goto mismatch;
      }
   }

   DEBUGC(DBCLASS_BABBLE, "comparing callid - matched: "
          "%s@%s <-> %s@%s",
          cid1->number, cid1->host, cid2->number, cid2->host);
   return STS_SUCCESS;

mismatch:
   DEBUGC(DBCLASS_BABBLE, "comparing callid - mismatch: "
          "%s@%s <-> %s@%s",
          cid1->number, cid1->host, cid2->number, cid2->host);
   return STS_FAILURE;
}


/*
 * check if a given request is addressed to local. I.e. it is addressed
 * to the proxy itself (IP of my inbound or outbound interface, same port)
 *
 * RETURNS
 *	STS_TRUE if the request is addressed local
 *	STS_FALSE otherwise
 */
int is_sipuri_local (sip_ticket_t *ticket) {
   osip_message_t *sip=ticket->sipmsg;
   int found;
   struct in_addr addr_uri, addr_myself;
   int port;
   int i;

   if (sip==NULL) {
      ERROR("called is_sipuri_local with NULL sip");
      return STS_FALSE;
   }

   if (!sip || !sip->req_uri) {
      ERROR("is_sipuri_local: no request URI present");
      return STS_FALSE;
   }

   DEBUGC(DBCLASS_DNS,"check for local SIP URI %s:%s",
          sip->req_uri->host? sip->req_uri->host : "*NULL*",
          sip->req_uri->port? sip->req_uri->port : "*NULL*");

   if (utils_inet_aton(sip->req_uri->host, &addr_uri) == 0) {
      /* need name resolution */
      get_ip_by_host(sip->req_uri->host, &addr_uri);
   }   

   found=0;
   for (i=0; i<2; i++) {
      /*
       * search my in/outbound interfaces
       */
      DEBUGC(DBCLASS_BABBLE,"resolving IP of interface %s",
             (i==IF_INBOUND)? "inbound":"outbound");
      if (get_interface_ip(i, &addr_myself) != STS_SUCCESS) {
         continue;
      }

      /* check the extracted HOST against my own host addresses */
      if (sip->req_uri->port) {
         port=atoi(sip->req_uri->port);
      } else {
         port=SIP_PORT;
      }

      if ( (memcmp(&addr_myself, &addr_uri, sizeof(addr_myself))==0) &&
           (port == configuration.sip_listen_port) ) {
         DEBUG("address match [%s]", utils_inet_ntoa(addr_uri));
         found=1;
	 break;
      }
   }

   DEBUGC(DBCLASS_DNS, "SIP URI is %slocal", found? "":"not ");
   return (found)? STS_TRUE : STS_FALSE;
}


/*
 * check if a given request (outbound -> inbound) shall its
 * request URI get rewritten based upon our UA knowledge
 *
 * RETURNS
 *	STS_TRUE if to be rewritten
 *	STS_FALSE otherwise
 */
int check_rewrite_rq_uri (osip_message_t *sip) {
   int i, j, sts;
   int dflidx;
   osip_header_t *ua_hdr;

   /* get index of default entry */
   dflidx=(sizeof(RQ_rewrite)/sizeof(RQ_rewrite[0])) - 1;

   /* check fort existence of method */
   if ((sip==NULL) ||
       (sip->sip_method==NULL)) {
      ERROR("check_rewrite_rq_uri: got NULL method");
      return STS_FALSE;
   }

   /* extract UA string */
   osip_message_get_user_agent (sip, 0, &ua_hdr);
   if ((ua_hdr==NULL) || (ua_hdr->hvalue==NULL)) {
      DEBUGC(DBCLASS_SIP, "check_rewrite_rq_uri: NULL UA in Header, "
             "using default");
      i=dflidx;
   } else {
      /* loop through the knowledge base */
      for (i=0; RQ_rewrite[i].UAstring; i++) {
         if (strncmp(RQ_rewrite[i].UAstring, ua_hdr->hvalue,
                    sizeof(RQ_rewrite[i].UAstring))==0) {
            DEBUGC(DBCLASS_SIP, "got knowledge entry for [%s]",
                   ua_hdr->hvalue);
            break;
         }
      } /* for i */
   } /* if ua_hdr */

   for (j=0; RQ_method[j].name; j++) {
      if (strncmp(RQ_method[j].name,
                 sip->sip_method, RQ_method[j].size)==0) {
         if (RQ_rewrite[i].action[j] >= 0) {
            sts = (RQ_rewrite[i].action[j])? STS_TRUE: STS_FALSE;
         } else {
	    sts = (RQ_rewrite[dflidx].action[j])? STS_TRUE: STS_FALSE;
         }
         DEBUGC(DBCLASS_SIP, "check_rewrite_rq_uri: [%s:%s, i=%i, j=%i] "
                "got action %s",
                (sip && sip->sip_method) ?
                  sip->sip_method : "*NULL*",
                (ua_hdr && ua_hdr->hvalue)? ua_hdr->hvalue:"*NULL*",
                 i, j, (sts==STS_TRUE)? "rewrite":"norewrite");
         return sts;
      }
   } /* for j */

   WARN("check_rewrite_rq_uri: didn't get a hit of the method [%s]",
        sip->sip_method);
   return STS_FALSE;
}


/*
 * SIP_GEN_RESPONSE
 *
 * send an proxy generated response back to the client.
 * Only errors are reported from the proxy itself.
 *  code =  SIP result code to deliver
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int sip_gen_response(sip_ticket_t *ticket, int code) {
   osip_message_t *response;
   int sts;
   osip_via_t *via;
   int port;
   char *buffer;
   int buflen;
   struct in_addr addr;

   /* create the response template */
   if ((response=msg_make_template_reply(ticket, code))==NULL) {
      ERROR("sip_gen_response: error in msg_make_template_reply");
      return STS_FAILURE;
   }

   /* we must check if first via has x.x.x.x address. If not, we must resolve it */
   osip_message_get_via (response, 0, &via);
   if (via == NULL)
   {
      ERROR("sip_gen_response: Cannot send response - no via field");
      return STS_FAILURE;
   }


   /* name resolution */
   if (utils_inet_aton(via->host, &addr) == 0)
   {
      /* need name resolution */
      DEBUGC(DBCLASS_DNS,"resolving name:%s",via->host);
      sts = get_ip_by_host(via->host, &addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "sip_gen_response: cannot resolve via [%s]",
                via->host);
         return STS_FAILURE;
      }
   }   

   sts = sip_message_to_str(response, &buffer, &buflen);
   if (sts != 0) {
      ERROR("sip_gen_response: msg_2char failed");
      return STS_FAILURE;
   }


   if (via->port) {
      port=atoi(via->port);
   } else {
      port=SIP_PORT;
   }

   /* send to destination */
   sipsock_send(addr, port, ticket->protocol, buffer, buflen);

   /* free the resources */
   osip_message_free(response);
   osip_free(buffer);
   return STS_SUCCESS;
}


/*
 * SIP_ADD_MYVIA
 *
 * interface == IF_OUTBOUND, IF_INBOUND
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int sip_add_myvia (sip_ticket_t *ticket, int interface) {
   struct in_addr addr;
   char tmp[URL_STRING_SIZE];
   osip_via_t *via;
   int sts;
   char branch_id[VIA_BRANCH_SIZE];
   char *myaddr;

   if (get_interface_ip(interface, &addr) != STS_SUCCESS) {
      return STS_FAILURE;
   }

   sts = sip_calculate_branch_id(ticket, branch_id);

   myaddr=utils_inet_ntoa(addr);
   sprintf(tmp, "SIP/2.0/UDP %s:%i;branch=%s",
           myaddr, configuration.sip_listen_port,
           branch_id);

   DEBUGC(DBCLASS_BABBLE,"adding VIA:%s",tmp);

   sts = osip_via_init(&via);
   if (sts!=0) return STS_FAILURE; /* allocation failed */

   sts = osip_via_parse(via, tmp);
   if (sts!=0) return STS_FAILURE;

   osip_list_add(ticket->sipmsg->vias,via,0);

   return STS_SUCCESS;
}


/*
 * SIP_DEL_MYVIA
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int sip_del_myvia (sip_ticket_t *ticket) {
   osip_via_t *via;
   int sts;

   DEBUGC(DBCLASS_PROXY,"deleting topmost VIA");
   via = osip_list_get (ticket->sipmsg->vias, 0);
   
   if ( via == NULL ) {
      ERROR("Got empty VIA list - is your UA configured properly?");
      return STS_FAILURE;
   }

   if ( is_via_local(via) == STS_FALSE ) {
      ERROR("I'm trying to delete a VIA but it's not mine! host=%s",via->host);
      return STS_FAILURE;
   }

   sts = osip_list_remove(ticket->sipmsg->vias, 0);
   osip_via_free (via);
   return STS_SUCCESS;
}


/*
 * SIP_REWRITE_CONTACT
 *
 * rewrite the Contact header
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int sip_rewrite_contact (sip_ticket_t *ticket, int direction) {
   osip_message_t *sip_msg=ticket->sipmsg;
   osip_contact_t *contact;
   int i;

   if (sip_msg == NULL) return STS_FAILURE;

   osip_message_get_contact(sip_msg, 0, &contact);
   if (contact == NULL) return STS_FAILURE;

   for (i=0;i<URLMAP_SIZE;i++){
      if (urlmap[i].active == 0) continue;
      if ((direction == DIR_OUTGOING) &&
          (compare_url(contact->url, urlmap[i].true_url)==STS_SUCCESS)) break;
      if ((direction == DIR_INCOMING) &&
          (compare_url(contact->url, urlmap[i].masq_url)==STS_SUCCESS)) break;
   }

   /* found a mapping entry */
   if (i<URLMAP_SIZE) {
      char *tmp;
      DEBUGC(DBCLASS_PROXY, "rewrote Contact header %s@%s -> %s@%s",
             (contact->url->username)? contact->url->username : "*NULL*",
             (contact->url->host)? contact->url->host : "*NULL*",
             urlmap[i].masq_url->username, urlmap[i].masq_url->host);

      /* remove old entry */
      osip_list_remove(sip_msg->contacts,0);
      osip_contact_to_str(contact, &tmp);
      osip_contact_free(contact);

      /* clone the url from urlmap*/
      osip_contact_init(&contact);
      osip_contact_parse(contact,tmp);
      osip_free(tmp);
      osip_uri_free(contact->url);
      if (direction == DIR_OUTGOING) {
         /* outgoing, use masqueraded url */
         osip_uri_clone(urlmap[i].masq_url, &contact->url);
      } else {
         /* incoming, use true url */
         osip_uri_clone(urlmap[i].true_url, &contact->url);
      }

      osip_list_add(sip_msg->contacts,contact,-1);
   } else {
      return STS_FAILURE;
   } 

   return STS_SUCCESS;
}


/*
 * SIP_CALCULATE_BRANCH
 *
 * Calculates a branch parameter according to RFC3261 section 16.11
 *
 * The returned 'id' will be HASHHEXLEN + strlen(magic_cookie)
 * characters (32 + 7) long. The caller must supply at least this
 * amount of space in 'id'.
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int  sip_calculate_branch_id (sip_ticket_t *ticket, char *id) {
/* RFC3261 section 16.11 recommends the following procedure:
 *   The stateless proxy MAY use any technique it likes to guarantee
 *   uniqueness of its branch IDs across transactions.  However, the
 *   following procedure is RECOMMENDED.  The proxy examines the
 *   branch ID in the topmost Via header field of the received
 *   request.  If it begins with the magic cookie, the first
 *   component of the branch ID of the outgoing request is computed
 *   as a hash of the received branch ID.  Otherwise, the first
 *   component of the branch ID is computed as a hash of the topmost
 *   Via, the tag in the To header field, the tag in the From header
 *   field, the Call-ID header field, the CSeq number (but not
 *   method), and the Request-URI from the received request.  One of
 *   these fields will always vary across two different
 *   transactions.
 *
 * The branch value will consist of:
 * - magic cookie "z9hG4bK"
 * - 1st part (unique calculated ID
 * - 2nd part (value for loop detection) <<- not yet used by siproxd
 */
   osip_message_t *sip_msg=ticket->sipmsg;
   static char *magic_cookie="z9hG4bK";
   osip_via_t *via;
   osip_uri_param_t *param=NULL;
   osip_call_id_t *call_id=NULL;
   HASHHEX hashstring;

   hashstring[0]='\0';

   /*
    * Examine topmost via and look for a magic cookie.
    * If it is there, I use THIS branch parameter as input for
    * our hash calculation
    */
   via = osip_list_get (sip_msg->vias, 0);
   if (via == NULL) {
      ERROR("have a SIP message without any via header");
      return STS_FAILURE;
   }

   param=NULL;
   osip_via_param_get_byname(via, "branch", &param);
   if (param && param->gvalue) {
      DEBUGC(DBCLASS_BABBLE, "looking for magic cookie [%s]",param->gvalue);
      if (strncmp(param->gvalue, magic_cookie,
                  strlen(magic_cookie))==0) {
         /* calculate MD5 hash */
         MD5_CTX Md5Ctx;
         HASH HA1;

         MD5Init(&Md5Ctx);
         MD5Update(&Md5Ctx, param->gvalue,
                   strlen(param->gvalue));
         MD5Final(HA1, &Md5Ctx);
         CvtHex(HA1, hashstring);

         DEBUGC(DBCLASS_BABBLE, "existing branch -> branch hash [%s]",
                hashstring);
      }
   }

   /*
    * If I don't have a branch parameter in the existing topmost via,
    * then I need:
    *   - the topmost via
    *   - the tag in the To header field
    *   - the tag in the From header field
    *   - the Call-ID header field
    *   - the CSeq number (but not method)
    *   - the Request-URI from the received request
    */
   if (hashstring[0] == '\0') {
      /* calculate MD5 hash */
      MD5_CTX Md5Ctx;
      HASH HA1;
      char *tmp;

      MD5Init(&Md5Ctx);

      /* topmost via */
      osip_via_to_str(via, &tmp);
      if (tmp) {
         MD5Update(&Md5Ctx, tmp, strlen(tmp));
         osip_free(tmp);
      }
     
      /* Tag in To header */
      osip_to_get_tag(sip_msg->to, &param);
      if (param && param->gvalue) {
         MD5Update(&Md5Ctx, param->gvalue, strlen(param->gvalue));
      }

      /* Tag in From header */
      osip_from_get_tag(sip_msg->from, &param);
      if (param && param->gvalue) {
         MD5Update(&Md5Ctx, param->gvalue, strlen(param->gvalue));
      }

      /* Call-ID */
      call_id = osip_message_get_call_id(sip_msg);
      osip_call_id_to_str(call_id, &tmp);
      if (tmp) {
         MD5Update(&Md5Ctx, tmp, strlen(tmp));
         osip_free(tmp);
      }

      /* CSeq number (but not method) */
      tmp = osip_cseq_get_number(sip_msg->cseq);
      if (tmp) {
         MD5Update(&Md5Ctx, tmp, strlen(tmp));
      }
 
      /* Request URI */
      osip_uri_to_str(sip_msg->req_uri, &tmp);
      if (tmp) {
         MD5Update(&Md5Ctx, tmp, strlen(tmp));
         osip_free(tmp);
      }

      MD5Final(HA1, &Md5Ctx);
      CvtHex(HA1, hashstring);

      DEBUGC(DBCLASS_BABBLE, "non-existing branch -> branch hash [%s]",
             hashstring);
   }

   /* include the magic cookie */
   sprintf(id, "%s%s", magic_cookie, hashstring);

   return STS_SUCCESS;
}


/*
 * SIP_FIND_OUTBOUND_PROXY
 *
 * performs the lookup for an apropriate outbound proxy
 *
 * RETURNS
 *	STS_SUCCESS on successful lookup
 *	STS_FAILURE if no outbound proxy to be used
 */
int  sip_find_outbound_proxy(sip_ticket_t *ticket, struct in_addr *addr,
                             int *port) {
   int i, sts;
   char *domain=NULL;
   osip_message_t *sipmsg;

   sipmsg=ticket->sipmsg;

   if (!addr ||!port) {
      ERROR("sip_find_outbound_proxy called with NULL addr or port");
      return STS_FAILURE;
   }

   if (sipmsg && sipmsg->from && sipmsg->from->url) {
      domain=sipmsg->from->url->host;
   }

   if (domain == NULL) {
      WARN("sip_find_outbound_proxy called with NULL from->url->host");
      return STS_FAILURE;
   }

   /*
    * check consistency of configuration:
    * outbound_domain_name, outbound_domain_host, outbound_domain_port
    * must match up
    */
   if ((configuration.outbound_proxy_domain_name.used !=
        configuration.outbound_proxy_domain_host.used) ||
       (configuration.outbound_proxy_domain_name.used !=
        configuration.outbound_proxy_domain_port.used)) {
      ERROR("configuration of outbound_domain_ inconsistent, check config");
   } else {
      /*
       * perform the lookup for domain specific proxies
       * first match wins
       */
      for (i=0; i<configuration.outbound_proxy_domain_name.used; i++) {
         if (strcmp(configuration.outbound_proxy_domain_name.string[i],
             domain)==0) {
            sts = get_ip_by_host(configuration.outbound_proxy_domain_host.string[i],
                                 addr);
            if (sts == STS_FAILURE) {
               ERROR("sip_find_outbound_proxy: cannot resolve "
                     "outbound proxy host [%s], check config", 
                     configuration.outbound_proxy_domain_host.string[i]);
               return STS_FAILURE;
            }
            *port=atoi(configuration.outbound_proxy_domain_port.string[i]);
            if (*port == 0) *port = SIP_PORT;

            return STS_SUCCESS;

         } /* strcmp */
      } /* for i */
   }

   /*
    * now check for a global outbound proxy
    */
   if (configuration.outbound_proxy_host) {
      /* I have a global outbound proxy configured */
      sts = get_ip_by_host(configuration.outbound_proxy_host, addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve outbound "
                " proxy host [%s]", configuration.outbound_proxy_host);
         return STS_FAILURE;
      }

      if (configuration.outbound_proxy_port) {
         *port=configuration.outbound_proxy_port;
      } else {
         *port = SIP_PORT;
      }
      DEBUGC(DBCLASS_PROXY, "proxy_request: have outbound proxy %s:%i",
             configuration.outbound_proxy_host, *port);

      return STS_SUCCESS;
   }

   return STS_FAILURE; /* no proxy */
}






