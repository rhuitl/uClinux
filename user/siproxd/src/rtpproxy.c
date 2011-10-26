/*
    Copyright (C) 2003-2005  Thomas Ries <tries@gmx.net>

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

#include <sys/types.h>
#include <netinet/in.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "log.h"

static char const ident[]="$Id: rtpproxy.c,v 1.25 2005/01/08 10:05:12 hb9xar Exp $";

/* configuration storage */
extern struct siproxd_config configuration;

/*
 * initialize and create rtp_proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 */
int rtpproxy_init( void ) {
  int sts=STS_FAILURE;

   if (configuration.rtp_proxy_enable == 0) {
      sts = STS_SUCCESS;
   } else if (configuration.rtp_proxy_enable == 1) { // Relay
      sts = rtp_relay_init ();
   } else {
      ERROR("CONFIG: rtp_proxy_enable has invalid value",
            configuration.rtp_proxy_enable);
   }

   return sts;
}

/*
 * start an rtp stream on the proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int rtp_start_fwd (osip_call_id_t *callid, char *client_id,
                   int direction, int media_stream_no,
		   struct in_addr local_ipaddr, int *local_port,
                   struct in_addr remote_ipaddr, int remote_port) {
  int sts=STS_FAILURE;

   if (configuration.rtp_proxy_enable == 0) {
      sts = STS_SUCCESS;
   } else if (configuration.rtp_proxy_enable == 1) { // Relay
      sts = rtp_relay_start_fwd (callid, client_id,
                                 direction, media_stream_no,
                                 local_ipaddr, local_port,
                                 remote_ipaddr, remote_port);
   } else {
      ERROR("CONFIG: rtp_proxy_enable has invalid value",
            configuration.rtp_proxy_enable);
   }

   return sts;
}


/*
 * stop a rtp stream on the proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int rtp_stop_fwd (osip_call_id_t *callid, int direction) {
   int sts = STS_FAILURE;

   if (configuration.rtp_proxy_enable == 0) {
      sts = STS_SUCCESS;
   } else if (configuration.rtp_proxy_enable == 1) { // Relay
      sts = rtp_relay_stop_fwd(callid, direction, 0);
   } else {
      ERROR("CONFIG: rtp_proxy_enable has invalid value",
            configuration.rtp_proxy_enable);
   }

   return sts;
}
