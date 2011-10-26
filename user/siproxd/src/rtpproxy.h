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

/* $Id: rtpproxy.h,v 1.11 2005/01/08 10:05:12 hb9xar Exp $ */

#define CALLIDNUM_SIZE	256
#define CALLIDHOST_SIZE	32
#define CLIENT_ID_SIZE	128
typedef struct {
   int rtp_rx_sock;				/* rx socket (0 -> free slot)*/
   int rtp_tx_sock;				/* tx socket */
   char callid_number[CALLIDNUM_SIZE];          /* call ID */
   char callid_host[CALLIDHOST_SIZE];           /*  --"--  */
   char client_id[CLIENT_ID_SIZE];
   int direction;                               /* Direction of RTP stream */
   int media_stream_no;
   struct in_addr local_ipaddr;                 /* local IP */
   int local_port;                              /* local allocated port */
   struct in_addr remote_ipaddr;                /* remote IP */
   int remote_port;                             /* remote port */
   time_t timestamp;                            /* last 'stream alive' TS */
} rtp_proxytable_t;

/*
 * RTP relay
 */
int  rtp_relay_init(void);
int  rtp_relay_start_fwd (osip_call_id_t *callid, char *client_id,
                          int rtp_direction, int media_stream_no,
		          struct in_addr local_ipaddr, int *local_port,
                          struct in_addr remote_ipaddr, int remote_port);
int  rtp_relay_stop_fwd (osip_call_id_t *callid, int rtp_direction, int nolock);
