/* $Id: arp.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * Dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define MAC_BCAST_ADDR	"\xff\xff\xff\xff\xff\xff"

struct arpMsg {
	struct ethhdr ethhdr;		/* Ethernet header */
	u_short htype;				/* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;				/* protocol type (must be ETH_P_IP) */
	u_char  hlen;				/* hardware address length (must be 6) */
	u_char  plen;				/* protocol address length (must be 4) */
	u_short operation;			/* ARP opcode */
	u_char  sHaddr[6];			/* sender's hardware address */
	u_char  sInaddr[4];			/* sender's IP address */
	u_char  tHaddr[6];			/* target's hardware address */
	u_char  tInaddr[4];			/* target's IP address */
	u_char  pad[18];			/* pad for min. Ethernet payload (60 bytes) */
};


/* function prototypes
 */

int		arpCheck(u_long inaddr, struct ifinfo *ifbuf, long timeout);
/* requests: 'inaddr' containing the target IP address (network byte order).
 *           'ifbuf' pointing to the structure containing interface info.
 *           'timeout' specifies how many seconds it waits for ARP reply msg.
 * effects:  it sends an ARP request message whose target address is specified
 *           with 'inaddr' onto the interface described with 'ifbuf', and waits
 *           for ARP reply msg to it for 'timeout' seconds. it checks ARP reply
 *           message(s) if it gets it/them and returns result.
 * modifies: nothing
 * returns:  1 if no hosts are using 'inaddr'
 *           0 if somebody else is using 'inaddr'
 */

void	sendArpReply(u_char *thaddr, u_long tinaddr, struct ifinfo *ifbuf);
/* requests: 'thaddr' pointing to the target MAC address
 *           'tinaddr' containing the target IP address (network byte order).
 *           'ifbuf' pointing to the structure containing interface info.
 * effects:  it sends an ARP request message whose target address is specified
 *           with 'tinaddr' onto the interface described with 'ifbuf'.
 * modifies: nothing
 * returns:  nothing
 */

void	mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr,
				 u_long sInaddr, u_char *sHaddr, struct arpMsg *msg);
/* requests: 'opcode' containing the ARP OP code (1: ARP request, etc.)
 *           'tInaddr' containing the target IP address (network byte order)
 *           'tHaddr' pointing to the array containing target MAC address
 *           'sInaddr' containing the source IP address (network byte order)
 *           'tHaddr' pointing to the array containing source MAC address
 *           'msg' pointing to the structure where the ARP message is copied
 * effects:  it makes an ARP message in '*msg'
 * modifies: '*msg'
 * returns:  nothing
 */
