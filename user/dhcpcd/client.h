/* $Id: client.h,v 1.2 2001-03-04 11:26:09 jaredd Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
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

/* function prototypes
 */

void	classIDsetup(char *id);
/* requests: 'id' pointing to the class identifier string
 * effects:  it sets the default class identifier to 'ClassId' if 'id' is NULL.
 *           Otherwise it sets the string described by 'id' to 'ClassId'.
 * modifies: ClassId[]
 * returns:  nothing
 */

void	clientIDsetup(char *id, char *ifname);
/* requests: 'id' pointing to the class identifier string
 *           'ifname' pointing to the interface name like 'eth0'
 * effects:  it sets the default client identifier to 'ClientId'
 *           if 'id' is NULL. Otherwise it sets the string described by
 *           'id' to 'ClientId'.
 * modifies: ClientId[]
 * returns:  nothing
 */

void	dhcpMsgInit(u_char *ifname);
/* requests: 'ifname' pointing to the interface name
 * effects:  it opens two sockets 'Srecv' and 'Ssend' for sending/receiving
 *           DHCP messages. it also initializes 'ClassId[]', class identifier.
 * modifies: Srecv, Ssend, ClassId[]
 * returns:  nothing
 */

void	dhcpClient();
/* requests: nothing
 * effects:  it runs the finite state machine of DHCP client.
 * modifies: Fsm[], CurrState, PrevState, 
 * returns:  nothing
 */

int		initReboot();
/* requests: nothing
 * effects:  it handles 'INIT/REBOOT state as follows:
 *            1. try to get the previously used IP address from the cache file
 *            2. move to the state INIT  if it fails.
 *            3. send DHCP REQUEST message and move to the state REBOOTING
 *               if it succeeded in reading the cache file.
 * modifies: DhcpMsgSend, ReqSentTime
 * returns:  nothing
 */

int		init();
/* requests: nothing
 * effects:  it makes and sends a DHCP discover message
 * modifies: ReqSentTime, DhcpMsgSend
 * returns:  SELECTING
 */

int		rebooting();
/* requests: nothing
 * effects:  it waits for a DHCPACK or DHCPNAK msg. it also rexmit DHCPREQUEST
 *           msg if necessary.
 * modifies: DhcpMsgRecv, OptPtr
 * returns:  INIT if it timeouts or gets DHCPNAK msg
 *           BOUND if it gets DHCPACK msg.
 */

int		selecting();
/* requests: nothing
 * effects:  it waits for a DHCPOFFER msg. it also rexmit DHCPREQUEST msg
 *           if necessary.
 * modifies: DhcpMsgRecv, OptPtr
 * returns:  REQUESTING
 */

int		requesting();
/* requests: nothing
 * effects:  it checks if the assigned IP address is already used. if not,
 *           it sends a DHCPREQUEST msg and waits for a DHCPACK or DHCPNAK msg.
 *           it also rexmit DHCPREQUEST msgs if necessary. it configures host
 *           information if it gets a DHCPACK msg. it moves back to the
 *           INIT state if it gets a DHCPNAK msg, or timeouts.
 * modifies: DhcpMsgRecv, OptPtr
 * returns:  BOUND if it gets an IP IP address successfully.
 *           INIT if it fails. 
 */

int		bound();
/* requests: nothing
 * effects:  it closes the socket for receiving, sleeps for 'RenewTime' sec.
 *           , and moves to the RENEWING state.
 * modifies: nothing
 * returns:  RENEWING
 */

int		renewing();
/* requests: nothing
 * effects:  it opens a socket for receiving, sends a DHCPREQ msg, and waits
 *           for DHCPACK or DHCPNAK msg. it makes the interface down if it gets
 *           a DHCPNAK msg. it moves back to the BOUND state if it gets a
 *           DHCPACK msg.
 * modifies: DhcpMsgSend, DhcpMsgRecv, Srecv, OptPtr, ReqSentTime
 * returns:  BOUND if it gets a DHCPACK msg,
 *           REBIND if it gets a DHCPNAK msg,
 *           INIT if it timeouts.
 */

int		rebinding();
/* requests: nothing
 * effects:  it sends a DHCPREQ msg, and waits for DHCPACK or DHCPNAK msg.
 *           it rexmit DHCPREQ msg if necessary. it makes the interface down
 *           if it gets a DHCPNAK msg. it moves back to the BOUND state if it
 *           gets a DHCPACK msg.
 * modifies: DhcpMsgSend, DhcpMsgRecv, Srecv, OptPtr, ReqSentTime
 * returns:  BOUND if it gets a DHCPACK msg,
 *           INIT if it gets a DHCPACK msg.
 */

void	mkDhcpDiscoverMsg(u_char *haddr, dhcpMessage *msg);
void	mkDhcpRequestMsg(int flag, u_long serverInaddr, u_long leaseTime,
						 u_long xid, u_long ciaddr, dhcpMessage *msg);
void	mkDhcpDeclineMsg(int flag, u_long serverInaddr, u_long ciaddr,
						 dhcpMessage *msg);
void	sendDhcpDecline(int flag, u_long serverInaddr, u_long ciaddr);
int		setDhcpInfo(u_char *optp[], dhcpMessage *msg);
void	setupIfInfo(struct ifinfo *ifbuf, u_long yiaddr, u_char *optp[]);
void	initHost(struct ifinfo *ifbuf, u_long yiaddr);
long	getNextTimeout(int flag);


#ifdef LLIP_SUPPORT
extern int linkLocalSet;
extern void sendrawpacket();
#endif
