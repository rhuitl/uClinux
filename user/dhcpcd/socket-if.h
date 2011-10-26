/* $Id: socket-if.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
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

void	setSockAddrIn(u_short port, u_long inaddr, struct sockaddr_in *saddr);
/*  requires: 'port' containing port number (network byte order)
 *            'inaddr' containing IP address (network byte order)
 *            'saddr' pointing to the structure to be configured.
 *  effects:  it initializes '*saddr', and assigns other parameters to '*saddr'
 *  modifies: *saddr
 *  return:   Nothing
 */

void	openSendSocket(struct sockaddr_in *addr, int *s);
/*  requires: 'addr' points sender's IP address.
 *            's' points the file descripter used by caller.
 *  effects:  it opens a socket '*s' for sending DHCP messages, and bind
 *            '*addr' to *s. port # is selected by the system. it also enables
 *            itself to send broadcast messages
 *  modifies: *addr, *s
 *  return:   Nothing
 */

void	openRecvSocket(struct sockaddr_in *addr, int *s);
/*  requires: 'addr' points sender's IP address.
 *            's' points the file descripter used by caller.
 *  effects:  it opens a socket '*s' for sending DHCP messages, and bind
 *            '*addr' to *s. port # is selected by the system. it also enables
 *            itself to send broadcast messages
 *  modifies: *addr, *s
 *  return:   Nothing
 */

void	openRawSocket(int *s, u_short type);
/*  requires: 's' points the file descripter used by caller.
 *            'type' containing ethernet frame type (ETH_P_XXXX)
 *  effects:  it opens a socket '*s' for sending raw datalink layer frame
 *            it also enables the process to send/receive broadcast frames
 *  modifies: *s
 *  return:   Nothing
 */

int		rcvAndCheckDhcpMsg(int s, dhcpMessage *msg, u_long waitMsgType,
						   u_char *optp[], long timeout);
/*  requires: 's' containing the socket descpipter to receive a DHCP packet
 *            'msg' pointing the structure for received DHCP packet
 *            'waitMsgType' containing the DHCP message types for which you
 *            are waiting in bit map. the 'DHCP_OFFER'th bit in waitMsgType
 *            must be 1 if you are waiting for DHCPOFFER message.
 *            'optp' 
 *  effects:  it reads the input from the socket 's' and checkes whether
 *            the packet is a correct DHCP message for 'timeout' seconds.
 *            it saves pointers to each DHCP option field in '*msg' to
 *            'optp[i]' and return 1. See 'parseDhcpMsg' for more details about
 *            how those pointers are set to 'opt[i]'.
 *  modifies: *msg, optp[i]
 *  return:   1 if it received a correct DHCP packet.
 *            0 if timeout.
 */

int		waitChkReXmitMsg(int sRecv, dhcpMessage *pMsgRecv, 
						 int sSend, dhcpMessage *pMsgSend,
						 struct sockaddr_in *addr, u_long waitMsgType,
						 u_char *optp[], int nretry);

void	setWaitMsgType(int type, u_int *ptype);
