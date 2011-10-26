/* $Id: dhcp-options.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
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

/* DHCP option type
 */
enum {
	OT_STRING = 1,				/* string */
	OT_ADDR	  = 2				/* addresses */
};


/* DHCP option and value (cf. RFC1533)
 */
enum {
	padOption				=  0,
	endOption				= 255,
	subnetMask				=  1,
	timerOffset				=  2,
	routersOnSubnet			=  3,
	timeServer				=  4,
	nameServer				=  5,
	dns						=  6,
	logServer				=  7,
	cookieServer			=  8,
	lprServer				=  9,
	impressServer			= 10,
	resourceLocationServer	= 11,
	hostName				= 12,
	bootFileSize			= 13,
	meritDumpFile			= 14,
	domainName				= 15,
	swapServer				= 16,
	rootPath				= 17,
	extentionsPath			= 18,
	IPforwarding			= 19,
	nonLocalSourceRouting	= 20,
	policyFilter			= 21,
	maxDgramReasmSize		= 22,
	defaultIPTTL			= 23,
	pathMTUagingTimeout		= 24,
	pathMTUplateauTable		= 25,
	ifMTU					= 26,
	allSubnetsLocal			= 27,
	broadcastAddr			= 28,
	performMaskDiscovery	= 29,
	maskSupplier			= 30,
	performRouterDiscovery	= 31,
	routerSolicitationAddr	= 32,
	staticRoute				= 33,
	trailerEncapsulation	= 34,
	arpCacheTimeout			= 35,
	ethernetEncapsulation	= 36,
	tcpDefaultTTL			= 37,
	tcpKeepaliveInterval	= 38,
	tcpKeepaliveGarbage		= 39,
	nisDomainName			= 40,
	nisServers				= 41,
	ntpServers				= 42,
	vendorSpecificInfo		= 43,
	netBIOSnameServer		= 44,
	netBIOSdgramDistServer	= 45,
	netBIOSnodeType			= 46,
	netBIOSscope			= 47,
	xFontServer				= 48,
	xDisplayManager			= 49,
	dhcpRequestedIPaddr		= 50,
	dhcpIPaddrLeaseTime		= 51,
	dhcpOptionOverload		= 52,
	dhcpMessageType			= 53,
	dhcpServerIdentifier	= 54,
	dhcpParamRequest		= 55,
	dhcpMsg					= 56,
	dhcpMaxMsgSize			= 57,
	dhcpT1value				= 58,
	dhcpT2value				= 59,
	dhcpClassIdentifier		= 60,
	dhcpClientIdentifier	= 61
};


/* function prototypes
 */

void	getOptions(u_char *optp[], dhcpMessage *msg);
/*  requires: 'optp' pointing to the area to which pointers to DHCP option
 *            fields are saved. 'optp' must have at least 312 elements.
 *            'msg' pointing to the DHCP message to be processed.
 *  effects:  it scans the option field of '*msg', and assigns pointers to
 *            the options in '*msg' to optp[i]. optp[] elements are not sorted.
 *  modifies: 'optp[i]'
 *  return:   Nothing
 */

int		parseDhcpMsg(u_char *optp[], dhcpMessage *msg);
/*  requires: 'optp' pointing to the area to which pointers to DHCP option
 *            fields are saved. 'optp' must have at least 312 elements.
 *            'msg' pointing to the DHCP message to be processed.
 *  effects:  it checks '*msg' is a correct DHCP message or not. it also
 *            sorts 'optp[i]' according to 'Oxxx' (enum in dhcp.h)
 *  modifies: 'optp[i]'
 *  return:   1 if '*msg' is good, 0 if '*msg' is bad
 */
