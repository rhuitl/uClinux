/***********************************************************************
*
* pppoe.c 
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Copyright (C) 2000 by Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
***********************************************************************/

static char const RCSID[] =
"$Id: pppoe.c,v 1.4 2009-04-03 03:34:31 davidm Exp $";

#include "pppoe.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef USE_LINUX_PACKET
#include <sys/ioctl.h>
#include <fcntl.h>
#endif

#include <signal.h>

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

int DiscoveryState;
int DiscoverySocket = -1;
int SessionSocket = -1;

unsigned char BroadcastAddr[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

unsigned char MyEthAddr[ETH_ALEN];	/* Source hardware address */
unsigned char PeerEthAddr[ETH_ALEN];	/* Destination hardware address */
UINT16_t Session = 0;

char *IfName = NULL;		/* Interface name */
char *ServiceName = NULL;	/* Desired service name */
char *DesiredACName = NULL;	/* Desired access concentrator */
extern UINT16_t Session;	/* Identifier for our session */
int Synchronous = 0;		/* True if using Sync PPP encapsulation */
FILE *DebugFile = NULL;		/* File for dumping debug output */
int optPrintACNames = 0;	/* Only print access concentrator names */
int NumPADOPacketsReceived = 0;	/* Number of PADO packets received */
int optInactivityTimeout = 0;	/* Inactivity timeout */
int optUseHostUnique = 0;       /* Use Host-Unique tag for multiple sessions */
int optClampMSS = 0;		/* Clamp MSS to this value */
int optSkipDiscovery = 0;	/* Skip discovery phase */
int optKillSession = 0;		/* Kill a session by sending PADT */
int optSkipSession = 0;         /* Perform discovery, print session info
				   and exit */
struct PPPoETag cookie;		/* We have to send this if we get it */
struct PPPoETag relayId;	/* Ditto */

#define CHECK_ROOM(cursor, start, len) \
do {\
    if (((cursor)-(start))+(len) > MAX_PPPOE_PAYLOAD) { \
        syslog(LOG_ERR, "Would create too-long packet"); \
        return; \
    } \
} while(0)

/**********************************************************************
*%FUNCTION: parseForHostUniq
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data.
* extra -- user-supplied pointer.  This is assumed to be a pointer to int.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If a HostUnique tag is found which matches our PID, sets *extra to 1.
***********************************************************************/
void
parseForHostUniq(UINT16_t type, UINT16_t len, unsigned char *data,
		 void *extra)
{
    int *val = (int *) extra;
    if (type == TAG_HOST_UNIQ && len == sizeof(pid_t)) {
	pid_t tmp;
	memcpy(&tmp, data, len);
	if (tmp == getpid()) {
	    *val = 1;
	}
    }
}

/**********************************************************************
*%FUNCTION: packetIsForMe
*%ARGUMENTS:
* packet -- a received PPPoE packet
*%RETURNS:
* 1 if packet is for this PPPoE daemon; 0 otherwise.
*%DESCRIPTION:
* If we are using the Host-Unique tag, verifies that packet contains
* our unique identifier.
***********************************************************************/
int
packetIsForMe(struct PPPoEPacket *packet)
{
    int forMe = 0;

    /* If we're not using the Host-Unique tag, then accept the packet */
    if (!optUseHostUnique) return 1;

    parsePacket(packet, parseForHostUniq, &forMe);
    return forMe;
}

/**********************************************************************
*%FUNCTION: parsePADOTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.  Should point to a PacketCriteria structure
*          which gets filled in according to selected AC name and service
*          name.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADO packet
***********************************************************************/
void
parsePADOTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    struct PacketCriteria *pc = (struct PacketCriteria *) extra;
    int i;

    switch(type) {
    case TAG_AC_NAME:
	if (optPrintACNames) {
	    printf("Access-Concentrator: %.*s\n", (int) len, data);
	}
	if (DesiredACName && len == strlen(DesiredACName) &&
	    !strncmp((char *) data, DesiredACName, len)) {
	    pc->acNameOK = 1;
	}
	break;
    case TAG_SERVICE_NAME:
	if (optPrintACNames && len > 0) {
	    printf("       Service-Name: %.*s\n", (int) len, data);
	}
	if (ServiceName && len == strlen(ServiceName) &&
	    !strncmp((char *) data, ServiceName, len)) {
	    pc->serviceNameOK = 1;
	}
	break;
    case TAG_AC_COOKIE:
	if (optPrintACNames) {
	    printf("Got a cookie:");
	    /* Print first 20 bytes of cookie */
	    for (i=0; i<len && i < 20; i++) {
		printf(" %02x", (unsigned) data[i]);
	    }
	    if (i < len) printf("...");
	    printf("\n");
	}
	cookie.type = htons(type);
	cookie.length = htons(len);
	memcpy(cookie.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	if (optPrintACNames) {
	    printf("Got a Relay-ID\n");
	}
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_SERVICE_NAME_ERROR:
	if (optPrintACNames) {
	    printf("Got a Service-Name-Error tag: %.*s\n", (int) len, data);
	} else {
	    syslog(LOG_ERR, "PADO: Service-Name-Error: %.*s", (int) len, data);
	    exit(1);
	}
	break;
    case TAG_AC_SYSTEM_ERROR:
	if (optPrintACNames) {
	    printf("Got a System-Error tag: %.*s\n", (int) len, data);
	} else {
	    syslog(LOG_ERR, "PADO: System-Error: %.*s", (int) len, data);
	    exit(1);
	}
	break;
    case TAG_GENERIC_ERROR:
	if (optPrintACNames) {
	    printf("Got a Generic-Error tag: %.*s\n", (int) len, data);
	} else {
	    syslog(LOG_ERR, "PADO: Generic-Error: %.*s", (int) len, data);
	    exit(1);
	}
	break;
    }
}

/**********************************************************************
*%FUNCTION: parseLogErrs
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks error tags out of a packet and logs them.
***********************************************************************/
void
parseLogErrs(UINT16_t type, UINT16_t len, unsigned char *data,
	     void *extra)
{
    switch(type) {
    case TAG_SERVICE_NAME_ERROR:
	syslog(LOG_ERR, "PADT: Service-Name-Error: %.*s", (int) len, data);
	break;
    case TAG_AC_SYSTEM_ERROR:
	syslog(LOG_ERR, "PADT: System-Error: %.*s", (int) len, data);
	break;
    case TAG_GENERIC_ERROR:
	syslog(LOG_ERR, "PADT: Generic-Error: %.*s", (int) len, data);
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADSTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADS packet
***********************************************************************/
void
parsePADSTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_SERVICE_NAME:
	syslog(LOG_DEBUG, "PADS: Service-Name: '%.*s'", (int) len, data);
	break;
    case TAG_SERVICE_NAME_ERROR:
	syslog(LOG_ERR, "PADS: Service-Name-Error: %.*s", (int) len, data);
	exit(1);
    case TAG_AC_SYSTEM_ERROR:
	syslog(LOG_ERR, "PADS: System-Error: %.*s", (int) len, data);
	exit(1);
    case TAG_GENERIC_ERROR:
	syslog(LOG_ERR, "PADS: Generic-Error: %.*s", (int) len, data);
	exit(1);
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    }
}

/***********************************************************************
*%FUNCTION: sendPADI
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADI packet
***********************************************************************/
void
sendPADI(void)
{
    struct PPPoEPacket packet;
    unsigned char *cursor = packet.payload;
    struct PPPoETag *svc = (struct PPPoETag *) (&packet.payload);
    UINT16_t namelen = 0;
    UINT16_t plen;

    if (ServiceName) {
	namelen = (UINT16_t) strlen(ServiceName);
    }
    plen = TAG_HDR_SIZE + namelen;
    CHECK_ROOM(cursor, packet.payload, plen);

    memcpy(packet.ethHdr.h_dest, BroadcastAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, MyEthAddr, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADI;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    CHECK_ROOM(cursor, packet.payload, namelen+TAG_HDR_SIZE);

    if (ServiceName) {
	memcpy(svc->payload, ServiceName, strlen(ServiceName));
    }
    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (optUseHostUnique) {
	struct PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	CHECK_ROOM(cursor, packet.payload, sizeof(pid) + TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	cursor += sizeof(pid) + TAG_HDR_SIZE;
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);

    sendPacket(DiscoverySocket, &packet, (int) (plen + HDR_SIZE));
    if (DebugFile) {
	fprintf(DebugFile, "SENT ");
	dumpPacket(DebugFile, &packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

/**********************************************************************
*%FUNCTION: waitForPADO
*%ARGUMENTS:
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADO packet and copies useful information
***********************************************************************/
void
waitForPADO(int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    struct PPPoEPacket packet;
    int len;

    struct PacketCriteria pc;
    pc.acNameOK      = (DesiredACName)    ? 0 : 1;
    pc.serviceNameOK = (ServiceName)      ? 0 : 1;
	
    do {
	if (BPF_BUFFER_IS_EMPTY) {
	    tv.tv_sec = timeout;
	    tv.tv_usec = 0;
	
	    FD_ZERO(&readable);
	    FD_SET(DiscoverySocket, &readable);

	    while(1) {
		r = select(DiscoverySocket+1, &readable, NULL, NULL, &tv);
		if (r >= 0 || errno != EINTR) break;
	    }
	    if (r < 0) {
		fatalSys("select (waitForPADO)");
	    }
	    if (r == 0) return;        /* Timed out */
	}
	
	/* Get the packet */
	receivePacket(DiscoverySocket, &packet, &len);

	/* Check length */
	if (ntohs(packet.length) + HDR_SIZE > len) {
	    syslog(LOG_ERR, "Bogus PPPoE length field");
	    continue;
	}

#ifdef USE_BPF
	/* If it's not a Discovery packet, loop again */
	if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif

	if (DebugFile) {
	    fprintf(DebugFile, "RCVD ");
	    dumpPacket(DebugFile, &packet);
	    fprintf(DebugFile, "\n");
	    fflush(DebugFile);
	}
	/* If it's not for us, loop again */
	if (!packetIsForMe(&packet)) continue;

	if (packet.code == CODE_PADO) {
	    NumPADOPacketsReceived++;
	    if (optPrintACNames) {
		printf("--------------------------------------------------\n");
	    }
	    parsePacket(&packet, parsePADOTags, &pc);
	    if (pc.acNameOK && pc.serviceNameOK) {
		memcpy(PeerEthAddr, packet.ethHdr.h_source, ETH_ALEN);
		if (optPrintACNames) {
		    printf("AC-Ethernet-Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			   (unsigned) PeerEthAddr[0], 
			   (unsigned) PeerEthAddr[1],
			   (unsigned) PeerEthAddr[2],
			   (unsigned) PeerEthAddr[3],
			   (unsigned) PeerEthAddr[4],
			   (unsigned) PeerEthAddr[5]);
		    continue;
		}
		DiscoveryState = STATE_RECEIVED_PADO;
		break;
	    }
	}
    } while (DiscoveryState != STATE_RECEIVED_PADO);
}

/***********************************************************************
*%FUNCTION: sendPADR
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADR packet
***********************************************************************/
void
sendPADR(void)
{
    struct PPPoEPacket packet;
    struct PPPoETag *svc = (struct PPPoETag *) packet.payload;
    unsigned char *cursor = packet.payload;

    UINT16_t namelen = 0;
    UINT16_t plen;

    if (ServiceName) {
	namelen = (UINT16_t) strlen(ServiceName);
    }
    plen = TAG_HDR_SIZE + namelen;
    CHECK_ROOM(cursor, packet.payload, plen);

    memcpy(packet.ethHdr.h_dest, PeerEthAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, MyEthAddr, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADR;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    if (ServiceName) {
	memcpy(svc->payload, ServiceName, namelen);
    }
    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (optUseHostUnique) {
	struct PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	CHECK_ROOM(cursor, packet.payload, sizeof(pid)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	cursor += sizeof(pid) + TAG_HDR_SIZE;
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Copy cookie and relay-ID if needed */
    if (cookie.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(cookie.length) + TAG_HDR_SIZE);
	memcpy(cursor, &cookie, ntohs(cookie.length) + TAG_HDR_SIZE);
	cursor += ntohs(cookie.length) + TAG_HDR_SIZE;
	plen += ntohs(cookie.length) + TAG_HDR_SIZE;
    }

    if (relayId.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);
    sendPacket(DiscoverySocket, &packet, (int) (plen + HDR_SIZE));
    if (DebugFile) {
	fprintf(DebugFile, "SENT ");
	dumpPacket(DebugFile, &packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

/**********************************************************************
*%FUNCTION: waitForPADS
*%ARGUMENTS:
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADS packet and copies useful information
***********************************************************************/
void
waitForPADS(int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    struct PPPoEPacket packet;
    int len;

    do {
	if (BPF_BUFFER_IS_EMPTY) {
	    tv.tv_sec = timeout;
	    tv.tv_usec = 0;
	    
	    FD_ZERO(&readable);
	    FD_SET(DiscoverySocket, &readable);
	    
	    while(1) {
		r = select(DiscoverySocket+1, &readable, NULL, NULL, &tv);
		if (r >= 0 || errno != EINTR) break;
	    }
	    if (r < 0) {
		fatalSys("select (waitForPADS)");
	    }
	    if (r == 0) return;
	}

	/* Get the packet */
	receivePacket(DiscoverySocket, &packet, &len);

	/* Check length */
	if (ntohs(packet.length) + HDR_SIZE > len) {
	    syslog(LOG_ERR, "Bogus PPPoE length field");
	    continue;
	}

#ifdef USE_BPF
	/* If it's not a Discovery packet, loop again */
	if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif
	if (DebugFile) {
	    fprintf(DebugFile, "RCVD ");
	    dumpPacket(DebugFile, &packet);
	    fprintf(DebugFile, "\n");
	    fflush(DebugFile);
	}

	/* If it's not from the AC, it's not for me */
	if (memcmp(packet.ethHdr.h_source, PeerEthAddr, ETH_ALEN)) continue;

	/* If it's not for us, loop again */
	if (!packetIsForMe(&packet)) continue;

	/* Is it PADS?  */
	if (packet.code == CODE_PADS) {
	    /* Parse for goodies */
	    parsePacket(&packet, parsePADSTags, NULL);
	    DiscoveryState = STATE_SESSION;
	    break;
	}
    } while (DiscoveryState != STATE_SESSION);

    /* Don't bother with ntohs; we'll just end up converting it back... */
    Session = packet.session;

    syslog(LOG_DEBUG, "PPP session is %d", (int) ntohs(Session));

    /* RFC 2516 says session id MUST NOT be zero */
    if (ntohs(Session) == 0) {
	syslog(LOG_ERR, "Access concentrator used a session value of zero -- the AC is violating RFC 2516");
    }
}

/**********************************************************************
*%FUNCTION: discovery
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Performs the PPPoE discovery phase
***********************************************************************/
void
discovery(void)
{
    int padiAttempts = 0;
    int padrAttempts = 0;
    int timeout = PADI_TIMEOUT;
    DiscoverySocket = openInterface(IfName, Eth_PPPOE_Discovery, MyEthAddr);

    /* Skip discovery? */
    if (optSkipDiscovery) {
	DiscoveryState = STATE_SESSION;
	if (optKillSession) {
	    sendPADT();
	    exit(0);
	}
	return;
    }

    do {
	padiAttempts++;
	if (padiAttempts > MAX_PADI_ATTEMPTS) {
	    fatal("Timeout waiting for PADO packets");
	}
	sendPADI();
	DiscoveryState = STATE_SENT_PADI;
	waitForPADO(timeout);

	/* If we're just probing for access concentrators, don't do
	   exponential backoff.  This reduces the time for an unsuccessful
	   probe to 15 seconds. */
	if (!optPrintACNames) {
	    timeout *= 2;
	}
	if (optPrintACNames && NumPADOPacketsReceived) {
	    break;
	}
    } while (DiscoveryState == STATE_SENT_PADI);

    /* If we're only printing access concentrator names, we're done */
    if (optPrintACNames) {
	printf("--------------------------------------------------\n");
	exit(0);
    }

    timeout = PADI_TIMEOUT;
    do {
	padrAttempts++;
	if (padrAttempts > MAX_PADI_ATTEMPTS) {
	    fatal("Timeout waiting for PADS packets");
	}
	sendPADR();
	DiscoveryState = STATE_SENT_PADR;
	waitForPADS(timeout);
	timeout *= 2;
    } while (DiscoveryState == STATE_SENT_PADR);

    /* We're done. */
    DiscoveryState = STATE_SESSION;
    return;
}

/***********************************************************************
*%FUNCTION: sendSessionPacket
*%ARGUMENTS:
* packet -- the packet to send
# len -- length of data to send
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Transmits a session packet to the peer.
***********************************************************************/
void
sendSessionPacket(struct PPPoEPacket *packet, int len)
{
    packet->length = htons(len);
    if (optClampMSS) {
	clampMSS(packet, "outgoing", optClampMSS);
    }
    sendPacket(SessionSocket, packet, len + HDR_SIZE);
    if (DebugFile) {
	fprintf(DebugFile, "SENT ");
	dumpPacket(DebugFile, packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

#ifdef USE_BPF
/**********************************************************************
*%FUNCTION: sessionDiscoveryPacket
*%ARGUMENTS:
* packet -- the discovery packet that was received
*%RETURNS:
* Nothing
*%DESCRIPTION:
* We got a discovery packet during the session stage.  This most likely
* means a PADT.
*
* The BSD version uses a single socket for both discovery and session
* packets.  When a packet comes in over the wire once we are in
* session mode, either syncReadFromEth() or asyncReadFromEth() will
* have already read the packet and determined it to be a discovery
* packet before passing it here.
***********************************************************************/
void
sessionDiscoveryPacket(struct PPPoEPacket *packet)
{
    /* Sanity check */
    if (packet->code != CODE_PADT) {
	syslog(LOG_DEBUG, "Got discovery packet (code %d) during session",
	       (int) packet->code);
	return;
    }

    /* It's a PADT, all right.  Is it for us? */
    if (packet->session != Session) {
	/* Nope, ignore it */
	return;
    }

    syslog(LOG_INFO,
	   "Session terminated -- received PADT from access concentrator");
    parsePacket(packet, parseLogErrs, NULL);
    exit(0);
}
#else
/**********************************************************************
*%FUNCTION: sessionDiscoveryPacket
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* We got a discovery packet during the session stage.  This most likely
* means a PADT.
***********************************************************************/
void
sessionDiscoveryPacket(void)
{
    struct PPPoEPacket packet;
    int len;

    receivePacket(DiscoverySocket, &packet, &len);

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus PPPoE length field");
	return;
    }

    if (DebugFile) {
	fprintf(DebugFile, "RCVD ");
	dumpPacket(DebugFile, &packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }

    /* Sanity check */
    if (packet.code != CODE_PADT) {
	syslog(LOG_DEBUG, "Got discovery packet (code %d) during session",
	       (int) packet.code);
	return;
    }

    /* It's a PADT, all right.  Is it for us? */
    if (packet.session != Session) {
	/* Nope, ignore it */
	return;
    }

    syslog(LOG_INFO,
	   "Session terminated -- received PADT from peer");
    parsePacket(&packet, parseLogErrs, NULL);
    exit(0);
}
#endif /* USE_BPF */

/**********************************************************************
*%FUNCTION: session
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Handles the "session" phase of PPPoE
***********************************************************************/
void
session(void)
{
    fd_set readable;
    struct PPPoEPacket packet;
    struct timeval tv;
    struct timeval *tvp = NULL;
    int maxFD = 0;
    int r;

    /* Open a session socket */
    SessionSocket = openInterface(IfName, Eth_PPPOE_Session, NULL);

    /* Prepare for select() */
    if (SessionSocket > maxFD) maxFD = SessionSocket;
    if (DiscoverySocket > maxFD) maxFD = DiscoverySocket;
    maxFD++;

    /* Fill in the constant fields of the packet to save time */
    memcpy(packet.ethHdr.h_dest, PeerEthAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, MyEthAddr, ETH_ALEN);
    packet.ethHdr.h_proto = htons(Eth_PPPOE_Session);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_SESS;
    packet.session = Session;

    initPPP();

#ifdef USE_BPF
    /* check for buffered session data */
    while (BPF_BUFFER_HAS_DATA) {
	if (Synchronous) {
	    syncReadFromEth(SessionSocket, optClampMSS);
	} else {
	    asyncReadFromEth(SessionSocket, optClampMSS);
	}
    }
#endif

    for (;;) {
	if (optInactivityTimeout > 0) {
	    tv.tv_sec = optInactivityTimeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	FD_ZERO(&readable);
	FD_SET(0, &readable);     /* ppp packets come from stdin */
	FD_SET(DiscoverySocket, &readable);
	FD_SET(SessionSocket, &readable);
	while(1) {
	    r = select(maxFD, &readable, NULL, NULL, tvp);
	    if (r >= 0 || errno != EINTR) break;
	}
	if (r < 0) {
	    fatalSys("select (session)");
	}
	if (r == 0) { /* Inactivity timeout */
	    syslog(LOG_ERR, "Inactivity timeout... something wicked happened");
	    sendPADT();
	    exit(1);
	}

	/* Handle ready sockets */
	if (FD_ISSET(0, &readable)) {
	    if (Synchronous) {
		syncReadFromPPP(&packet);
	    } else {
		asyncReadFromPPP(&packet);
	    }
	}

	if (FD_ISSET(SessionSocket, &readable)) {
	    do {
		if (Synchronous) {
		    syncReadFromEth(SessionSocket, optClampMSS);
		} else {
		    asyncReadFromEth(SessionSocket, optClampMSS);
		}
	    } while (BPF_BUFFER_HAS_DATA);
	}

#ifndef USE_BPF	
	/* BSD uses a single socket, see *syncReadFromEth() */
	/* for calls to sessionDiscoveryPacket() */
	if (FD_ISSET(DiscoverySocket, &readable)) {
	    sessionDiscoveryPacket();
	}
#endif

    }
}


/***********************************************************************
*%FUNCTION: sendPADT
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADT packet
***********************************************************************/
void
sendPADT(void)
{
    struct PPPoEPacket packet;
    unsigned char *cursor = packet.payload;

    UINT16_t plen = 0;

    /* Do nothing if no session established yet */
    if (!Session) return;

    memcpy(packet.ethHdr.h_dest, PeerEthAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, MyEthAddr, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADT;
    packet.session = Session;

    /* Reset Session to zero so there is no possibility of
       recursive calls to this function by any signal handler */
    Session = 0;

    /* If we're using Host-Uniq, copy it over */
    if (optUseHostUnique) {
	struct PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	cursor += sizeof(pid) + TAG_HDR_SIZE;
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Copy cookie and relay-ID if needed */
    if (cookie.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(cookie.length) + TAG_HDR_SIZE);
	memcpy(cursor, &cookie, ntohs(cookie.length) + TAG_HDR_SIZE);
	cursor += ntohs(cookie.length) + TAG_HDR_SIZE;
	plen += ntohs(cookie.length) + TAG_HDR_SIZE;
    }

    if (relayId.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);
    sendPacket(DiscoverySocket, &packet, (int) (plen + HDR_SIZE));
    if (DebugFile) {
	fprintf(DebugFile, "SENT ");
	dumpPacket(DebugFile, &packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
    syslog(LOG_INFO,"Sent PADT");
}

/***********************************************************************
*%FUNCTION: sigPADT
*%ARGUMENTS:
* src -- signal received
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If an established session exists send PADT to terminate from session
*  from our end
***********************************************************************/

void
sigPADT(int src)
{
  syslog(LOG_DEBUG,"Received signal %d.",(int)src);
  sendPADT();
  exit(0);
}

/**********************************************************************
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- program name
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage information and exits.
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
#ifdef USE_BPF
    fprintf(stderr, "   -I if_name     -- Specify interface (REQUIRED)\n");
#else
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n",
	    DEFAULT_IF);
#endif
    fprintf(stderr, "   -T timeout     -- Specify inactivity timeout in seconds.\n");
    fprintf(stderr, "   -D filename    -- Log debugging information in filename.\n");
    fprintf(stderr, "   -V             -- Print version and exit.\n");
    fprintf(stderr, "   -A             -- Print access concentrator names and exit.\n");
    fprintf(stderr, "   -S name        -- Set desired service name.\n");
    fprintf(stderr, "   -C name        -- Set desired access concentrator name.\n");
    fprintf(stderr, "   -U             -- Use Host-Unique to allow multiple PPPoE sessions.\n");
    fprintf(stderr, "   -s             -- Use synchronous PPP encapsulation.\n");
    fprintf(stderr, "   -m MSS         -- Clamp incoming and outgoing MSS options.\n");
    fprintf(stderr, "   -p pidfile     -- Write process-ID to pidfile.\n");
    fprintf(stderr, "   -e sess:mac    -- Skip discovery phase; use existing session.\n");
    fprintf(stderr, "   -k             -- Kill a session with PADT (requires -e)\n");
    fprintf(stderr, "   -d             -- Perform discovery, print session info and exit.\n");
    fprintf(stderr, "   -f disc:sess   -- Set Ethernet frame types (hex).\n");
    fprintf(stderr, "   -h             -- Print usage information.\n\n");
    fprintf(stderr, "PPPoE Version %s, Copyright (C) 2000 Roaring Penguin Software Inc.\n", VERSION);
    fprintf(stderr, "PPPoE comes with ABSOLUTELY NO WARRANTY.\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it under the terms\n");
    fprintf(stderr, "of the GNU General Public License, version 2 or any later version.\n");
    fprintf(stderr, "http://www.roaringpenguin.com\n");
    exit(0);
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- count and values of command-line arguments
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Main program
***********************************************************************/
int
main(int argc, char *argv[])
{
    int opt;
    int n;
    unsigned int m[6];		/* MAC address in -e option */
    unsigned int s;		/* Temporary to hold session */
    FILE *pidfile;
    unsigned int discoveryType, sessionType;

#ifdef HAVE_N_HDLC
    int disc = N_HDLC;
    long flags;
#endif

    /* No cookie or relay-ID yet */
    cookie.type = 0;
    relayId.type = 0;

    /* Initialize syslog */
    openlog("pppoe", LOG_PID, LOG_DAEMON);

    while((opt = getopt(argc, argv, "I:VAT:D:hS:C:Usm:p:e:kdf:")) != -1) {
	switch(opt) {
	case 'f':
	    if (sscanf(optarg, "%x:%x", &discoveryType, &sessionType) != 2) {
		fprintf(stderr, "Illegal argument to -f: Should be disc:sess in hex\n");
		exit(1);
	    }
	    Eth_PPPOE_Discovery = (UINT16_t) discoveryType;
	    Eth_PPPOE_Session   = (UINT16_t) sessionType;
	    break;
	case 'd':
	    optSkipSession = 1;
	    break;

	case 'k':
	    optKillSession = 1;
	    break;

	case 'e':
	    /* Existing session: "sess:xx:yy:zz:aa:bb:cc" where "sess" is
	       session-ID, and xx:yy:zz:aa:bb:cc is MAC-address of peer */
	    n = sscanf(optarg, "%u:%2x:%2x:%2x:%2x:%2x:%2x",
		       &s, &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
	    if (n != 7) {
		fprintf(stderr, "Illegal argument to -e: Should be sess:xx:yy:zz:aa:bb:cc\n");
		exit(1);
	    }

	    /* Copy MAC address of peer */
	    for (n=0; n<6; n++) {
		PeerEthAddr[n] = (unsigned char) m[n];
	    }

	    /* Convert session */
	    Session = htons(s);

	    /* Skip discovery phase! */
	    optSkipDiscovery = 1;
	    break;
		       
	case 'p':
	    pidfile = fopen(optarg, "w");
	    if (pidfile) {
		fprintf(pidfile, "%lu\n", (unsigned long) getpid());
		fclose(pidfile);
	    }
	    break;
	case 'S':
	    SET_STRING(ServiceName, optarg);
	    break;
	case 'C':
	    SET_STRING(DesiredACName, optarg);
	    break;
	case 's':
	    Synchronous = 1;
	    break;
	case 'U':
	    optUseHostUnique = 1;
	    break;
	case 'D':
	    DebugFile = fopen(optarg, "w");
	    if (!DebugFile) {
		fprintf(stderr, "Could not open %s: %s\n",
			optarg, strerror(errno));
		exit(1);
	    }
	    fprintf(DebugFile, "rp-pppoe-%s\n", VERSION);
	    fflush(DebugFile);
	    break;
	case 'T':
	    optInactivityTimeout = (int) strtol(optarg, NULL, 10);
	    if (optInactivityTimeout < 0) {
		optInactivityTimeout = 0;
	    }
	    break;
	case 'm':
	    optClampMSS = (int) strtol(optarg, NULL, 10);
	    if (optClampMSS < 536) {
		fprintf(stderr, "-m: %d is too low (min 536)\n", optClampMSS);
		exit(1);
	    }
	    if (optClampMSS > 1452) {
		fprintf(stderr, "-m: %d is too high (max 1452)\n", optClampMSS);
		exit(1);
	    }
	    break;
	case 'I':
	    SET_STRING(IfName, optarg);
	    break;
	case 'V':
	    printf("Roaring Penguin PPPoE Version %s\n", VERSION);
	    exit(0);
	case 'A':
	    optPrintACNames = 1;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	default:
	    usage(argv[0]);
	}
    }

    /* Pick a default interface name */
    if (!IfName) {
#ifdef USE_BPF
	fprintf(stderr, "No interface specified (-I option)\n");
	exit(1);
#else
	IfName = DEFAULT_IF;
#endif
    }

    /* Set signal handlers: send PADT on TERM, HUP and INT */
    if (!optPrintACNames) {
	signal(SIGTERM, sigPADT);
	signal(SIGHUP, sigPADT);
	signal(SIGINT, sigPADT);

#ifdef HAVE_N_HDLC
	if (Synchronous) {
	    if (ioctl(0, TIOCSETD, &disc) < 0) {
		printErr("Unable to set line discipline to N_HDLC -- synchronous mode probably will fail");
	    } else {
		syslog(LOG_INFO,
		       "Changed pty line discipline to N_HDLC for synchronous mode");
	    }
	    /* There is a bug in Linux's select which returns a descriptor
	     * as readable if N_HDLC line discipline is on, even if
	     * it isn't really readable.  This return happens onlt when
	     * select() times out.  To avoid blocking forever in read(),
	     * make descriptor 0 non-blocking */
	    flags = fcntl(0, F_GETFL);
	    if (flags < 0) fatalSys("fcntl(F_GETFL)");
	    if (fcntl(0, F_SETFL, (long) flags | O_NONBLOCK) < 0) {
		fatalSys("fcntl(F_SETFL)");
	    }
	}
#endif

    }

    discovery();
    if (optSkipSession) {
	printf("%u:%02x:%02x:%02x:%02x:%02x:%02x\n",
	       ntohs(Session),
	       PeerEthAddr[0],
	       PeerEthAddr[1],
	       PeerEthAddr[2],
	       PeerEthAddr[3],
	       PeerEthAddr[4],
	       PeerEthAddr[5]);
	exit(0);
    }
    session();
    return 0;
}

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
    sendPADT();
    exit(1);
}

/**********************************************************************
*%FUNCTION: fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
fatal(char const *str)
{
    printErr(str);
    sendPADT();
    exit(1);
}

/**********************************************************************
*%FUNCTION: asyncReadFromEth
*%ARGUMENTS:
* sock -- Ethernet socket
* clampMss -- if non-zero, do MSS-clamping
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads a packet from the Ethernet interface and sends it to async PPP
* device.
***********************************************************************/
void
asyncReadFromEth(int sock, int clampMss)
{
    struct PPPoEPacket packet;
    int len;
    int plen;
    int i;
    unsigned char pppBuf[4096];
    unsigned char *ptr = pppBuf;
    unsigned char c;
    UINT16_t fcs;
    unsigned char header[2] = {FRAME_ADDR, FRAME_CTRL};
    unsigned char tail[2];
#ifdef USE_BPF
    int type;
#endif

    receivePacket(sock, &packet, &len);

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus PPPoE length field");
	return;
    }
    if (DebugFile) {
	fprintf(DebugFile, "RCVD ");
	dumpPacket(DebugFile, &packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }

#ifdef USE_BPF
    /* Make sure this is a session packet before processing further */
    type = etherType(&packet);
    if (type == Eth_PPPOE_Discovery) {
	sessionDiscoveryPacket(&packet);
    } else if (type != Eth_PPPOE_Session) {
	return;
    }
#endif

    /* Sanity check */
    if (packet.code != CODE_SESS) {
	syslog(LOG_ERR, "Unexpected packet code %d", (int) packet.code);
	return;
    }
    if (packet.ver != 1) {
	syslog(LOG_ERR, "Unexpected packet version %d", (int) packet.ver);
	return;
    }
    if (packet.type != 1) {
	syslog(LOG_ERR, "Unexpected packet type %d", (int) packet.type);
	return;
    }
    if (memcmp(packet.ethHdr.h_source, PeerEthAddr, ETH_ALEN)) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }

    if (packet.session != Session) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }
    plen = ntohs(packet.length);
    if (plen + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus length field in session packet %d (%d)",
	       (int) plen, (int) len);
	return;
    }

    /* Clamp MSS */
    if (clampMss) {
	clampMSS(&packet, "incoming", clampMss);
    }

    /* Compute FCS */
    fcs = pppFCS16(PPPINITFCS16, header, 2);
    fcs = pppFCS16(fcs, packet.payload, plen) ^ 0xffff;
    tail[0] = fcs & 0x00ff;
    tail[1] = (fcs >> 8) & 0x00ff;

    /* Build a buffer to send to PPP */
    *ptr++ = FRAME_FLAG;
    *ptr++ = FRAME_ADDR;
    *ptr++ = FRAME_ESC;
    *ptr++ = FRAME_CTRL ^ FRAME_ENC;

    for (i=0; i<plen; i++) {
	c = packet.payload[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    for (i=0; i<2; i++) {
	c = tail[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    *ptr++ = FRAME_FLAG;

    /* Ship it out */
    if (write(1, pppBuf, (ptr-pppBuf)) < 0) {
	fatalSys("asyncReadFromEth: write");
    }
}

/**********************************************************************
*%FUNCTION: syncReadFromEth
*%ARGUMENTS:
* sock -- Ethernet socket
* clampMss -- if true, clamp MSS.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads a packet from the Ethernet interface and sends it to sync PPP
* device.
***********************************************************************/
void
syncReadFromEth(int sock, int clampMss)
{
    struct PPPoEPacket packet;
    int len;
    int plen;
    struct iovec vec[2];
    unsigned char dummy[2];
#ifdef USE_BPF
    int type;
#endif

    receivePacket(sock, &packet, &len);

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus PPPoE length field");
	return;
    }
    if (DebugFile) {
	fprintf(DebugFile, "RCVD ");
	dumpPacket(DebugFile, &packet);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }

#ifdef USE_BPF
    /* Make sure this is a session packet before processing further */
    type = etherType(&packet);
    if (type == Eth_PPPOE_Discovery) {
	sessionDiscoveryPacket(&packet);
    } else if (type != Eth_PPPOE_Session) {
	return;
    }
#endif

    /* Sanity check */
    if (packet.code != CODE_SESS) {
	syslog(LOG_ERR, "Unexpected packet code %d", (int) packet.code);
	return;
    }
    if (packet.ver != 1) {
	syslog(LOG_ERR, "Unexpected packet version %d", (int) packet.ver);
	return;
    }
    if (packet.type != 1) {
	syslog(LOG_ERR, "Unexpected packet type %d", (int) packet.type);
	return;
    }
    if (memcmp(packet.ethHdr.h_source, PeerEthAddr, ETH_ALEN)) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }
    if (packet.session != Session) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }
    plen = ntohs(packet.length);
    if (plen + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus length field in session packet %d (%d)",
	       (int) plen, (int) len);
	return;
    }

    /* Clamp MSS */
    if (clampMss) {
	clampMSS(&packet, "incoming", clampMss);
    }

    /* Ship it out */
    vec[0].iov_base = (void *) dummy;
    dummy[0] = FRAME_ADDR;
    dummy[1] = FRAME_CTRL;
    vec[0].iov_len = 2;
    vec[1].iov_base = (void *) packet.payload;
    vec[1].iov_len = plen;

    if (writev(1, vec, 2) < 0) {
	fatalSys("syncReadFromEth: write");
    }
}

