/* $Id: upnphttp.h,v 1.1 2007-12-27 05:33:40 kwilson Exp $ */ 
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef __UPNPHTTP_H__
#define __UPNPHTTP_H__

#include <sys/queue.h>

#include "config.h"

/* server: HTTP header returned in all HTTP responses : */
#define MINIUPNPD_SERVER_STRING	OS_VERSION " UPnP/1.0 miniupnpd/1.0"

/*
 states :
  0 - waiting for data to read
  1 - waiting for HTTP Post Content.
  ...
  >= 100 - to be deleted
*/
enum httpCommands {
	EUnknown = 0,
	EGet,
	EPost
};

struct upnphttp {
	int socket;
	int state;
	char HttpVer[16];
	/* request */
	char * req_buf;
	int req_buflen;
	int req_contentlen;
	int req_contentoff;     /* header length */
	enum httpCommands req_command;
	char * req_soapAction;
	int req_soapActionLen;
	/* response */
	char * res_buf;
	int res_buflen;
	int res_buf_alloclen;
	/*int res_contentlen;*/
	/*int res_contentoff;*/		/* header length */
	LIST_ENTRY(upnphttp) entries;
};

/* New_upnphttp() */
struct upnphttp *
New_upnphttp(int);

/* CloseSocket_upnphttp() */
void
CloseSocket_upnphttp(struct upnphttp *);

/* Delete_upnphttp() */
void
Delete_upnphttp(struct upnphttp *);

/* Process_upnphttp() */
void
Process_upnphttp(struct upnphttp *);

/* BuildHeader_upnphttp()
 * build the header for the HTTP Response
 * also allocate the buffer for body data */
void
BuildHeader_upnphttp(struct upnphttp * h, int respcode,
                     const char * respmsg,
                     int bodylen);

/* BuildResp_upnphttp() 
 * fill the res_buf buffer with the complete
 * HTTP 200 OK response from the body passed as argument */
void
BuildResp_upnphttp(struct upnphttp *, const char *, int);

/* BuildResp2_upnphttp()
 * same but with given response code/message */
void
BuildResp2_upnphttp(struct upnphttp * h, int respcode,
                    const char * respmsg,
                    const char * body, int bodylen);

/* SendResp_upnphttp() */
void
SendResp_upnphttp(struct upnphttp *);

#endif

