/* $Id: upnpsoap.c,v 1.2 2008-01-03 03:54:54 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "upnpglobalvars.h"
#include "upnphttp.h"
#include "upnpsoap.h"
#include "upnpreplyparse.h"
#include "upnpredirect.h"
#include "getifaddr.h"
#include "getifstats.h"

static void
BuildSendAndCloseSoapResp(struct upnphttp * h,
                          const char * body, int bodylen)
{
	static const char beforebody[] =
		"<?xml version=\"1.0\"?>\n"
		"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<s:Body>";

	static const char afterbody[] =
		"</s:Body>"
		"</s:Envelope>";

	BuildHeader_upnphttp(h, 200, "OK",  sizeof(beforebody) - 1
		+ sizeof(afterbody) - 1 + bodylen );

	memcpy(h->res_buf + h->res_buflen, beforebody, sizeof(beforebody) - 1);
	h->res_buflen += sizeof(beforebody) - 1;

	memcpy(h->res_buf + h->res_buflen, body, bodylen);
	h->res_buflen += bodylen;

	memcpy(h->res_buf + h->res_buflen, afterbody, sizeof(afterbody) - 1);
	h->res_buflen += sizeof(afterbody) - 1;

	SendResp_upnphttp(h);
	CloseSocket_upnphttp(h);
}

static void
GetConnectionTypeInfo(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetConnectionTypeInfoResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewConnectionType>IP_Routed</NewConnectionType>"
		"<NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>"
		"</u:GetConnectionTypeInfoResponse>";
	BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
}

static void
GetTotalBytesSent(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalBytesSentResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalBytesSent>%lu</NewTotalBytesSent>"
		"</u:GetTotalBytesSentResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.obytes);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetTotalBytesReceived(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalBytesReceivedResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalBytesReceived>%lu</NewTotalBytesReceived>"
		"</u:GetTotalBytesReceivedResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.ibytes);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetTotalPacketsSent(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalPacketsSentResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalPacketsSent>%lu</NewTotalPacketsSent>"
		"</u:GetTotalPacketsSentResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.opackets);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetTotalPacketsReceived(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalPacketsReceivedResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalPacketsReceived>%lu</NewTotalPacketsReceived>"
		"</u:GetTotalPacketsReceivedResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.ipackets);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetCommonLinkProperties(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetCommonLinkPropertiesResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		/*"<NewWANAccessType>DSL</NewWANAccessType>"*/
		"<NewWANAccessType>Cable</NewWANAccessType>"
		"<NewLayer1UpstreamMaxBitRate>%lu</NewLayer1UpstreamMaxBitRate>"
		"<NewLayer1DownstreamMaxBitRate>%lu</NewLayer1DownstreamMaxBitRate>"
		"<NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>"
		"</u:GetCommonLinkPropertiesResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	if((downstream_bitrate == 0) || (upstream_bitrate == 0))
	{
		if(getifstats(ext_if_name, &data) >= 0)
		{
			if(downstream_bitrate == 0) downstream_bitrate = data.baudrate;
			if(upstream_bitrate == 0) upstream_bitrate = data.baudrate;
		}
	}
	bodylen = snprintf(body, sizeof(body), resp,
		upstream_bitrate, downstream_bitrate);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetStatusInfo(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetStatusInfoResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewConnectionStatus>Connected</NewConnectionStatus>"
		"<NewLastConnectionError>ERROR_NONE</NewLastConnectionError>"
		"<NewUptime>%ld</NewUptime>"
		"</u:GetStatusInfoResponse>";

	char body[512];
	int bodylen;
	time_t uptime;

	uptime = (time(NULL) - startup_time);
	bodylen = snprintf(body, sizeof(body), resp, (long)uptime);	
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetNATRSIPStatus(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetNATRSIPStatusResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewRSIPAvailable>0</NewRSIPAvailable>"
		"<NewNATEnabled>1</NewNATEnabled>"
		"</u:GetNATRSIPStatusResponse>";

	BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
}

static void
GetExternalIPAddress(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetExternalIPAddressResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewExternalIPAddress>%s</NewExternalIPAddress>"
		"</u:GetExternalIPAddressResponse>";

	char body[512];
	int bodylen;
	char ext_ip_addr[INET_ADDRSTRLEN];

	if(use_ext_ip_addr)
	{
		strncpy(ext_ip_addr, use_ext_ip_addr, INET_ADDRSTRLEN);
	}
	else if(getifaddr(ext_if_name, ext_ip_addr, INET_ADDRSTRLEN) < 0)
	{
		syslog(LOG_ERR, "Failed to get ip address for interface %s",
			ext_if_name);
		strncpy(ext_ip_addr, "0.0.0.0", INET_ADDRSTRLEN);
	}
	bodylen = snprintf(body, sizeof(body), resp, ext_ip_addr);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
AddPortMapping(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:AddPortMappingResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/>";

	struct NameValueParserData data;
	char * int_ip, * int_port, * ext_port, * protocol, * desc;
	unsigned short iport, eport;

	struct hostent *hp; /* getbyhostname() */
	char ** ptr; /* getbyhostname() */
	unsigned char result_ip[16]; /* inet_pton() */

	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	int_ip = GetValueFromNameValueList(&data, "NewInternalClient");

	if (!int_ip)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
		return;
	}

	/* if ip not valid assume hostname and convert */
	if (inet_pton(AF_INET, int_ip, result_ip) <= 0) 
	{
		hp = gethostbyname(int_ip);
		if(hp && hp->h_addrtype == AF_INET) 
		{ 
			for(ptr = hp->h_addr_list; ptr && *ptr; ptr++)
		   	{
				int_ip = inet_ntoa(*((struct in_addr *) *ptr));
				/* TODO : deal with more than one ip per hostname */
				break;
			}
		} 
		else 
		{
			syslog(LOG_ERR, "Failed to convert hostname '%s' to ip address", int_ip); 
			ClearNameValueList(&data);
			SoapError(h, 402, "Invalid Args");
			return;
		}				
	}

	int_port = GetValueFromNameValueList(&data, "NewInternalPort");
	ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	protocol = GetValueFromNameValueList(&data, "NewProtocol");
	desc = GetValueFromNameValueList(&data, "NewPortMappingDescription");

	if (!int_port || !ext_port || !protocol)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
		return;
	}

	eport = (unsigned short)atoi(ext_port);
	iport = (unsigned short)atoi(int_port);

	syslog(LOG_INFO, "AddPortMapping: external port %hu to %s:%hu protocol %s for: %s",
			eport, int_ip, iport, protocol, desc);

	r = upnp_redirect
	(
		eport, 
		int_ip, 
		iport, 
		protocol, 
		desc
#ifdef SECURE_COMPUTING
		,
		1
#endif
		);

	ClearNameValueList(&data);

	/* possible error codes for AddPortMapping :
	 * 402 - Invalid Args
	 * 501 - Action Failed
	 * 715 - Wildcard not permited in SrcAddr
	 * 716 - Wildcard not permited in ExtPort
	 * 718 - ConflictInMappingEntry
	 * 724 - SamePortValuesRequired */
	switch(r)
	{
	case 0:	/* success */
		BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
		break;
	case -2:	/* already redirected */
		SoapError(h, 718, "ConflictInMappingEntry");
		break;
	default:
		SoapError(h, 501, "ActionFailed");
	}
}

static void
GetSpecificPortMappingEntry(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetSpecificPortMappingEntryResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewInternalPort>%u</NewInternalPort>"
		"<NewInternalClient>%s</NewInternalClient>"
		"<NewEnabled>1</NewEnabled>"
		"<NewPortMappingDescription>%s</NewPortMappingDescription>"
		"<NewLeaseDuration>0</NewLeaseDuration>"
		"</u:GetSpecificPortMappingEntryResponse>";

	char body[2048];
	int bodylen;
	struct NameValueParserData data;
	const char * r_host, * ext_port, * protocol;
	unsigned short eport, iport;
	char int_ip[32];
	char desc[64];

	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	r_host = GetValueFromNameValueList(&data, "NewRemoteHost");
	ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	protocol = GetValueFromNameValueList(&data, "NewProtocol");

	if(!ext_port || !protocol)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
		return;
	}

	eport = (unsigned short)atoi(ext_port);

	r = upnp_get_redirection_infos(eport, protocol, &iport,
	                               int_ip, sizeof(int_ip),
	                               desc, sizeof(desc));

	if(r < 0)
	{		
		SoapError(h, 714, "NoSuchEntryInArray");
	}
	else
	{
		syslog(LOG_INFO, "GetSpecificPortMappingEntry: rhost='%s' %s %s found => %s:%u desc='%s'",
		       r_host, ext_port, protocol, int_ip, (unsigned int)iport, desc);
		bodylen = snprintf(body, sizeof(body), resp, (unsigned int)iport, int_ip, desc);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}

	ClearNameValueList(&data);
}

static void
DeletePortMapping(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:DeletePortMappingResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"</u:DeletePortMappingResponse>";

	struct NameValueParserData data;
	const char * r_host, * ext_port, * protocol;
	unsigned short eport;

	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	r_host = GetValueFromNameValueList(&data, "NewRemoteHost");
	ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	protocol = GetValueFromNameValueList(&data, "NewProtocol");

	if(!ext_port || !protocol)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
		return;
	}

	eport = (unsigned short)atoi(ext_port);

	syslog(LOG_INFO, "DeletePortMapping: external port: %hu, protocol: %s", 
		eport, protocol);

	r = upnp_delete_redirection(eport, protocol);

	if(r < 0)
	{	
		SoapError(h, 714, "NoSuchEntryInArray");
	}
	else
	{
		BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
	}

	ClearNameValueList(&data);
}

static void
GetGenericPortMappingEntry(struct upnphttp * h)
{
	int r;
	
	static const char resp[] =
		"<u:GetGenericPortMappingEntryResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewRemoteHost></NewRemoteHost>"
		"<NewExternalPort>%u</NewExternalPort>"
		"<NewProtocol>%s</NewProtocol>"
		"<NewInternalPort>%u</NewInternalPort>"
		"<NewInternalClient>%s</NewInternalClient>"
		"<NewEnabled>1</NewEnabled>"
		"<NewPortMappingDescription>%s</NewPortMappingDescription>"
		"<NewLeaseDuration>0</NewLeaseDuration>"
		"</u:GetGenericPortMappingEntryResponse>";

	int index = 0;
	unsigned short eport, iport;
	const char * m_index;
	char protocol[4], iaddr[32];
	char desc[64];
	struct NameValueParserData data;

	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	m_index = GetValueFromNameValueList(&data, "NewPortMappingIndex");

	if(!m_index)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
		return;
	}	

	index = (int)atoi(m_index);

	syslog(LOG_INFO, "GetGenericPortMappingEntry: index=%d", index);

	r = upnp_get_redirection_infos_by_index(index, &eport, protocol, &iport,
                                            iaddr, sizeof(iaddr),
	                                        desc, sizeof(desc));

	if(r < 0)
	{
		SoapError(h, 713, "SpecifiedArrayIndexInvalid");
	}
	else
	{
		int bodylen;
		char body[2048];
		bodylen = snprintf(body, sizeof(body), resp, (unsigned int)eport,
			protocol, (unsigned int)iport, iaddr, desc);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}

	ClearNameValueList(&data);
}

/*
If a control point calls QueryStateVariable on a state variable that is not
buffered in memory within (or otherwise available from) the service,
the service must return a SOAP fault with an errorCode of 404 Invalid Var.

QueryStateVariable remains useful as a limited test tool but may not be
part of some future versions of UPnP.
*/
static void
QueryStateVariable(struct upnphttp * h)
{
	static const char resp[] =
        "<u:QueryStateVariableResponse "
        "xmlns:u=\"urn:schemas-upnp-org:control-1-0\">"
		"<return>%s</return>"
        "</u:QueryStateVariableResponse>";

	char body[2048];
	int bodylen;
	struct NameValueParserData data;
	const char * var_name;

	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	/*var_name = GetValueFromNameValueList(&data, "QueryStateVariable"); */
	/*var_name = GetValueFromNameValueListIgnoreNS(&data, "varName");*/
	var_name = GetValueFromNameValueList(&data, "varName");

	/*syslog(LOG_INFO, "QueryStateVariable(%.40s)", var_name); */

	if(!var_name)
	{
		SoapError(h, 402, "Invalid Args");
	}
	else if(strcmp(var_name, "ConnectionStatus") == 0)
	{	
		bodylen = snprintf(body, sizeof(body), resp, "Connected");
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}
#if 0
	/* not usefull */
	else if(strcmp(var_name, "ConnectionType") == 0)
	{	
		bodylen = snprintf(body, sizeof(body), resp, "IP_Routed");
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}
	else if(strcmp(var_name, "LastConnectionError") == 0)
	{	
		bodylen = snprintf(body, sizeof(body), resp, "ERROR_NONE");
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}
#endif
	else if(strcmp(var_name, "PortMappingNumberOfEntries") == 0)
	{
		int r = 0, index = 0;
		unsigned short eport, iport;
		char protocol[4], iaddr[32], desc[64];
		char strindex[10];

		do
		{
			protocol[0] = '\0'; iaddr[0] = '\0'; desc[0] = '\0';

			r = upnp_get_redirection_infos_by_index(index, &eport, protocol, &iport,
													iaddr, sizeof(iaddr),
													desc, sizeof(desc));
			index++;
		}
		while(r==0);

		snprintf(strindex, sizeof(strindex), "%i", index - 1);
		bodylen = snprintf(body, sizeof(body), resp, strindex);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}
	else
	{
		syslog(LOG_NOTICE, "QueryStateVariable: Unknown: %s", var_name?var_name:"");
		SoapError(h, 404, "Invalid Var");
	}

	ClearNameValueList(&data);	
}

/* Windows XP as client send the following requests :
 * GetConnectionTypeInfo
 * GetNATRSIPStatus
 * ? GetTotalBytesSent - WANCommonInterfaceConfig
 * ? GetTotalBytesReceived - idem
 * ? GetTotalPacketsSent - idem
 * ? GetTotalPacketsReceived - idem
 * GetCommonLinkProperties - idem
 * GetStatusInfo - WANIPConnection
 * GetExternalIPAddress
 * QueryStateVariable / ConnectionStatus!
 */
static const struct 
{
	const char * methodName; 
	void (*methodImpl)(struct upnphttp *);
}
soapMethods[] =
{
	{ "GetConnectionTypeInfo", GetConnectionTypeInfo },
	{ "GetNATRSIPStatus", GetNATRSIPStatus},
	{ "GetExternalIPAddress", GetExternalIPAddress},
	{ "AddPortMapping", AddPortMapping},
	{ "DeletePortMapping", DeletePortMapping},
	{ "GetGenericPortMappingEntry", GetGenericPortMappingEntry},
	{ "GetSpecificPortMappingEntry", GetSpecificPortMappingEntry},
	{ "QueryStateVariable", QueryStateVariable},
	{ "GetTotalBytesSent", GetTotalBytesSent},
	{ "GetTotalBytesReceived", GetTotalBytesReceived},
	{ "GetTotalPacketsSent", GetTotalPacketsSent},
	{ "GetTotalPacketsReceived", GetTotalPacketsReceived},
	{ "GetCommonLinkProperties", GetCommonLinkProperties},
	{ "GetStatusInfo", GetStatusInfo},
	{ 0, 0 }
};

void
ExecuteSoapAction(struct upnphttp * h, const char * action, int n)
{
	char * p;
	char method[2048];
	int i, len, methodlen;

	i = 0;
	p = strchr(action, '#');
	methodlen = strchr(p, '"') - p - 1;

	if(p)
	{
		p++;
		while(soapMethods[i].methodName)
		{
			len = strlen(soapMethods[i].methodName);
			if(strncmp(p, soapMethods[i].methodName, len) == 0)
			{
				soapMethods[i].methodImpl(h);
				return;
			}
			i++;
		}

		memset(method, 0, 2048);
		memcpy(method, p, methodlen);
		syslog(LOG_NOTICE, "SoapMethod: Unknown: %s", method);
	}

	SoapError(h, 401, "Invalid Action");
}

/* Standard Errors:
 *
 * errorCode  	errorDescription  	Description
 * --------		----------------	-----------
 * 401 			Invalid Action 		No action by that name at this service.
 * 402 			Invalid Args 		Could be any of the following: not enough in args,
 * 									too many in args, no in arg by that name, 
 * 									one or more in args are of the wrong data type.
 * 403 			Out of Sync 		Out of synchronization.
 * 501 			Action Failed 		May be returned in current state of service prevents 
 * 									invoking that action.
 * 600-699 		TBD 				Common action errors. Defined by UPnP Forum Technical 
 * 									Committee.
 * 700-799 		TBD 				Action-specific errors for standard actions. Defined 
 * 									by UPnP Forum working committee.
 * 800-899 		TBD 				Action-specific errors for non-standard actions. 
 * 									Defined by UPnP vendor.
*/
void
SoapError(struct upnphttp * h, int errCode, const char * errDesc)
{
	static const char resp[] = 
		"<s:Envelope "
		"xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<s:Body>"
		"<s:Fault>"
		"<faultcode>s:Client</faultcode>"
		"<faultstring>UPnPError</faultstring>"
		"<detail>"
		"<UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">"
		"<errorCode>%d</errorCode>"
		"<errorDescription>%s</errorDescription>"
		"</UPnPError>"
		"</detail>"
		"</s:Fault>"
		"</s:Body>"
		"</s:Envelope>";

	char body[2048];
	int bodylen;

	syslog(LOG_INFO, "Returning UPnPError %d: %s", errCode, errDesc);
	bodylen = snprintf(body, sizeof(body), resp, errCode, errDesc);
	BuildResp2_upnphttp(h, 500, "Internal Server Error", body, bodylen);
	SendResp_upnphttp(h);
	CloseSocket_upnphttp(h);
}

