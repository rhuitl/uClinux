#include <syslog.h>
#include <stdlib.h>
#include <upnp/ixml.h>
#include <string.h>
#include <time.h>
#include <upnp/upnp.h>
#include <upnp/upnptools.h>
#include <upnp/TimerThread.h>
#include "globals.h"
#include "gatedevice.h"
#include "pmlist.h"
#include "util.h"

//Definitions for mapping expiration timer thread
static TimerThread gExpirationTimerThread;
static ThreadPool gExpirationThreadPool;

char ConnectionStatus[20];
char ExternalIPAddress[20];
char LastConnectionError[35];
int PortMappingNumberOfEntries;
UpnpDevice_Handle deviceHandle;
char *gateUDN;
struct portMap *pmlist_Head, *pmlist_Tail, *pmlist_Current;
long int startup_time;

// MUTEX for locking shared state variables whenver they are changed
static ithread_mutex_t DevMutex = PTHREAD_MUTEX_INITIALIZER;

// Main event handler for callbacks from the SDK.  Determine type of event
// and dispatch to the appropriate handler (Note: Get Var Request deprecated
int EventHandler(Upnp_EventType EventType, void *Event, void *Cookie)
{
	switch (EventType)
	{
		case UPNP_EVENT_SUBSCRIPTION_REQUEST:
			HandleSubscriptionRequest((struct Upnp_Subscription_Request *) Event);
			break;
		// -- Deprecated --
		case UPNP_CONTROL_GET_VAR_REQUEST:
			HandleGetVarRequest((struct Upnp_State_Var_Request *) Event);
			break;
		case UPNP_CONTROL_ACTION_REQUEST:
			HandleActionRequest((struct Upnp_Action_Request *) Event);
			break;
		default:
			trace(1, "Error in EventHandler: Unknown event type %d",
						EventType);
	}
	return (0);
}

// Grab our UDN from the Description Document.  This may not be needed, 
// the UDN comes with the request, but we leave this for other device initializations
int StateTableInit(char *descDocUrl)
{
	IXML_Document *ixmlDescDoc;
	int ret;

	if ((ret = UpnpDownloadXmlDoc(descDocUrl, &ixmlDescDoc)) != UPNP_E_SUCCESS)
	{
		syslog(LOG_ERR, "Could not parse description document. Exiting ...");
		UpnpFinish();
		exit(0);
	}

	// Get the UDN from the description document, then free the DescDoc's memory
	gateUDN = GetFirstDocumentItem(ixmlDescDoc, "UDN");
	ixmlDocument_free(ixmlDescDoc);
		
	// Initialize our linked list of port mappings.
	pmlist_Head = pmlist_Current = NULL;
	PortMappingNumberOfEntries = 0;

	return (ret);
}

// Handles subscription request for state variable notifications
int HandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event)
{
	IXML_Document *propSet = NULL;
	
	ithread_mutex_lock(&DevMutex);

	if (strcmp(sr_event->UDN, gateUDN) == 0)
	{
		// WAN Common Interface Config Device Notifications
		if (strcmp(sr_event->ServiceId, "urn:upnp-org:serviceId:WANCommonIFC1") == 0)
		{
		        trace(3, "Recieved request to subscribe to WANCommonIFC1");
			UpnpAddToPropertySet(&propSet, "PhysicalLinkStatus", "Up");
			UpnpAcceptSubscriptionExt(deviceHandle, sr_event->UDN, sr_event->ServiceId,
						  propSet, sr_event->Sid);
			ixmlDocument_free(propSet);
		}
		// WAN IP Connection Device Notifications
		else if (strcmp(sr_event->ServiceId, "urn:upnp-org:serviceId:WANIPConn1") == 0)
		{
			GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
			trace(3, "Received request to subscribe to WANIPConn1");
			UpnpAddToPropertySet(&propSet, "PossibleConnectionTypes","IP_Routed");
			UpnpAddToPropertySet(&propSet, "ConnectionStatus","Connected");
			UpnpAddToPropertySet(&propSet, "ExternalIPAddress", ExternalIPAddress);
			UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries","0");
			UpnpAcceptSubscriptionExt(deviceHandle, sr_event->UDN, sr_event->ServiceId,
						  propSet, sr_event->Sid);
			ixmlDocument_free(propSet);
		}
	}
	ithread_mutex_unlock(&DevMutex);
	return(1);
}

int HandleGetVarRequest(struct Upnp_State_Var_Request *gv_request)
{
	// GET VAR REQUEST DEPRECATED FROM UPnP SPECIFICATIONS 
	// Report this in debug and ignore requests.  If anyone experiences problems
	// please let us know.
        trace(3, "Deprecated Get Variable Request received. Ignoring.");
	return 1;
}

int HandleActionRequest(struct Upnp_Action_Request *ca_event)
{
	int result = 0;

	ithread_mutex_lock(&DevMutex);
	
	if (strcmp(ca_event->DevUDN, gateUDN) == 0)
	{
		// Common debugging info, hopefully gets removed soon.
	        trace(3, "ActionName = %s", ca_event->ActionName);
		
		if (strcmp(ca_event->ServiceID, "urn:upnp-org:serviceId:WANIPConn1") == 0)
		{
			if (strcmp(ca_event->ActionName,"GetConnectionTypeInfo") == 0)
			  result = GetConnectionTypeInfo(ca_event);
			else if (strcmp(ca_event->ActionName,"GetNATRSIPStatus") == 0)
			  result = GetNATRSIPStatus(ca_event);
			else if (strcmp(ca_event->ActionName,"SetConnectionType") == 0)
			  result = SetConnectionType(ca_event);
			else if (strcmp(ca_event->ActionName,"RequestConnection") == 0)
			  result = RequestConnection(ca_event);
			else if (strcmp(ca_event->ActionName,"AddPortMapping") == 0)
			  result = AddPortMapping(ca_event);
			else if (strcmp(ca_event->ActionName,"GetGenericPortMappingEntry") == 0)
			  result = GetGenericPortMappingEntry(ca_event);
			else if (strcmp(ca_event->ActionName,"GetSpecificPortMappingEntry") == 0)
			  result = GetSpecificPortMappingEntry(ca_event);
			else if (strcmp(ca_event->ActionName,"GetExternalIPAddress") == 0)
			  result = GetExternalIPAddress(ca_event);
			else if (strcmp(ca_event->ActionName,"DeletePortMapping") == 0)
			  result = DeletePortMapping(ca_event);
			else if (strcmp(ca_event->ActionName,"GetStatusInfo") == 0)
			  result = GetStatusInfo(ca_event);
	
			// Intentionally Non-Implemented Functions -- To be added later
			/*else if (strcmp(ca_event->ActionName,"RequestTermination") == 0)
				result = RequestTermination(ca_event);
			else if (strcmp(ca_event->ActionName,"ForceTermination") == 0)
				result = ForceTermination(ca_event);
			else if (strcmp(ca_event->ActionName,"SetAutoDisconnectTime") == 0)
				result = SetAutoDisconnectTime(ca_event);
			else if (strcmp(ca_event->ActionName,"SetIdleDisconnectTime") == 0)
				result = SetIdleDisconnectTime(ca_event);
			else if (strcmp(ca_event->ActionName,"SetWarnDisconnectDelay") == 0)
				result = SetWarnDisconnectDelay(ca_event);
			else if (strcmp(ca_event->ActionName,"GetAutoDisconnectTime") == 0)
				result = GetAutoDisconnectTime(ca_event);
			else if (strcmp(ca_event->ActionName,"GetIdleDisconnectTime") == 0)
				result = GetIdleDisconnectTime(ca_event);
			else if (strcmp(ca_event->ActionName,"GetWarnDisconnectDelay") == 0)
				result = GetWarnDisconnectDelay(ca_event);*/
			else result = InvalidAction(ca_event);
		}
		else if (strcmp(ca_event->ServiceID,"urn:upnp-org:serviceId:WANCommonIFC1") == 0)
		{
			if (strcmp(ca_event->ActionName,"GetTotalBytesSent") == 0)
				result = GetTotal(ca_event, STATS_TX_BYTES);
			else if (strcmp(ca_event->ActionName,"GetTotalBytesReceived") == 0)
				result = GetTotal(ca_event, STATS_RX_BYTES);
			else if (strcmp(ca_event->ActionName,"GetTotalPacketsSent") == 0)
				result = GetTotal(ca_event, STATS_TX_PACKETS);
			else if (strcmp(ca_event->ActionName,"GetTotalPacketsReceived") == 0)
				result = GetTotal(ca_event, STATS_RX_PACKETS);
			else if (strcmp(ca_event->ActionName,"GetCommonLinkProperties") == 0)
				result = GetCommonLinkProperties(ca_event);
			else 
			{
				trace(1, "Invalid Action Request : %s",ca_event->ActionName);
				result = InvalidAction(ca_event);
			}
		} 
	}
	
	ithread_mutex_unlock(&DevMutex);

	return (result);
}

// Default Action when we receive unknown Action Requests
int InvalidAction(struct Upnp_Action_Request *ca_event)
{
        ca_event->ErrCode = 401;
        strcpy(ca_event->ErrStr, "Invalid Action");
        ca_event->ActionResult = NULL;
        return (ca_event->ErrCode);
}

// As IP_Routed is the only relevant Connection Type for Linux-IGD
// we respond with IP_Routed as both current type and only type
int GetConnectionTypeInfo (struct Upnp_Action_Request *ca_event)
{
	char resultStr[RESULT_LEN];
	IXML_Document *result;

	snprintf(resultStr, RESULT_LEN,
		"<u:GetConnectionTypeInfoResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
		"<NewConnectionType>IP_Routed</NewConnectionType>\n"
		"<NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>"
		"</u:GetConnectionTypeInfoResponse>");

   // Create a IXML_Document from resultStr and return with ca_event
   if ((result = ixmlParseBuffer(resultStr)) != NULL)
   {
      ca_event->ActionResult = result;
      ca_event->ErrCode = UPNP_E_SUCCESS;
   }
   else
   {
      trace(1, "Error parsing Response to GetConnectionTypeinfo: %s", resultStr);
      ca_event->ActionResult = NULL;
      ca_event->ErrCode = 402;
   }

	return(ca_event->ErrCode);
}

// Linux-IGD does not support RSIP.  However NAT is of course
// so respond with NewNATEnabled = 1
int GetNATRSIPStatus(struct Upnp_Action_Request *ca_event)
{
   char resultStr[RESULT_LEN];
	IXML_Document *result;

   snprintf(resultStr, RESULT_LEN, "<u:GetNATRSIPStatusResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
      							"<NewRSIPAvailable>0</NewRSIPAvailable>\n"
									"<NewNATEnabled>1</NewNATEnabled>\n"
								"</u:GetNATRSIPStatusResponse>");

	// Create a IXML_Document from resultStr and return with ca_event
	if ((result = ixmlParseBuffer(resultStr)) != NULL)
	{
		ca_event->ActionResult = result;
		ca_event->ErrCode = UPNP_E_SUCCESS;	
	}
   else
	{
	        trace(1, "Error parsing Response to GetNATRSIPStatus: %s", resultStr);
		ca_event->ActionResult = NULL;
		ca_event->ErrCode = 402;
	}

	return(ca_event->ErrCode);
}


// Connection Type is a Read Only Variable as linux-igd is only
// a device that supports a NATing IP router (not an Ethernet
// bridge).  Possible other uses may be explored.
int SetConnectionType(struct Upnp_Action_Request *ca_event)
{
	// Ignore requests
	ca_event->ActionResult = NULL;
	ca_event->ErrCode = UPNP_E_SUCCESS;
	return ca_event->ErrCode;
}

// This function should set the state variable ConnectionStatus to
// connecting, and then return synchronously, firing off a thread
// asynchronously to actually change the status to connected.  However, here we
// assume that the external WAN device is configured and connected
// outside of linux igd.
int RequestConnection(struct Upnp_Action_Request *ca_event)
{
	
	IXML_Document *propSet = NULL;
	
	//Immediatley Set connectionstatus to connected, and lastconnectionerror to none.
	strcpy(ConnectionStatus,"Connected");
	strcpy(LastConnectionError, "ERROR_NONE");
	trace(2, "RequestConnection recieved ... Setting Status to %s.", ConnectionStatus);

	// Build DOM Document with state variable connectionstatus and event it
	UpnpAddToPropertySet(&propSet, "ConnectionStatus", ConnectionStatus);
	
	// Send off notifications of state change
	UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);

	ca_event->ErrCode = UPNP_E_SUCCESS;
	return ca_event->ErrCode;
}


int GetCommonLinkProperties(struct Upnp_Action_Request *ca_event)
{
   char resultStr[RESULT_LEN];
	IXML_Document *result;
        
	ca_event->ErrCode = UPNP_E_SUCCESS;
	snprintf(resultStr, RESULT_LEN,
		"<u:GetCommonLinkPropertiesResponse xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">\n"
		"<NewWANAccessType>Cable</NewWANAccessType>\n"
		"<NewLayer1UpstreamMaxBitRate>%s</NewLayer1UpstreamMaxBitRate>\n"
		"<NewLayer1DownstreamMaxBitRate>%s</NewLayer1DownstreamMaxBitRate>\n"
		"<NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>\n"
		"</u:GetCommonLinkPropertiesResponse>",g_vars.upstreamBitrate,g_vars.downstreamBitrate);

   // Create a IXML_Document from resultStr and return with ca_event
   if ((result = ixmlParseBuffer(resultStr)) != NULL)
   {
      ca_event->ActionResult = result;
      ca_event->ErrCode = UPNP_E_SUCCESS;
   }
   else
   {
      trace(1, "Error parsing Response to GetCommonLinkProperties: %s", resultStr);
      ca_event->ActionResult = NULL;
      ca_event->ErrCode = 402;
   }

	return(ca_event->ErrCode);
}

/* get specified statistic from /proc/net/dev */
int GetTotal(struct Upnp_Action_Request *ca_event, stats_t stat)
{
	char dev[IFNAMSIZ], resultStr[RESULT_LEN];
	const char *methods[STATS_LIMIT] =
		{ "BytesSent", "BytesReceived", "PacketsSent", "PacketsReceived" };
	unsigned long stats[STATS_LIMIT];
	FILE *proc;
	IXML_Document *result;
	int read;
	
	proc = fopen("/proc/net/dev", "r");
	if (!proc)
	{
		fprintf(stderr, "failed to open\n");
		return 0;
	}

	/* skip first two lines */
	fscanf(proc, "%*[^\n]\n%*[^\n]\n");

	/* parse stats */
	do
		read = fscanf(proc, "%[^:]:%lu %lu %*u %*u %*u %*u %*u %*u %lu %lu %*u %*u %*u %*u %*u %*u\n", dev, &stats[STATS_RX_BYTES], &stats[STATS_RX_PACKETS], &stats[STATS_TX_BYTES], &stats[STATS_TX_PACKETS]);
	while (read != EOF && (read == 5 && strncmp(dev, g_vars.extInterfaceName, IFNAMSIZ) != 0));

	fclose(proc);

	snprintf(resultStr, RESULT_LEN,
		"<u:GetTotal%sResponse xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">\n"
		"<NewTotal%s>%lu</NewTotal%s>\n"
		"</u:GetTotal%sResponse>", 
		methods[stat], methods[stat], stats[stat], methods[stat], methods[stat]);

	// Create a IXML_Document from resultStr and return with ca_event
	if ((result = ixmlParseBuffer(resultStr)) != NULL)
	{
		ca_event->ActionResult = result;
		ca_event->ErrCode = UPNP_E_SUCCESS;
	}
	else
	{
		trace(1, "Error parsing response to GetTotal: %s", resultStr);
		ca_event->ActionResult = NULL;
		ca_event->ErrCode = 402;
	}

	return (ca_event->ErrCode);
}

// Returns connection status related information to the control points
int GetStatusInfo(struct Upnp_Action_Request *ca_event)
{
   long int uptime;
   char resultStr[RESULT_LEN];
	IXML_Document *result = NULL;

   uptime = (time(NULL) - startup_time);
   
	snprintf(resultStr, RESULT_LEN,
		"<u:GetStatusInfoResponse xmlns:u=\"urn:schemas-upnp-org:service:GetStatusInfo:1\">\n"
		"<NewConnectionStatus>Connected</NewConnectionStatus>\n"
		"<NewLastConnectionError>ERROR_NONE</NewLastConnectionError>\n"
		"<NewUptime>%li</NewUptime>\n"
		"</u:GetStatusInfoResponse>", 
		uptime);
   
	// Create a IXML_Document from resultStr and return with ca_event
   if ((result = ixmlParseBuffer(resultStr)) != NULL)
   {
      ca_event->ActionResult = result;
      ca_event->ErrCode = UPNP_E_SUCCESS;
   }
   else
   {
     trace(1, "Error parsing Response to GetStatusInfo: %s", resultStr);
      ca_event->ActionResult = NULL;
      ca_event->ErrCode = 402;
   }

   return(ca_event->ErrCode);
}

// Add New Port Map to the IGD
int AddPortMapping(struct Upnp_Action_Request *ca_event)
{
	char *remote_host=NULL;
	char *ext_port=NULL;
	char *proto=NULL;
	char *int_port=NULL;
	char *int_ip=NULL;
	char *int_duration=NULL;
	char *bool_enabled=NULL;
	char *desc=NULL;
  	struct portMap *ret, *new;
	int result;
	char num[5]; // Maximum number of port mapping entries 9999
	IXML_Document *propSet = NULL;
	int action_succeeded = 0;
	char resultStr[RESULT_LEN];

	if ( (ext_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort") )
	     && (proto = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol") )
	     && (int_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewInternalPort") )
	     && (int_ip = GetFirstDocumentItem(ca_event->ActionRequest, "NewInternalClient") )
	     && (int_duration = GetFirstDocumentItem(ca_event->ActionRequest, "NewLeaseDuration") )
	     && (bool_enabled = GetFirstDocumentItem(ca_event->ActionRequest, "NewEnabled") )
	     && (desc = GetFirstDocumentItem(ca_event->ActionRequest, "NewPortMappingDescription") ))
	{
	  remote_host = GetFirstDocumentItem(ca_event->ActionRequest, "NewRemoteHost");
		// If port map with the same External Port, Protocol, and Internal Client exists
		// then, as per spec, we overwrite it (for simplicity, we delete and re-add at end of list)
		// Note: This may cause problems with GetGernericPortMappingEntry if a CP expects the overwritten
		// to be in the same place.
		if ((ret = pmlist_Find(ext_port, proto, int_ip)) != NULL)
		{
				trace(3, "Found port map to already exist.  Replacing");
				pmlist_Delete(ret);
		}
			
		new = pmlist_NewNode(atoi(bool_enabled), atol(int_duration), "", ext_port, int_port, proto, int_ip, desc); 
		result = pmlist_PushBack(new);
		if (result==1)
		{
		        ScheduleMappingExpiration(new,ca_event->DevUDN,ca_event->ServiceID);
			sprintf(num, "%d", pmlist_Size());
			trace(3, "PortMappingNumberOfEntries: %d", pmlist_Size());
			UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", num);				
			UpnpNotifyExt(deviceHandle, ca_event->DevUDN, ca_event->ServiceID, propSet);
			ixmlDocument_free(propSet);
			trace(2, "AddPortMap: DevUDN: %s ServiceID: %s RemoteHost: %s Prot: %s ExtPort: %s Int: %s.%s",
					    ca_event->DevUDN,ca_event->ServiceID,remote_host, proto, ext_port, int_ip, int_port);
			action_succeeded = 1;
		}
		else
		{
			if (result==718)
			{
				trace(1,"Failure in GateDeviceAddPortMapping: RemoteHost: %s Prot:%s ExtPort: %s Int: %s.%s\n",
						    remote_host, proto, ext_port, int_ip, int_port);
				ca_event->ErrCode = 718;
				strcpy(ca_event->ErrStr, "ConflictInMappingEntry");
				ca_event->ActionResult = NULL;
			}
 		}
	}
	else
	{
	  trace(1, "Failiure in GateDeviceAddPortMapping: Invalid Arguments!");
	  trace(1, "  ExtPort: %s Proto: %s IntPort: %s IntIP: %s Dur: %s Ena: %s Desc: %s",
		ext_port, proto, int_port, int_ip, int_duration, bool_enabled, desc);
	  ca_event->ErrCode = 402;
	  strcpy(ca_event->ErrStr, "Invalid Args");
	  ca_event->ActionResult = NULL;
	}
	
	if (action_succeeded)
	{
		ca_event->ErrCode = UPNP_E_SUCCESS;
		snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
			ca_event->ActionName, "urn:schemas-upnp-org:service:WANIPConnection:1", "", ca_event->ActionName);
		ca_event->ActionResult = ixmlParseBuffer(resultStr);
	}

	if (ext_port) free(ext_port);
	if (int_port) free(int_port);
	if (proto) free(proto);
	if (int_ip) free(int_ip);
	if (bool_enabled) free(bool_enabled);
	if (desc) free(desc);
	if (remote_host) free(remote_host);

	return(ca_event->ErrCode);
}

int GetGenericPortMappingEntry(struct Upnp_Action_Request *ca_event)
{
	char *mapindex = NULL;
	struct portMap *temp;
	char result_param[RESULT_LEN];
	char resultStr[RESULT_LEN];
	int action_succeeded = 0;

	if ((mapindex = GetFirstDocumentItem(ca_event->ActionRequest, "NewPortMappingIndex")))
	{
		temp = pmlist_FindByIndex(atoi(mapindex));
		if (temp)
		{
			snprintf(result_param, RESULT_LEN, "<NewRemoteHost>%s</NewRemoteHost><NewExternalPort>%s</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%s</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%d</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%li</NewLeaseDuration>", temp->m_RemoteHost, temp->m_ExternalPort, temp->m_PortMappingProtocol, temp->m_InternalPort, temp->m_InternalClient, temp->m_PortMappingEnabled, temp->m_PortMappingDescription, temp->m_PortMappingLeaseDuration);
			action_succeeded = 1;
		}
      if (action_succeeded)
      {
         ca_event->ErrCode = UPNP_E_SUCCESS;
                   snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>", ca_event->ActionName,
                           "urn:schemas-upnp-org:service:WANIPConnection:1",result_param, ca_event->ActionName);
                   ca_event->ActionResult = ixmlParseBuffer(resultStr);
      }
      else
      {
         ca_event->ErrCode = 713;
			strcpy(ca_event->ErrStr, "SpecifiedArrayIndexInvalid");
			ca_event->ActionResult = NULL;
      }

   }
   else
   {
            trace(1, "Failure in GateDeviceGetGenericPortMappingEntry: Invalid Args");
            ca_event->ErrCode = 402;
                 strcpy(ca_event->ErrStr, "Invalid Args");
                 ca_event->ActionResult = NULL;
   }
	if (mapindex) free (mapindex);
	return (ca_event->ErrCode);
 	
}
int GetSpecificPortMappingEntry(struct Upnp_Action_Request *ca_event)
{
   char *ext_port=NULL;
   char *proto=NULL;
   char result_param[RESULT_LEN];
   char resultStr[RESULT_LEN];
   int action_succeeded = 0;
	struct portMap *temp;

   if ((ext_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort"))
      && (proto = GetFirstDocumentItem(ca_event->ActionRequest,"NewProtocol")))
   {
      if ((strcmp(proto, "TCP") == 0) || (strcmp(proto, "UDP") == 0))
      {
			temp = pmlist_FindSpecific (ext_port, proto);
			if (temp)
			{
				snprintf(result_param, RESULT_LEN, "<NewInternalPort>%s</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%d</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%li</NewLeaseDuration>",
            temp->m_InternalPort,
            temp->m_InternalClient,
            temp->m_PortMappingEnabled,
				temp->m_PortMappingDescription,
            temp->m_PortMappingLeaseDuration);
            action_succeeded = 1;
			}
         if (action_succeeded)
         {
            ca_event->ErrCode = UPNP_E_SUCCESS;
	    snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>", ca_event->ActionName,
		    "urn:schemas-upnp-org:service:WANIPConnection:1",result_param, ca_event->ActionName);
	    ca_event->ActionResult = ixmlParseBuffer(resultStr);
         }
         else
         {
            trace(2, "GateDeviceGetSpecificPortMappingEntry: PortMapping Doesn't Exist...");
	    ca_event->ErrCode = 714;
	    strcpy(ca_event->ErrStr, "NoSuchEntryInArray");
	    ca_event->ActionResult = NULL;
         }
      }
      else
      {
              trace(1, "Failure in GateDeviceGetSpecificPortMappingEntry: Invalid NewProtocol=%s\n",proto);
	      ca_event->ErrCode = 402;
	      strcpy(ca_event->ErrStr, "Invalid Args");
	      ca_event->ActionResult = NULL;
      }
   }
   else
   {
      trace(1, "Failure in GateDeviceGetSpecificPortMappingEntry: Invalid Args");
      ca_event->ErrCode = 402;
      strcpy(ca_event->ErrStr, "Invalid Args");
      ca_event->ActionResult = NULL;
   }

   return (ca_event->ErrCode);


}
int GetExternalIPAddress(struct Upnp_Action_Request *ca_event)
{
   char resultStr[RESULT_LEN];
	IXML_Document *result = NULL;

   ca_event->ErrCode = UPNP_E_SUCCESS;
   GetIpAddressStr(ExternalIPAddress, g_vars.extInterfaceName);
   snprintf(resultStr, RESULT_LEN, "<u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
										"<NewExternalIPAddress>%s</NewExternalIPAddress>\n"
								"</u:GetExternalIPAddressResponse>", ExternalIPAddress);

   // Create a IXML_Document from resultStr and return with ca_event
   if ((result = ixmlParseBuffer(resultStr)) != NULL)
   {
      ca_event->ActionResult = result;
      ca_event->ErrCode = UPNP_E_SUCCESS;
   }
   else
   {
      trace(1, "Error parsing Response to ExternalIPAddress: %s", resultStr);
      ca_event->ActionResult = NULL;
      ca_event->ErrCode = 402;
   }

   return(ca_event->ErrCode);
}

int DeletePortMapping(struct Upnp_Action_Request *ca_event)
{
   char *ext_port=NULL;
   char *proto=NULL;
   int result=0;
   char num[5];
   char resultStr[RESULT_LEN];
   IXML_Document *propSet= NULL;
   int action_succeeded = 0;
	struct portMap *temp;

   if (((ext_port = GetFirstDocumentItem(ca_event->ActionRequest, "NewExternalPort")) &&
      (proto = GetFirstDocumentItem(ca_event->ActionRequest, "NewProtocol"))))
   {

     if ((strcmp(proto, "TCP") == 0) || (strcmp(proto, "UDP") == 0))
     {
       if ((temp = pmlist_FindSpecific(ext_port, proto)))
	 result = pmlist_Delete(temp);

         if (result==1)
         {
            trace(2, "DeletePortMap: Proto:%s Port:%s\n",proto, ext_port);
            sprintf(num,"%d",pmlist_Size());
            UpnpAddToPropertySet(&propSet,"PortMappingNumberOfEntries", num);
            UpnpNotifyExt(deviceHandle, ca_event->DevUDN,ca_event->ServiceID,propSet);
            ixmlDocument_free(propSet);
            action_succeeded = 1;
         }
         else
         {
            trace(1, "Failure in GateDeviceDeletePortMapping: DeletePortMap: Proto:%s Port:%s\n",proto, ext_port);
            ca_event->ErrCode = 714;
            strcpy(ca_event->ErrStr, "NoSuchEntryInArray");
            ca_event->ActionResult = NULL;
         }
      }
      else
      {
         trace(1, "Failure in GateDeviceDeletePortMapping: Invalid NewProtocol=%s\n",proto);
         ca_event->ErrCode = 402;
			strcpy(ca_event->ErrStr, "Invalid Args");
			ca_event->ActionResult = NULL;
      }
   }
   else
   {
		trace(1, "Failiure in GateDeviceDeletePortMapping: Invalid Arguments!");
		ca_event->ErrCode = 402;
		strcpy(ca_event->ErrStr, "Invalid Args");
		ca_event->ActionResult = NULL;
   }

   if (action_succeeded)
   {
      ca_event->ErrCode = UPNP_E_SUCCESS;
      snprintf(resultStr, RESULT_LEN, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>",
         ca_event->ActionName, "urn:schemas-upnp-org:service:WANIPConnection:1", "", ca_event->ActionName);
      ca_event->ActionResult = ixmlParseBuffer(resultStr);
   }

   if (ext_port) free(ext_port);
   if (proto) free(proto);

   return(ca_event->ErrCode);
}

// From sampleutil.c included with libupnp 
char* GetFirstDocumentItem( IN IXML_Document * doc,
                                 IN const char *item )
{
    IXML_NodeList *nodeList = NULL;
    IXML_Node *textNode = NULL;
    IXML_Node *tmpNode = NULL;

    char *ret = NULL;

    nodeList = ixmlDocument_getElementsByTagName( doc, ( char * )item );

    if( nodeList ) {
        if( ( tmpNode = ixmlNodeList_item( nodeList, 0 ) ) ) {
            textNode = ixmlNode_getFirstChild( tmpNode );
       if (textNode != NULL)
       {
      ret = strdup( ixmlNode_getNodeValue( textNode ) );
       }
        }
    }

    if( nodeList )
        ixmlNodeList_free( nodeList );
    return ret;
}

int ExpirationTimerThreadInit(void)
{
  int retVal;
  ThreadPoolAttr attr;
  TPAttrInit( &attr );
  TPAttrSetMaxThreads( &attr, MAX_THREADS );
  TPAttrSetMinThreads( &attr, MIN_THREADS );
  TPAttrSetJobsPerThread( &attr, JOBS_PER_THREAD );
  TPAttrSetIdleTime( &attr, THREAD_IDLE_TIME );

  if( ThreadPoolInit( &gExpirationThreadPool, &attr ) != UPNP_E_SUCCESS ) {
    return UPNP_E_INIT_FAILED;
  }

  if( ( retVal = TimerThreadInit( &gExpirationTimerThread,
				  &gExpirationThreadPool ) ) !=
      UPNP_E_SUCCESS ) {
    return retVal;
  }
  
  return 0;
}

int ExpirationTimerThreadShutdown(void)
{
  return TimerThreadShutdown(&gExpirationTimerThread);
}


void free_expiration_event(expiration_event *event)
{
  if (event->mapping!=NULL)
    event->mapping->expirationEventId = -1;
  free(event);
}

void ExpireMapping(void *input)
{
  char num[5]; // Maximum number of port mapping entries 9999
  IXML_Document *propSet = NULL;
  expiration_event *event = ( expiration_event * ) input;
    
  ithread_mutex_lock(&DevMutex);

  trace(2, "ExpireMapping: Proto:%s Port:%s\n",
		      event->mapping->m_PortMappingProtocol, event->mapping->m_ExternalPort);

  //reset the event id before deleting the mapping so that pmlist_Delete
  //will not call CancelMappingExpiration
  event->mapping->expirationEventId = -1;
  pmlist_Delete(event->mapping);
  
  sprintf(num, "%d", pmlist_Size());
  UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", num);
  UpnpNotifyExt(deviceHandle, event->DevUDN, event->ServiceID, propSet);
  ixmlDocument_free(propSet);
  trace(3, "ExpireMapping: UpnpNotifyExt(deviceHandle,%s,%s,propSet)\n  PortMappingNumberOfEntries: %s",
		      event->DevUDN, event->ServiceID, num);
  
  free_expiration_event(event);
  
  ithread_mutex_unlock(&DevMutex);
}

int ScheduleMappingExpiration(struct portMap *mapping, char *DevUDN, char *ServiceID)
{
  int retVal = 0;
  ThreadPoolJob job;
  expiration_event *event;
  time_t curtime = time(NULL);
	
  if (mapping->m_PortMappingLeaseDuration > 0) {
    mapping->expirationTime = curtime + mapping->m_PortMappingLeaseDuration;
  }
  else {
    //client did not provide a duration, so use the default duration
    if (g_vars.duration==0) {
      return 1; //no default duration set
    }
    else if (g_vars.duration>0) {
      //relative duration
      mapping->expirationTime = curtime+g_vars.duration;
    }
    else { //g_vars.duration < 0
      //absolute daily expiration time
      long int expclock = -1*g_vars.duration;
      struct tm *loctime = localtime(&curtime);
      long int curclock = loctime->tm_hour*3600 + loctime->tm_min*60 + loctime->tm_sec;
      long int diff = expclock-curclock;
      if (diff<60) //if exptime is in less than a minute (or in the past), schedule it in 24 hours instead
	diff += 24*60*60;
      mapping->expirationTime = curtime+diff;
    }
  }

  event = ( expiration_event * ) malloc( sizeof( expiration_event ) );
  if( event == NULL ) {
    return 0;
  }
  event->mapping = mapping;
  if (strlen(DevUDN) < sizeof(event->DevUDN)) strcpy(event->DevUDN, DevUDN);
  else strcpy(event->DevUDN, "");
  if (strlen(ServiceID) < sizeof(event->ServiceID)) strcpy(event->ServiceID, ServiceID);
  else strcpy(event->ServiceID, "");
  
  TPJobInit( &job, ( start_routine ) ExpireMapping, event );
  TPJobSetFreeFunction( &job, ( free_routine ) free_expiration_event );
  if( ( retVal = TimerThreadSchedule( &gExpirationTimerThread,
				      mapping->expirationTime,
				      ABS_SEC, &job, SHORT_TERM,
				      &( event->eventId ) ) )
      != UPNP_E_SUCCESS ) {
    free( event );
    mapping->expirationEventId = -1;
    return 0;
  }
  mapping->expirationEventId = event->eventId;

  trace(3,"ScheduleMappingExpiration: DevUDN: %s ServiceID: %s Proto: %s ExtPort: %s Int: %s.%s at: %s eventId: %d",event->DevUDN,event->ServiceID,mapping->m_PortMappingProtocol, mapping->m_ExternalPort, mapping->m_InternalClient, mapping->m_InternalPort, ctime(&(mapping->expirationTime)), event->eventId);

  return event->eventId;
}

int CancelMappingExpiration(int expirationEventId)
{
  ThreadPoolJob job;
  if (expirationEventId<0)
    return 1;
  trace(3,"CancelMappingExpiration: eventId: %d",expirationEventId);
  if (TimerThreadRemove(&gExpirationTimerThread,expirationEventId,&job)==0) {
    free_expiration_event((expiration_event *)job.arg);
  }
  else {
    trace(1,"  TimerThreadRemove failed!");
  }
  return 1;
}

void DeleteAllPortMappings(void)
{
  IXML_Document *propSet = NULL;

  ithread_mutex_lock(&DevMutex);

  pmlist_FreeList();

  UpnpAddToPropertySet(&propSet, "PortMappingNumberOfEntries", "0");
  UpnpNotifyExt(deviceHandle, gateUDN, "urn:upnp-org:serviceId:WANIPConn1", propSet);
  ixmlDocument_free(propSet);
  trace(2, "DeleteAllPortMappings: UpnpNotifyExt(deviceHandle,%s,%s,propSet)\n  PortMappingNumberOfEntries: %s",
	gateUDN, "urn:upnp-org:serviceId:WANIPConn1", "0");

  ithread_mutex_unlock(&DevMutex);
}
