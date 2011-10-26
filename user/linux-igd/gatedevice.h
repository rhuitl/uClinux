#ifndef _GATEDEVICE_H_
#define _GATEDEVICE_H_ 1

#include <upnp/upnp.h>

/* interface statistics */
typedef enum {
        STATS_TX_BYTES,
        STATS_RX_BYTES,
        STATS_TX_PACKETS,
        STATS_RX_PACKETS,
        STATS_LIMIT
} stats_t;

// IGD Device Globals
extern UpnpDevice_Handle deviceHandle;
extern char *gateUDN;
extern long int startup_time;

// State Variables
extern char ConnectionType[50];
extern char PossibleConnectionTypes[50];
extern char ConnectionStatus[20];
extern long int StartupTime;
extern char LastConnectionError[35];
extern long int AutoDisconnectTime;
extern long int IdleDisconnectTime;
extern long int WarnDisconnectDelay;
extern int RSIPAvailable;
extern int NATEnabled;
extern char ExternalIPAddress[20];
extern int PortMappingNumberOfEntries;
extern int PortMappingEnabled;

// Helper routines
extern char* GetFirstDocumentItem( IN IXML_Document * doc, const char *item );

// Linked list for portmapping entries
extern struct portMap *pmlist_Head;
extern struct portMap *pmlist_Current;

// WanIPConnection Actions 
int EventHandler(Upnp_EventType EventType, void *Event, void *Cookie);
int StateTableInit(char *descDocUrl);
int HandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event);
int HandleGetVarRequest(struct Upnp_State_Var_Request *gv_event);
int HandleActionRequest(struct Upnp_Action_Request *ca_event);

int GetConnectionTypeInfo(struct Upnp_Action_Request *ca_event);
int GetNATRSIPStatus(struct Upnp_Action_Request *ca_event);
int SetConnectionType(struct Upnp_Action_Request *ca_event);
int RequestConnection(struct Upnp_Action_Request *ca_event);
int GetTotal(struct Upnp_Action_Request *ca_event, stats_t stat);
int GetCommonLinkProperties(struct Upnp_Action_Request *ca_event);
int InvalidAction(struct Upnp_Action_Request *ca_event);
int GetStatusInfo(struct Upnp_Action_Request *ca_event);
int AddPortMapping(struct Upnp_Action_Request *ca_event);
int GetGenericPortMappingEntry(struct Upnp_Action_Request *ca_event);
int GetSpecificPortMappingEntry(struct Upnp_Action_Request *ca_event);
int GetExternalIPAddress(struct Upnp_Action_Request *ca_event);
int DeletePortMapping(struct Upnp_Action_Request *ca_event);

// Definitions for mapping expiration timer thread
#define THREAD_IDLE_TIME 5000
#define JOBS_PER_THREAD 10
#define MIN_THREADS 2 
#define MAX_THREADS 12 

int ExpirationTimerThreadInit(void);
int ExpirationTimerThreadShutdown(void);
int ScheduleMappingExpiration(struct portMap *mapping, char *DevUDN, char *ServiceID);
int CancelMappingExpiration(int eventId);
void DeleteAllPortMappings(void);

#endif //_GATEDEVICE_H
