/* dhcpd.h */

#define VERSION			"0.8.29"

/************************************/
/* Defaults _you_ may want to tweak */
/************************************/

#define MAX_SIMUL_CLIENTS	16 /* maximum number of simultaneous clients */

/* the period of time the client is allowed to use that address */
#define LEASE_TIME              "\x00\x00\x54\x60" /* 6 hours */

/* where to find the DHCP server files */
#define DHCPD_CONF_FILE         "/etc/config/dhcpd.conf"
#define DHCPD_IPLIST_FILE       "/etc/config/dhcpd.iplist"
#define DHCPD_LEASES_FILE       "/etc/config/dhcpd.leases"
#define PID_FILE                "/var/run/dhcpd.pid"


/*****************************************************************/
/* Do not modify below here unless you know what you are doing!! */
/*****************************************************************/

/* DHCP protocol -- see RFC */
#define LISTEN_PORT		67
#define SEND_PORT		68

#define MAGIC			0x63825363

#define DHCP_MESSAGE_TYPE	0x35
#define DHCP_SERVER_ID		0x36
#define DHCP_CLIENT_ID		0x3d

#define BOOTREQUEST		1
#define BOOTREPLY		2

#define ETH_10MB		1
#define ETH_10MB_LEN		6

#define DHCPDISCOVER		1
#define DHCPOFFER		2
#define DHCPREQUEST		3
#define DHCPDECLINE		4
#define DHCPACK			5
#define DHCPNAK			6
#define DHCPRELEASE		7

/* miscellaneous defines */
#define IPLIST			0
#define LEASED			1
#define TRUE			1
#define FALSE			0
#define MAX_BUF_SIZE		20 /* max xxx.xxx.xxx.xxx-xxx\n */
#define MAX_IP_ADDR		254
#define ADD			1
#define DEL			2

struct dhcpMessage {
	u_int8_t op;
	u_int8_t htype;
	u_int8_t hlen;
	u_int8_t hops;
	u_int32_t xid;
	u_int16_t secs;
	u_int16_t flags;
	u_int32_t ciaddr;
	u_int32_t yiaddr;
	u_int32_t siaddr;
	u_int32_t giaddr;
	u_int8_t chaddr[16];
	u_int8_t sname[64];
	u_int8_t file[128];
	u_int32_t cookie;
#ifdef EMBED
	u_int8_t options[128]; /* should be 308 but have to conserve space :-) */
#else
	u_int8_t options[308]; 
#endif
};


struct dhcpOfferedAddr {
	u_int8_t chaddr[16];
	u_int32_t yiaddr;
};


extern char *interface_name;
extern unsigned char interface_hwaddr[6];
