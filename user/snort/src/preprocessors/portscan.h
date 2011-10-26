#ifndef __PORTSCAN_H__
#define __PORTSCAN_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
#ifndef WIN32
    #include <sys/time.h>
#endif /* !WIN32 */

#include "ipobj.h"

#ifndef WIN32
#ifndef INLINE
#define INLINE inline
#endif
#else
#ifndef INLINE
#define INLINE __inline
#endif
#endif

#define PS_OPEN_PORTS 8

typedef struct s_PS_PROTO
{
    short          connection_count;
    short          priority_count;
    short          u_ip_count;
    short          u_port_count;

    unsigned short high_p;
    unsigned short low_p;
    unsigned short u_ports;

    unsigned long  high_ip;
    unsigned long  low_ip;
    unsigned long  u_ips;

    unsigned short open_ports[PS_OPEN_PORTS];
    unsigned char  open_ports_cnt;

    struct timeval event_time;
    unsigned int   event_ref;

    unsigned char  alerts;

    time_t         window;

} PS_PROTO;    

typedef struct s_PS_TRACKER
{
    char     priority_node;
    PS_PROTO proto[1];

} PS_TRACKER;

typedef struct s_PS_PKT
{
    void            *pkt;

    PS_TRACKER      *scanner;
    PS_TRACKER      *scanned;

    int              proto;
    int              proto_idx;

    int              reverse_pkt;
} PS_PKT;

#define PS_PROTO_TCP         0x01
#define PS_PROTO_UDP         0x02
#define PS_PROTO_ICMP        0x04
#define PS_PROTO_IP          0x08
#define PS_PROTO_ALL         0x0f

#define PS_PROTO_OPEN_PORT   0x80

#define PS_TYPE_PORTSCAN     0x01
#define PS_TYPE_PORTSWEEP    0x02
#define PS_TYPE_DECOYSCAN    0x04
#define PS_TYPE_DISTPORTSCAN 0x08
#define PS_TYPE_ALL          0x0f

#define PS_SENSE_HIGH        1
#define PS_SENSE_MEDIUM      2
#define PS_SENSE_LOW         3

#define PS_ALERT_ONE_TO_ONE                1
#define PS_ALERT_ONE_TO_ONE_DECOY          2
#define PS_ALERT_PORTSWEEP                 3
#define PS_ALERT_DISTRIBUTED               4
#define PS_ALERT_ONE_TO_ONE_FILTERED       5
#define PS_ALERT_ONE_TO_ONE_DECOY_FILTERED 6
#define PS_ALERT_DISTRIBUTED_FILTERED      7
#define PS_ALERT_PORTSWEEP_FILTERED        8
#define PS_ALERT_OPEN_PORT                 9

#define PS_ALERT_GENERATED                 255

int  ps_init(int detect_scans, int detect_scan_type, int sense_level,
        IPSET *ignore_scanners, IPSET *ignore_scanned, IPSET *watch_ip,
        int memcap);
        
int  ps_detect(PS_PKT *p);
void ps_tracker_print(PS_TRACKER *tracker);

#endif

