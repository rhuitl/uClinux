#ifndef _NETINET_IGMP_H
#define _NETINET_IGMP_H

#include <linux/igmp.h>

#ifdef __BSD_SOURCE

struct igmp
{
	__u8 igmp_type;
	__u8 igmp_code;
	__u16 igmp_cksum;
	struct in_addr igmp_group;
};

#define IGMP_MINLEN 			8
#define IGMP_MAX_HOST_REPORT_DELAY	10
#define IGMP_TIMER_SCALE		10

#define IGMP_AGE_THRESHOLD		540

#endif

#endif /* _NETINET_IGMP_H */
