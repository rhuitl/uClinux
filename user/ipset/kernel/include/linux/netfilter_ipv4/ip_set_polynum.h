#ifndef __IP_SET_POLYNUM_H
#define __IP_SET_POLYNUM_H

#include <linux/netfilter_ipv4/ip_set.h>
#include <linux/netfilter_ipv4/ip_set_bitmaps.h>
#include <linux/types.h>

#define SETTYPE_NAME	"polynum"

struct ip_set_polynum {
	void *members;			/* the polynum proper */
	ip_set_ip_t first_ip;		/* host byte order, included in range */
	ip_set_ip_t last_ip;		/* host byte order, included in range */
	u_int32_t size;			/* size of the ipmap proper */
};

struct ip_set_req_polynum_create {
	ip_set_ip_t from;
	ip_set_ip_t to;
};

struct ip_set_req_polynum {
	ip_set_ip_t ip;
};

#endif /* __IP_SET_POLYNUM_H */
