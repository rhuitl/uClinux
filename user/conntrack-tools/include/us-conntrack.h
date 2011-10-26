#ifndef _US_CONNTRACK_H_
#define _US_CONNTRACK_H_

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

/* be careful, do not modify the layout */
struct us_conntrack {
	struct 	nf_conntrack *ct;
	struct  cache *cache;          /* add new attributes here */
	char 	data[0];
};

#endif
