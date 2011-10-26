/* $Id: miniupnpdtypes.h,v 1.1 2007-12-27 05:33:40 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2007 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#ifndef __MINIUPNPDTYPES_H__
#define __MINIUPNPDTYPES_H__

#include <netinet/in.h>

/* structure for storing lan addresses
 * with ascii representation and mask */
struct lan_addr_s {
	char str[16];	/* ex: 192.168.0.1 */
	struct in_addr addr, mask;	/* ip/mask */
};

#endif
