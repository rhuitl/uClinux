/* $Id: upnpglobalvars.h,v 1.1 2007-12-27 05:33:40 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef __UPNPGLOBALVARS_H__
#define __UPNPGLOBALVARS_H__

#include <time.h>
#include "upnppermissions.h"

/* name of the network interface used to acces internet */
extern const char * ext_if_name;

/* forced ip address to use for this interface
 * when NULL, getifaddr() is used */
extern const char * use_ext_ip_addr;

/* LAN address */
/*extern const char * listen_addr;*/

/* parameters to return to upnp client when asked */
extern unsigned long downstream_bitrate;
extern unsigned long upstream_bitrate;

/* log packets flag */
extern int logpackets;

/* statup time */
extern time_t startup_time;

/* use system uptime */
extern int sysuptime;

extern const char * pidfilename;

extern char uuidvalue[];

#define SERIALNUMBER_MAX_LEN (10)
extern char serialnumber[];

#define MODELNUMBER_MAX_LEN (48)
extern char modelnumber[];

#define PRESENTATIONURL_MAX_LEN (64)
extern char presentationurl[];

/* UPnP permission rules : */
extern struct upnpperm * upnppermlist;
extern unsigned int num_upnpperm;

#endif

