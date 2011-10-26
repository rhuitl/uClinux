/*
 * route.c - diald routing code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

/* set up a point to point route for a device */
void set_ptp(char *itype, int iface, char *rip, int metric)
{
    char buf[128];
    char win[32];
    int res;
    if (window == 0)
	win[0] = 0;
    else
    	sprintf(win,"window %d",window);
    if (debug&DEBUG_VERBOSE)
	syslog(LOG_INFO, "Setting pointopoint route for %s%d",itype,iface);
    sprintf(buf,"%s add %s metric %d %s dev %s%d",
	PATH_ROUTE,rip,metric,win,itype,iface); 
    res = system(buf);
    report_system_result(res,buf);
}

/*
 * Add in a direct and default route to the slip link.
 * The default route is only added if the "default" option was
 * requested by the user.
 */

void add_routes(char *itype, int iface, char *lip, char *rip, int metric)
{
    char buf[128];
    char win[32];
    int res;

    if (debug&DEBUG_VERBOSE)
	syslog(LOG_INFO,"Establishing routes for %s%d",itype,iface);

    if (window == 0)
	win[0] = 0;
    else
    	sprintf(win,"window %d",window);
    sprintf(buf,"INTERFACE\n%s%d\n%s\n%s\n", itype, iface, lip, rip);
    if (monitors) mon_write(MONITOR_INTERFACE,buf,strlen(buf));

    /* Add in a default route for the link */
    /* FIXME: should this refuse to add if a default route exists? */
    if (default_route) {
		sprintf(buf,"%s add default gw %s metric %d %s dev %s%d",
		PATH_ROUTE, rip, metric,win,itype,iface);
        res = system(buf);
    	report_system_result(res,buf);
    }

    /* call addroute script */
    if (addroute) {
        sprintf(buf,"%s %s%d %s %s %s %d %d",
	    addroute,itype,iface,(netmask)?netmask:"default",
	    lip,rip,metric,window);
		res = system(buf);
    	report_system_result(res,buf);
    }

    if (proxyarp) set_proxyarp(inet_addr(rip));
}

/*
 * Call the delroute script.
 */
void del_routes(char *itype, int iface, char *lip, char *rip, int metric)
{
    char buf[128];
    int res;

    if (debug&DEBUG_VERBOSE)
	syslog(LOG_INFO,"Removing routes for %s%d",itype,iface);

    if (proxyarp) clear_proxyarp(inet_addr(rip));

    /* FIXME: should delete routes we added here?
     * We may be bringing a connection "down" that always has an up interface.
     * Question: should we just delete all routes through the interface?
     * That might be the best thing. On the other hand it confuses the
     * whole question of the need for a delroute script.
     */
    if (default_route) {
	sprintf(buf,"%s del default metric %d dev %s%d",PATH_ROUTE,metric,itype,iface);
        system(buf);
    }

    if (debug&DEBUG_VERBOSE)
	syslog(LOG_INFO, "Deleting pointopoint route for %s%d",itype,iface);
    sprintf(buf,"%s del %s metric %d dev %s%d",PATH_ROUTE,rip,metric,itype,iface); 
    res = system(buf);

    if (delroute) {
	/* call delroute <iface> <netmask> <local> <remote> */
        sprintf(buf,"%s %s%d %s %s %s %d",
	    delroute,itype,iface,(netmask)?netmask:"default",lip,rip,metric);
        res = system(buf);
        report_system_result(res,buf);
    }
}
