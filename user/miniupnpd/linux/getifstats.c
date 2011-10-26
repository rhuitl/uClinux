/* $Id: getifstats.c,v 1.1 2007-12-27 05:33:40 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "../getifstats.h"

int
getifstats(const char * ifname, struct ifdata * data)
{
	FILE *f;
	char line[512];
	char * p;
	int i;
	int r = -1;
	data->baudrate = 4200000;
	data->opackets = 0;
	data->ipackets = 0;
	data->obytes = 0;
	data->ibytes = 0;
	f = fopen("/proc/net/dev", "r");
	if(!f)
	{
		syslog(LOG_ERR, "cannot open /proc/net/dev : %m");
		return -1;
	}
	/* discard the two header lines */
	fgets(line, sizeof(line), f);
	fgets(line, sizeof(line), f);
	while(fgets(line, sizeof(line), f))
	{
		p = line;
		while(*p==' ') p++;
		i = 0;
		while(ifname[i] == *p)
		{
			p++; i++;
		}
		/* TODO : how to handle aliases ? */
		if(ifname[i] || *p != ':')
			continue;
		p++;
		while(*p==' ') p++;
		data->ibytes = strtoul(p, &p, 0);
		while(*p==' ') p++;
		data->ipackets = strtoul(p, &p, 0);
		/* skip 6 columns */
		for(i=6; i>0 && *p!='\0'; i--)
		{
			while(*p==' ') p++;
			while(*p!=' ' && *p) p++;
		}
		while(*p==' ') p++;
		data->obytes = strtoul(p, &p, 0);
		while(*p==' ') p++;
		data->opackets = strtoul(p, &p, 0);
		r = 0;
		break;
	}
	fclose(f);
	return r;
}

