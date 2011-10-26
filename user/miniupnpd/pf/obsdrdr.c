/* $Id: obsdrdr.c,v 1.1 2007-12-27 05:33:40 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2007 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pfvar.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include "../config.h"
#include "obsdrdr.h"
#include "../upnpglobalvars.h"

/* anchor name */
static const char anchor_name[] = "miniupnpd";

int
clear_redirect_rules(void)
{
	int dev;
	struct pfioc_trans io;
	struct pfioc_trans_e ioe;
	dev = open("/dev/pf", O_RDWR);
	if(dev<0)
	{
		syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
		return -1;
	}
	memset(&ioe, 0, sizeof(ioe));
	io.size = 1;
	io.esize = sizeof(ioe);
	io.array = &ioe;
	ioe.rs_num = PF_RULESET_RDR;
	strlcpy(ioe.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCXBEGIN, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXBEGIN, ...): %m");
		goto error;
	}
	if(ioctl(dev, DIOCXCOMMIT, &io) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCXCOMMIT, ...): %m");
		goto error;
	}
	close(dev);
	return 0;
error:
	close(dev);
	return -1;
}

int
add_redirect_rule2(const char * ifname, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto,
				   const char * desc)
{
	int dev;
	int r;
	struct pfioc_rule pcr;
	struct pfioc_pooladdr pp;
	struct pf_pooladdr *a;
	dev = open("/dev/pf", O_RDWR);
	if(dev<0)
	{
		syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
		return -1;
	}
	r = 0;
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, anchor_name, MAXPATHLEN);

	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCBEGINADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCBEGINADDRS, ...): %m");
		r = -1;
	}
	else
	{
		pcr.pool_ticket = pp.ticket;
		
		pcr.rule.dst.port_op = PF_OP_EQ;
		pcr.rule.dst.port[0] = htons(eport);
		pcr.rule.dst.port[1] = htons(eport);
		pcr.rule.action = PF_RDR;
		pcr.rule.natpass = 1;
		pcr.rule.af = AF_INET;
		strlcpy(pcr.rule.ifname, ifname, IFNAMSIZ);
		pcr.rule.proto = proto;
		pcr.rule.log = logpackets;
#ifdef PFRULE_HAS_RTABLEID
		pcr.rule.rtableid = -1;	/* first appeared in OpenBSD 4.0 */
#endif
		pcr.rule.rpool.proxy_port[0] = iport;
		pcr.rule.rpool.proxy_port[1] = iport;
		TAILQ_INIT(&pcr.rule.rpool.list);
		a = calloc(1, sizeof(struct pf_pooladdr));
		inet_pton(AF_INET, iaddr, &a->addr.v.a.addr.v4.s_addr);
		a->addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
		TAILQ_INSERT_TAIL(&pcr.rule.rpool.list, a, entries);

		memcpy(&pp.addr, a, sizeof(struct pf_pooladdr));
		strlcpy(pcr.rule.label, desc, PF_RULE_LABEL_SIZE);
		if(ioctl(dev, DIOCADDADDR, &pp) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCADDADDR, ...): %m");
			r = -1;
		}
		else
		{
			pcr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
			}
			else
			{
				pcr.action = PF_CHANGE_ADD_TAIL;
				if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_ADD_TAIL: %m");
					r = -1;
				}
			}
		}
		free(a);
	}
	close(dev);
	return r;
}

/* thanks to Seth Mos for this function */
int
add_filter_rule2(const char * ifname, const char * iaddr,
                 unsigned short eport, unsigned short iport,
				 int proto, const char * desc)
{
	int dev;
	int r;
	struct pfioc_rule pcr;
	struct pfioc_pooladdr pp;
	struct pf_pooladdr *a;
	dev = open("/dev/pf", O_RDWR);
	if(dev<0)
	{
		syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
		return -1;
	}
	r = 0;
	memset(&pcr, 0, sizeof(pcr));
	strlcpy(pcr.anchor, anchor_name, MAXPATHLEN);

	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	if(ioctl(dev, DIOCBEGINADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCBEGINADDRS, ...): %m");
		r = -1;
	}
	else
	{
		pcr.pool_ticket = pp.ticket;
		
		pcr.rule.dst.port_op = PF_OP_EQ;
		pcr.rule.dst.port[0] = htons(eport);
		pcr.rule.direction = PF_IN;
		pcr.rule.action = PF_PASS;
		pcr.rule.af = AF_INET;
		strlcpy(pcr.rule.ifname, ifname, IFNAMSIZ);
		pcr.rule.proto = proto;
		pcr.rule.quick = 1;
		pcr.rule.log = logpackets;
#ifdef PFRULE_HAS_RTABLEID
		pcr.rule.rtableid = -1;	/* first appeared in OpenBSD 4.0 */ 
#endif
		pcr.rule.keep_state = 1;
		strlcpy(pcr.rule.label, desc, PF_RULE_LABEL_SIZE);

		pcr.rule.rpool.proxy_port[0] = eport;
		a = calloc(1, sizeof(struct pf_pooladdr));
		inet_pton(AF_INET, iaddr, &a->addr.v.a.addr.v4.s_addr);
		a->addr.v.a.mask.v4.s_addr = htonl(INADDR_NONE);
		memcpy(&pp.addr, a, sizeof(struct pf_pooladdr));
		TAILQ_INIT(&pcr.rule.rpool.list);
		inet_pton(AF_INET, iaddr, &a->addr.v.a.addr.v4.s_addr);
		TAILQ_INSERT_TAIL(&pcr.rule.rpool.list, a, entries);
		
		/* we have any - any port = # keep state label */
		/* we want any - iaddr port = # keep state label */
		/* memcpy(&pcr.rule.dst, a, sizeof(struct pf_pooladdr)); */

		memcpy(&pp.addr, a, sizeof(struct pf_pooladdr));
		strlcpy(pcr.rule.label, desc, PF_RULE_LABEL_SIZE);
		if(ioctl(dev, DIOCADDADDR, &pp) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCADDADDR, ...): %m");
			r = -1;
		}
		else
		{
			pcr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				r = -1;
			}
			else
			{
				pcr.action = PF_CHANGE_ADD_TAIL;
				if(ioctl(dev, DIOCCHANGERULE, &pcr) < 0)
				{
					syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_ADD_TAIL: %m");
					r = -1;
				}
			}
		}
		free(a);
	}
	close(dev);
	return r;
}

/* get_redirect_rule()
 * return value : 0 success (found)
 * -1 = error or rule not found */
int
get_redirect_rule(const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen,
                  u_int64_t * packets, u_int64_t * bytes)
{
	int dev;
	int i, n;
	struct pfioc_rule pr;
	struct pfioc_pooladdr pp;
    dev = open("/dev/pf", O_RDWR);
    if(dev<0)
    {
        syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
        return -1;
    }
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	pr.rule.action = PF_RDR;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		goto error;
	}
	n = pr.nr;
	for(i=0; i<n; i++)
	{
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			goto error;
		}
		if( (eport == ntohs(pr.rule.dst.port[0]))
		  && (eport == ntohs(pr.rule.dst.port[1]))
		  && (pr.rule.proto == proto) )
		{
			*iport = pr.rule.rpool.proxy_port[0];
			if(desc)
				strlcpy(desc, pr.rule.label, desclen);
#ifdef PFRULE_INOUT_COUNTS
			if(packets)
				*packets = pr.rule.packets[0] + pr.rule.packets[1];
			if(bytes)
				*bytes = pr.rule.bytes[0] + pr.rule.bytes[1];
#else
			if(packets)
				*packets = pr.rule.packets;
			if(bytes)
				*bytes = pr.rule.bytes;
#endif
			memset(&pp, 0, sizeof(pp));
			strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
			pp.r_action = PF_RDR;
			pp.r_num = i;
			pp.ticket = pr.ticket;
			if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCGETADDRS, ...): %m");
				goto error;
			}
			if(pp.nr != 1)
			{
				syslog(LOG_NOTICE, "No address associated with pf rule");
				goto error;
			}
			pp.nr = 0;	/* first */
			if(ioctl(dev, DIOCGETADDR, &pp) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCGETADDR, ...): %m");
				goto error;
			}
			inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr,
			          iaddr, iaddrlen);
			close(dev);
			return 0;
		}
	}
error:
	close(dev);
	return -1;
}

int
delete_redirect_rule(const char * ifname, unsigned short eport, int proto)
{
	int dev;
	int i, n;
	struct pfioc_rule pr;
    dev = open("/dev/pf", O_RDWR);
    if(dev<0)
    {
        syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
        return -1;
    }
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	pr.rule.action = PF_RDR;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		goto error;
	}
	n = pr.nr;
	for(i=0; i<n; i++)
	{
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			goto error;
		}
		if( (eport == ntohs(pr.rule.dst.port[0]))
		  && (eport == ntohs(pr.rule.dst.port[1]))
		  && (pr.rule.proto == proto) )
		{
			pr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				goto error;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				goto error;
			}
			close(dev);
			return 0;
		}
	}
error:
	close(dev);
	return -1;
}

int
delete_filter_rule(const char * ifname, unsigned short eport, int proto)
{
	int dev;
	int i, n;
	struct pfioc_rule pr;
    dev = open("/dev/pf", O_RDWR);
    if(dev<0)
    {
        syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
        return -1;
    }
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	pr.rule.action = PF_PASS;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		goto error;
	}
	n = pr.nr;
	for(i=0; i<n; i++)
	{
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			goto error;
		}
		if( (eport == ntohs(pr.rule.dst.port[0]))
		  && (pr.rule.proto == proto) )
		{
			pr.action = PF_CHANGE_GET_TICKET;
        	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
            	syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
				goto error;
			}
			pr.action = PF_CHANGE_REMOVE;
			pr.nr = i;
			if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
			{
				syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
				goto error;
			}
			close(dev);
			return 0;
		}
	}
error:
	close(dev);
	return -1;
}

int
get_redirect_rule_by_index(int index,
                           char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen,
                           u_int64_t * packets, u_int64_t * bytes)
{
	int dev;
	int n;
	struct pfioc_rule pr;
	struct pfioc_pooladdr pp;
	if(index < 0)
		return -1;
    dev = open("/dev/pf", O_RDWR);
    if(dev<0)
    {
        syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
        return -1;
    }
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	pr.rule.action = PF_RDR;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		goto error;
	}
	n = pr.nr;
	if(index >= n)
		goto error;
	pr.nr = index;
	if(ioctl(dev, DIOCGETRULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
		goto error;
	}
	*proto = pr.rule.proto;
	*eport = ntohs(pr.rule.dst.port[0]);
	*iport = pr.rule.rpool.proxy_port[0];
	if(ifname)
		strlcpy(ifname, pr.rule.ifname, IFNAMSIZ);
	if(desc)
		strlcpy(desc, pr.rule.label, desclen);
#ifdef PFRULE_INOUT_COUNTS
	if(packets)
		*packets = pr.rule.packets[0] + pr.rule.packets[1];
	if(bytes)
		*bytes = pr.rule.bytes[0] + pr.rule.bytes[1];
#else
	if(packets)
		*packets = pr.rule.packets;
	if(bytes)
		*bytes = pr.rule.bytes;
#endif
	memset(&pp, 0, sizeof(pp));
	strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
	pp.r_action = PF_RDR;
	pp.r_num = index;
	pp.ticket = pr.ticket;
	if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETADDRS, ...): %m");
		goto error;
	}
	if(pp.nr != 1)
	{
		syslog(LOG_NOTICE, "No address associated with pf rule");
		goto error;
	}
	pp.nr = 0;	/* first */
	if(ioctl(dev, DIOCGETADDR, &pp) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETADDR, ...): %m");
		goto error;
	}
	inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr,
	          iaddr, iaddrlen);
	close(dev);
	return 0;
error:
	close(dev);
	return -1;
}

/* this function is only for testing */
void
list_rules(void)
{
	char buf[32];
	int dev;
	int i, n;
	struct pfioc_rule pr;
	struct pfioc_pooladdr pp;
    dev = open("/dev/pf", O_RDWR);
    if(dev<0)
    {
        perror("open(\"/dev/pf\")");
        syslog(LOG_ERR, "open(\"/dev/pf\"): %m");
        return ;
    }
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
	pr.rule.action = PF_RDR;
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
		perror("DIOCGETRULES");
	printf("ticket = %d, nr = %d\n", pr.ticket, pr.nr);
	n = pr.nr;
	for(i=0; i<n; i++)
	{
		printf("-- rule %d --\n", i);
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
			perror("DIOCGETRULE");
		printf(" %s %d:%d -> %d:%d  proto %d\n",
			pr.rule.ifname,
			(int)ntohs(pr.rule.dst.port[0]),
			(int)ntohs(pr.rule.dst.port[1]),
			(int)pr.rule.rpool.proxy_port[0],
			(int)pr.rule.rpool.proxy_port[1],
			(int)pr.rule.proto);
		printf("  description: \"%s\"\n", pr.rule.label);
		memset(&pp, 0, sizeof(pp));
		strlcpy(pp.anchor, anchor_name, MAXPATHLEN);
		pp.r_action = PF_RDR;
		pp.r_num = i;
		pp.ticket = pr.ticket;
		if(ioctl(dev, DIOCGETADDRS, &pp) < 0)
			perror("DIOCGETADDRS");
		printf("  nb pool addr = %d ticket=%d\n", pp.nr, pp.ticket);
		/*if(ioctl(dev, DIOCGETRULE, &pr) < 0)
			perror("DIOCGETRULE"); */
		pp.nr = 0;	/* first */
		if(ioctl(dev, DIOCGETADDR, &pp) < 0)
			perror("DIOCGETADDR");
		/* addr.v.a.addr.v4.s_addr */
		printf("  %s\n", inet_ntop(AF_INET, &pp.addr.addr.v.a.addr.v4.s_addr, buf, 32));
	}
	close(dev);
}

