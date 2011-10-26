/* $Id: upnpredirect.c,v 1.2 2008-01-03 03:54:54 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2007 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "config.h"
#include "upnpredirect.h"
#include "upnpglobalvars.h"
#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#endif
#if defined(USE_PF)
#include "pf/obsdrdr.h"
#endif
#if defined(USE_IPF)
#include "ipf/ipfrdr.h"
#endif
#ifdef USE_MINIUPNPDCTL
#include <stdio.h>
#include <unistd.h>
#endif

#ifdef SECURE_COMPUTING
struct redirect_rule *redirect_rule_list;
#endif

/* proto_atoi() 
 * convert the string "UDP" or "TCP" to IPPROTO_UDP and IPPROTO_UDP */
static int
proto_atoi(const char * protocol)
{
	int proto = IPPROTO_TCP;
	if(strcmp(protocol, "UDP") == 0)
		proto = IPPROTO_UDP;
	return proto;
}

/* upnp_redirect() 
 * calls OS/fw dependant implementation of the redirection.
 * protocol should be the string "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 */
int
upnp_redirect
(
	unsigned short eport,
	const char * iaddr,
	unsigned short iport,
	const char * protocol,
	const char * desc
#ifdef SECURE_COMPUTING
	,
	int add_to_rule_list
#endif
)
{
	int proto, r;
	char iaddr_old[32];
	unsigned short iport_old;
	struct in_addr address;
	proto = proto_atoi(protocol);
	if(inet_aton(iaddr, &address) < 0)
	{
		syslog(LOG_ERR, "inet_aton(%s) : %m", iaddr);
		return -1;
	}

	if(!check_upnp_rule_against_permissions(upnppermlist, num_upnpperm,
	                                        eport, address, iport))
	{
		syslog(LOG_INFO, "redirection permission check failed for "
		                 "%hu->%s:%hu %s", eport, iaddr, iport, protocol);
		return -3;
	}
	r = get_redirect_rule(ext_if_name, eport, proto,
	                      iaddr_old, sizeof(iaddr_old), &iport_old, 0, 0, 0, 0);
	if(r == 0)
	{
		/* if existing redirect rule matches redirect request return success
		 * xbox 360 does not keep track of the port it redirects and will
		 * redirect another port when receiving ConflictInMappingEntry */
		if(strcmp(iaddr,iaddr_old)==0 && iport==iport_old)
		{
			syslog(LOG_INFO, "ignoring redirect request as it matches existing redirect");
		}
		else
		{

			syslog(LOG_INFO, "port %hu protocol %s already redirected to %s:%hu",
				eport, protocol, iaddr_old, iport_old);
			return -2;
		}
	}
	else
	{
		syslog(LOG_INFO, "redirecting port %hu to %s:%hu protocol %s for: %s",
			eport, iaddr, iport, protocol, desc);
#ifdef SECURE_COMPUTING
		if 
		( 
			add_to_rule_list 
			&& 
			add_redirect_to_list(eport, iport, (char *)iaddr, (char *)protocol) == -1
		)
		{
			return -1;
		}
#endif	
		return upnp_redirect_internal(eport, iaddr, iport, proto, desc);
#if 0
		if(add_redirect_rule2(ext_if_name, eport, iaddr, iport, proto, desc) < 0)
		{
			return -1;
		}

		syslog(LOG_INFO, "creating pass rule to %s:%hu protocol %s for: %s",
			iaddr, iport, protocol, desc);
		if(add_filter_rule2(ext_if_name, iaddr, eport, iport, proto, desc) < 0)
		{
			/* clean up the redirect rule */
#if !defined(__linux__)
			delete_redirect_rule(ext_if_name, eport, proto);
#endif
			return -1;
		}
#endif
	}

	return 0;
}

int
upnp_redirect_internal(unsigned short eport,
                       const char * iaddr, unsigned short iport,
                       int proto, const char * desc)
{
	/*syslog(LOG_INFO, "redirecting port %hu to %s:%hu protocol %s for: %s",
		eport, iaddr, iport, protocol, desc);			*/
	if(add_redirect_rule2(ext_if_name, eport, iaddr, iport, proto, desc) < 0)
	{
		return -1;
	}

/*	syslog(LOG_INFO, "creating pass rule to %s:%hu protocol %s for: %s",
		iaddr, iport, protocol, desc);*/
	if(add_filter_rule2(ext_if_name, iaddr, eport, iport, proto, desc) < 0)
	{
		/* clean up the redirect rule */
#if !defined(__linux__)
		delete_redirect_rule(ext_if_name, eport, proto);
#endif
		return -1;
	}
	return 0;
}



int
upnp_get_redirection_infos(unsigned short eport, const char * protocol,
                           unsigned short * iport,
                           char * iaddr, int iaddrlen,
                           char * desc, int desclen)
{
	if(desc && (desclen > 0))
		desc[0] = '\0';
	return get_redirect_rule(ext_if_name, eport, proto_atoi(protocol),
	                         iaddr, iaddrlen, iport, desc, desclen, 0, 0);
}

int
upnp_get_redirection_infos_by_index(int index,
                                    unsigned short * eport, char * protocol,
                                    unsigned short * iport, 
                                    char * iaddr, int iaddrlen,
                                    char * desc, int desclen)
{
	/*char ifname[IFNAMSIZ];*/
	int proto = 0;

	if(desc && (desclen > 0))
		desc[0] = '\0';
	if(get_redirect_rule_by_index(index, 0/*ifname*/, eport, iaddr, iaddrlen,
	                              iport, &proto, desc, desclen, 0, 0) < 0)
		return -1;
	else
	{
		if(proto == IPPROTO_TCP)
			memcpy(protocol, "TCP", 4);
		else
			memcpy(protocol, "UDP", 4);
		return 0;
	}
}

int
_upnp_delete_redir(unsigned short eport, int proto)
{
	int r;
#if defined(__linux__)
	r = delete_redirect_and_filter_rules(eport, proto);
#else
	r = delete_redirect_rule(ext_if_name, eport, proto);
	delete_filter_rule(ext_if_name, eport, proto);
#endif
	return r;
}

int
upnp_delete_redirection(unsigned short eport, const char * protocol)
{
	syslog(LOG_INFO, "removing redirect rule port %hu %s", eport, protocol);
	return _upnp_delete_redir(eport, proto_atoi(protocol));
}

/* functions used to remove unused rules */
struct rule_state *
get_upnp_rules_state_list(int max_rules_number_target)
{
	char ifname[IFNAMSIZ];
	int proto;
	unsigned short iport;
	struct rule_state * tmp;
	struct rule_state * list = 0;
	int i = 0;
	tmp = malloc(sizeof(struct rule_state));
	if(!tmp)
		return 0;
	while(get_redirect_rule_by_index(i, ifname, &tmp->eport, 0, 0,
	                              &iport, &proto, 0, 0,
								  &tmp->packets, &tmp->bytes) >= 0)
	{
		tmp->proto = (short)proto;
		/* add tmp to list */
		tmp->next = list;
		list = tmp;
		/* prepare next iteration */
		i++;
		tmp = malloc(sizeof(struct rule_state));
		if(!tmp)
			break;
	}
	free(tmp);
	/* return empty list if not enough redirections */
	if(i<=max_rules_number_target)
		while(list)
		{
			tmp = list;
			list = tmp->next;
			free(tmp);
		}
	/* return list */
	return list;
}

void
remove_unused_rules(struct rule_state * list)
{
	char ifname[IFNAMSIZ];
	unsigned short iport;
	struct rule_state * tmp;
	u_int64_t packets;
	u_int64_t bytes;
	int n = 0;
	while(list)
	{
		/* remove the rule if no traffic has used it */
		if(get_redirect_rule(ifname, list->eport, list->proto,
	                         0, 0, &iport, 0, 0, &packets, &bytes) >= 0)
		{
			if(packets == list->packets && bytes == list->bytes)
			{
				_upnp_delete_redir(list->eport, list->proto);
				n++;
			}
		}
		tmp = list;
		list = tmp->next;
		free(tmp);
	}
	if(n>0)
		syslog(LOG_NOTICE, "removed %d unused rules", n);
}


/* stuff for miniupnpdctl */
#ifdef USE_MINIUPNPDCTL
void
write_ruleset_details(int s)
{
	char ifname[IFNAMSIZ];
	int proto = 0;
	unsigned short eport, iport;
	char desc[64];
	char iaddr[32];
	u_int64_t packets;
	u_int64_t bytes;
	int i = 0;
	char buffer[256];
	int n;
	while(get_redirect_rule_by_index(i, ifname, &eport, iaddr, sizeof(iaddr),
	                                 &iport, &proto, desc, sizeof(desc),
	                                 &packets, &bytes) >= 0)
	{
		n = snprintf(buffer, sizeof(buffer), "%2d %s %s %hu->%s:%hu "
		                                     "'%s' %llu %llu\n",
		             i, ifname, proto==IPPROTO_TCP?"TCP":"UDP",
		             eport, iaddr, iport, desc, packets, bytes);
		write(s, buffer, n);
		i++;
	}
}
#endif

#ifdef SECURE_COMPUTING

/* Add a redirect rule to the in-memory list */
int 
add_redirect_to_list(unsigned short eport, unsigned short iport, char *iaddr, char *protocol)
{
	struct redirect_rule *tmp_rule = NULL;
	
	tmp_rule = malloc(sizeof(struct redirect_rule));

	if (tmp_rule == NULL)
	{
		syslog(LOG_ERR, "Could not allocate redirect rule list entry");
		return -1;
	}
	
	/* Fill in the rule */
	tmp_rule->eport = eport;
	tmp_rule->iport = iport;
	strncpy((char *)&tmp_rule->iaddr, iaddr, IPADDR_MAX_LEN);
	tmp_rule->iaddr[IPADDR_MAX_LEN - 1] = '\0';
	strncpy((char *)&tmp_rule->protocol, protocol, PROTOCOL_MAX_LEN);
	tmp_rule->protocol[PROTOCOL_MAX_LEN -1] = '\0';
	
	/* Insert the rule into the list */
	tmp_rule->next = redirect_rule_list;
	redirect_rule_list = tmp_rule;
	
	return 1;
}

/* Remove a redirect rule from the in-memory list */
int
del_redirect_from_list(unsigned short eport, unsigned short iport, char *iaddr, char *protocol)
{
	struct redirect_rule *tmp_rule = redirect_rule_list;
	struct redirect_rule *prev_tmp_rule = NULL;

	while (tmp_rule != NULL)
	{
		if
		(
			tmp_rule->eport == eport
			&&
			tmp_rule->iport == iport
			&&
			strncmp((char *)&tmp_rule->iaddr, iaddr, IPADDR_MAX_LEN) == 0
			&&
			strncmp((char *)&tmp_rule->protocol, protocol, PROTOCOL_MAX_LEN) == 0
		)
		{
			if (prev_tmp_rule != NULL)
				prev_tmp_rule->next = tmp_rule->next;
			
			free(tmp_rule);
			return 1;
		}
		
		prev_tmp_rule = tmp_rule;
		tmp_rule = tmp_rule->next;
	}

	/* Rule not found */
	syslog(LOG_ERR, "Redirect rule not found in rule list");
	return -1;
}

/* Free all redirect rules from the list */
int
free_redirects()
{
	struct redirect_rule *tmp_rule = NULL;

	while (redirect_rule_list != NULL)
	{
		tmp_rule = redirect_rule_list->next;
		free(redirect_rule_list);
		redirect_rule_list = tmp_rule;
	}

	return 1;
}

/* Reload all of the redirect rules into netfilter/ipf */
int
reload_redirects()
{
	struct redirect_rule *tmp_rule = redirect_rule_list;
	int result = 0;

	while (tmp_rule != NULL)
	{
		result = upnp_redirect
		(
			tmp_rule->eport,
			tmp_rule->iaddr,
			tmp_rule->iport,
			tmp_rule->protocol,
			NULL,
			0
		);

		switch (result)
		{
			case -3:
				/* Permission check failed */
				return -1;
				break;
			case -2:
				/* Already redirected */
				break;
			case -1:
				/* Redirection failed */
				return -1;
				break;
			case 0:
				/* Success */
				break;
			default:
				return -1;
		}
		tmp_rule = tmp_rule->next;
	}

	return 1;
}

#endif