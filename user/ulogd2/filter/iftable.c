/* iftable - table of network interfaces
 *
 * (C) 2004 by Astaro AG, written by Harald Welte <hwelte@astaro.com>
 *
 * This software is Free Software and licensed under GNU GPLv2. 
 *
 */

/* IFINDEX handling */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netdevice.h>

#include "rtnl.h"

#define iftb_log(x, ...)

struct ifindex_map {
	struct ifindex_map *next;

	u_int32_t	index;
	u_int32_t	type;
	u_int32_t	alen;
	u_int32_t	flags;
	char		addr[8];
	char		name[16];
};

static struct ifindex_map *ifindex_map[16];

/* iftable_dump - Dump the interface table to a given file stream
 * @outfd:	file stream to which table should be dumped
 */
int iftable_dump(FILE *outfd)
{
	int i;

	for (i = 0; i < 16; i++) {
		struct ifindex_map *im;
		for (im = ifindex_map[i]; im; im = im->next) {
			fprintf(outfd, "%u %s", im->index, im->name);
			if (!(im->flags & IFF_UP))
				fputs(" DOWN", outfd);
			fputc('\n', outfd);
		}
	}
	fflush(outfd);
	return 0;
}

#ifndef IFLA_RTA
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif
#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

/* iftable_add - Add/Update an entry to/in the interface table
 * @n:		netlink message header of a RTM_NEWLINK message
 * @arg:	not used
 *
 * This function adds/updates an entry in the intrface table.
 * Returns -1 on error, 1 on success.
 */
static int iftable_add(struct nlmsghdr *n, void *arg)
{
	unsigned int hash;
	struct ifinfomsg *ifi_msg = NLMSG_DATA(n);
	struct ifindex_map *im, **imp;
	struct rtattr *cb[IFLA_MAX+1];

	if (n->nlmsg_type != RTM_NEWLINK)
		return -1;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi_msg))) {
		iftb_log(LOG_ERROR, "short message (%u < %u)",
			 n->nlmsg_len, NLMSG_LENGTH(sizeof(ifi_msg)));
		return -1;
	}

	memset(&cb, 0, sizeof(cb));
	rtnl_parse_rtattr(cb, IFLA_MAX, IFLA_RTA(ifi_msg), IFLA_PAYLOAD(n));
	if (!cb[IFLA_IFNAME]) {
		iftb_log(LOG_ERROR, "interface without name?");
		return -1;
	}

	hash = ifi_msg->ifi_index&0xF;
	for (imp = &ifindex_map[hash]; (im=*imp)!=NULL; imp = &im->next) {
		if (im->index == ifi_msg->ifi_index) {
			iftb_log(LOG_DEBUG,
				 "updating iftable (ifindex=%u)", im->index);
			break;
		}
	}

	if (!im) {
		im = malloc(sizeof(*im));
		if (!im) {
			iftb_log(LOG_ERROR,
				 "ENOMEM while allocating ifindex_map");
			return 0;
		}
		im->next = *imp;
		im->index = ifi_msg->ifi_index;
		*imp = im;
		iftb_log(LOG_DEBUG, "creating new iftable (ifindex=%u)",
			 im->index);
	}
	
	im->type = ifi_msg->ifi_type;
	im->flags = ifi_msg->ifi_flags;
	if (cb[IFLA_ADDRESS]) {
		unsigned int alen;
		im->alen = alen = RTA_PAYLOAD(cb[IFLA_ADDRESS]);
		if (alen > sizeof(im->addr))
			alen = sizeof(im->addr);
		memcpy(im->addr, RTA_DATA(cb[IFLA_ADDRESS]), alen);
	} else {
		im->alen = 0;
		memset(im->addr, 0, sizeof(im->addr));
	}
	strcpy(im->name, RTA_DATA(cb[IFLA_IFNAME]));
	return 1;
}

/* iftable_del - Delete an entry from the interface table
 * @n:		netlink message header of a RTM_DELLINK nlmsg
 * @arg:	not used
 *
 * Delete an entry from the interface table.  
 * Returns -1 on error, 0 if no matching entry was found or 1 on success.
 */
static int iftable_del(struct nlmsghdr *n, void *arg)
{
	struct ifinfomsg *ifi_msg = NLMSG_DATA(n);
	struct rtattr *cb[IFLA_MAX+1];
	struct ifindex_map *im;

	if (n->nlmsg_type != RTM_DELLINK) {
		iftb_log(LOG_ERROR,
			 "called with wrong nlmsg_type %u", n->nlmsg_type);
		return -1;
	}

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi_msg))) {
		iftb_log(LOG_ERROR, "short message (%u < %u)",
			 n->nlmsg_len, NLMSG_LENGTH(sizeof(ifi_msg)));
		return -1;
	}

	memset(&cb, 0, sizeof(cb));
	rtnl_parse_rtattr(cb, IFLA_MAX, IFLA_RTA(ifi_msg), IFLA_PAYLOAD(n));

	/* FIXME */

	return 1;
}
	
/* ifindex_2name - get the name for an ifindex
 * @index:	ifindex to be resolved
 *
 * Return value: character string containing name of interface
 */
char *ifindex_2name(unsigned int index)
{
	struct ifindex_map *im;

	if (index == 0)
		return "";
	for (im = ifindex_map[index&0xF]; im; im = im->next)
		if (im->index == index)
			return im->name;

	return NULL;
}

/* iftable_up - Determine whether a given interface is UP
 * @index:	ifindex of interface
 *
 * Return value: -1 if interface unknown, 1 if interface up, 0 if not.
 */
int iftable_up(unsigned int index)
{
	struct ifindex_map *im;

	for (im = ifindex_map[index&0xF]; im; im = im->next) {
		if (im->index == index) {
			if (im->flags & IFF_UP)
				return 1;
			else
				return 0;
		}
	}
	return -1;
}

static struct rtnl_handler handlers[] = {
	{ .nlmsg_type = RTM_NEWLINK, .handlefn = &iftable_add },
	{ .nlmsg_type = RTM_DELLINK, .handlefn = &iftable_del },
};

static int init_or_fini(int fini)
{
	int ret = 0;

	if (fini)
		goto cleanup;

	if (rtnl_handler_register(&handlers[0]) < 0) {
		ret = -1;
		goto cleanup_none;
	}

	if (rtnl_handler_register(&handlers[1]) < 0) {
		ret = -1;
		goto cleanup_0;
	}

	if (rtnl_dump_type(RTM_GETLINK) < 0) {
		ret = -1;
		goto cleanup_1;
	}

	return 0;

#if 0
	if (rtnl_wilddump_requet(rtnl_fd, AF_UNSPEC, RTM_GETLINK) < 0) {
		iftb_log(LOG_ERROR, "unable to send dump request");
		return -1;
	}

#endif

cleanup:

cleanup_1:
	rtnl_handler_unregister(&handlers[1]);
cleanup_0:
	rtnl_handler_unregister(&handlers[0]);
cleanup_none:
	return ret;
}

/* iftable_init - Initialize interface table
 */
int iftable_init(void)
{
	iftb_log(LOG_DEBUG, "%s", __FUNCTION__);
	return init_or_fini(0);
}

/* iftable_fini - Destructor of interface table
 */
void iftable_fini(void)
{
	init_or_fini(1);
}
