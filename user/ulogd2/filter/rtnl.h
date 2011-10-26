#ifndef _RTNL_H
#define _RTNL_H

#include <sys/socket.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>

struct rtnl_handler {
	struct rtnl_handler *next;

	u_int16_t	nlmsg_type;
	int		(*handlefn)(struct nlmsghdr *h, void *arg);
	void		*arg;
};


/* api for handler plugins */
int rtnl_handler_register(struct rtnl_handler *hdlr);
int rtnl_handler_unregister(struct rtnl_handler *hdlr);
int rtnl_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
int rtnl_dump_type(unsigned int type);

/* api for core program */
int rtnl_init(void);
void rtnl_fini(void);
int rtnl_receive();
  

#endif
