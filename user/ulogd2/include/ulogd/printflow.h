#ifndef _PRINTPKT_H
#define _PRINTPKT_H

#define FLOW_IDS 	10
extern struct ulogd_key printflow_keys[FLOW_IDS];

int printflow_print(struct ulogd_key *res, char *buf);

#endif
