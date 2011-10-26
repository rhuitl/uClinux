#ifndef _PRINTPKT_H
#define _PRINTPKT_H

#define INTR_IDS 	35
extern struct ulogd_key printpkt_keys[INTR_IDS];

int printpkt_print(struct ulogd_key *res, char *buf);

#endif
