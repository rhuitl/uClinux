#ifndef _IFTABLE_H
#define _IFTABLE_H

extern char *ifindex_2name(unsigned int index);
extern int iftable_up(unsigned int index);

extern int iftable_init(void);
extern void iftable_fini(void);

extern int iftable_dump(FILE *outfd);
#endif
