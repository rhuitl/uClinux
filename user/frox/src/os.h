
#ifndef OS_H
#define OS_H

#include "config.h"
#include "transdata.h"

/*****************
**linux.c/bsd.c **
******************/
int os_init(void);
int get_orig_dest(int fd, struct sockaddr_in *addr);
int get_local_address(const int fd, struct sockaddr_in *addr);
int bindtodevice(int fd);

#ifdef TRANS_DATA
struct fd_request {
	enum { CONNECT, LISTEN, UNLISTEN, NONE } type;
	struct sockaddr_in local;
	struct sockaddr_in remote;
	int ports[2];
};

int kernel_transdata_setup(void);
int kernel_td_connect(struct fd_request req);
int kernel_td_listen(struct fd_request req);
int kernel_td_unlisten(struct fd_request req);
void kernel_td_flush(void);
#endif
#endif /*OS_H */
