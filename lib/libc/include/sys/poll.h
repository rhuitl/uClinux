#ifndef _SYS_POLL_H_
#define _SYS_POLL_H_ 1

#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */
#define POLLNVAL    0x0020    /* Invalid request: fd not open */

/* Type used for the number of file descriptors.  */
typedef unsigned long int nfds_t;

struct pollfd {
	int		fd;           /* file descriptor */
	short	events;     /* requested events */
	short	revents;    /* returned events */
};

extern int poll(struct pollfd *ufds, nfds_t nfds, int timeout);

#endif /* _SYS_POLL_H_ */
