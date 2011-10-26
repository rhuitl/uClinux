#ifndef MISC_H
#define MISC_H
#include "config.h"

/*****************
**    misc.c    **
******************/
int listen_on_socket(struct sockaddr_in *listen_address, int portrange[2]);
int connect_to_socket(const struct sockaddr_in *to,
		      const struct in_addr *from_addr, int portrange[2]);
int bind_me(int fd, struct sockaddr_in *addr, int portrange[2]);
struct sockaddr_in com2n(int a1, int a2, int a3, int a4, int p1, int p2);
void n2com(struct sockaddr_in address, int *a1, int *a2, int *a3, int *a4,
	   int *p1, int *p2);
struct sockaddr_in extract_address(const sstr * buf);
int rclose(int *fd);
void xfer_log(void);
void write_log(int priority, const char *msg, ...);
sstr *addr2name(struct in_addr address);
int resolve_addr(const struct in_addr *address, sstr * fqdn);
int urlescape(sstr * url, char *extras);
int make_tmpdir(void);
void die(int loglevel, const char *lmessage,
	 int mcode, const char *message, int exitcode);
int append_read(int fd, char *buf);
void sstrerr(void);
int send_fd(int sock_fd, int send_fd, char msg);
char recv_fd(int sock_fd, int *recv_fd);
void set_write_lock(int fd);
int set_read_lock(int fd);
int do_chroot(void);
int droppriv(void);
void kill_procs(void);
int valid_uint16(int);
#ifdef ENABLE_CHANGEPROC
void set_proc_title(char *fmt, ...);
void init_set_proc_title(int argc, char *argv[], char *envp[]);
#endif

#endif /*MISC_H */
