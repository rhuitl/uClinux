#define MASQ_MOD_MAIN "masqmod_main"
/* 	$Id: ipmasqadm.h,v 0.6 1998/06/17 19:39:13 jjo Exp jjo $	 */

#include <linux/types.h>
struct sockaddr_in;

extern int masqmod_setsockopt(int fd, const char *modname, int cmd, void *arg, int arglen);
extern int masquser_setsockopt(int fd, int cmd, void *arg, int arglen);

/*
 *	Support miscelaneous functions
 */

extern int parse_addressport(const char * argv[], int argc, struct sockaddr_in *, int nolookup);
extern char * addr_to_name(u_int32_t addr, char *name, int namelen, int nolookup);
extern char * serv_to_name(u_int16_t serv, char *name, int namelen, int nolookup);

extern int masqmod_main(int argc, const char *argv[]);
