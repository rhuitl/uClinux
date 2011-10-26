/* debug.h */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


#define DEBUG		0
#define DEBUG_2	0	/* More debugging information */

#if DEBUG
void print_chaddr(u_int8_t *chaddr, char *title);
#endif

