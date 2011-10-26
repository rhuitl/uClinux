/* debug.c -- DHCP server debug specific functions */

#include "debug.h"
#include <syslog.h>


#if DEBUG
void print_chaddr(u_int8_t *chaddr,char *title) {
        syslog(LOG_INFO,"%s = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                        title,chaddr[0],chaddr[1],chaddr[2],chaddr[4],
                        chaddr[4],chaddr[5],chaddr[6],chaddr[7],
                        chaddr[8],chaddr[9],chaddr[10],chaddr[11],
                        chaddr[12],chaddr[13],chaddr[14],chaddr[15]);
}
#endif

