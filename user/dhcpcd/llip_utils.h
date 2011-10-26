/*
 * llip_arp.h
 */

#ifndef _LLIP_ARP_H
#define _LLIP_ARP_H

#include <sys/types.h>

/* function prototypes */
int llip_arpCheck(char* device_name, u_long test_addr, unsigned char *source_hw_addr, long timeout);

#endif
