/* csum.c
 * Computes the standard internet checksum of a set of data (from RFC1071)
 *	ChangeLog since sendip 2.0:
 * 02/12/2001: Moved ipv6_csum into icmp.c as that is where it is used
 * 22/01/2002: Include types.h to make sure u_int*_t defined on Solaris
 */

#define __USE_BSD    /* GLIBC */
#define _BSD_SOURCE  /* LIBC5 */
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"

u_int16_t csum (u_int16_t *packet, int packlen);

/* Checksum a block of data */
u_int16_t csum (u_int16_t *packet, int packlen) {
	register unsigned long sum = 0;

	while (packlen > 1) {
		sum+= *(packet++);
		packlen-=2;
	}

	if (packlen > 0)
		sum += *(unsigned char *)packet;

	/* TODO: this depends on byte order */

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (u_int16_t) ~sum;
}
