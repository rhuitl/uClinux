/* icmp.h
 */
#ifndef _SENDIP_ICMP_H
#define _SENDIP_ICMP_H

#define ICMP6_ECHO_REQUEST 128
#define ICMP_ECHO          8

/* ICMP HEADER
 * Copied from glibc 2.2, reproduced here without code specific stuff
 */
typedef struct {
	u_int8_t type;
	u_int8_t code;
	u_int16_t check;
} icmp_header;


/* Defines for which parts have been modified
 */
#define ICMP_MOD_TYPE  1
#define ICMP_MOD_CODE  1<<1
#define ICMP_MOD_CHECK 1<<2

/* Options
 */
sendip_option icmp_opts[] = {
	{"t",1,"ICMP message type","ICMP_ECHO (8), or ICMP6_ECHO_REQUEST (128) if embedded in an IPv6 packet"},
	{"d",1,"ICMP code","0"},
	{"c",1,"ICMP checksum","Correct"}
};

#endif  /* _SENDIP_ICMP_H */
