/* tcp.h
 */
#ifndef _SENDIP_TCP_H
#define _SENDIP_TCP_H

#ifndef NULL
#define NULL (0L)
#endif

/* TCP HEADER
 * Ripped straight out of glibc-2.2.2, modified for RFC22481
 * Reproduced here to prevent nasty #defines on non-linux boxes
 */
typedef struct {
	u_int16_t source;
	u_int16_t dest;
	u_int32_t seq;
	u_int32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int16_t res:4;
	u_int16_t off:4;
	u_int16_t fin:1;
	u_int16_t syn:1;
	u_int16_t rst:1;
	u_int16_t psh:1;
	u_int16_t ack:1;
	u_int16_t urg:1;
	u_int16_t cwr:1;
	u_int16_t ecn:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int16_t off:4;
	u_int16_t res:4;
	u_int16_t ecn:1;
	u_int16_t cwr:1;
	u_int16_t urg:1;
	u_int16_t ack:1;
	u_int16_t psh:1;
	u_int16_t rst:1;
	u_int16_t syn:1;
	u_int16_t fin:1;
#else
#  error "Adjust your <bits/endian.h> defines"
#endif
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;

} tcp_header;

/* Defines for which parts have been modified
 */
#define TCP_MOD_SOURCE 1
#define TCP_MOD_DEST   1<<1
#define TCP_MOD_SEQ    1<<2
#define TCP_MOD_ACKSEQ 1<<3
#define TCP_MOD_RES    1<<4
#define TCP_MOD_OFF    1<<5
#define TCP_MOD_FIN    1<<6
#define TCP_MOD_SYN    1<<7
#define TCP_MOD_RST    1<<8
#define TCP_MOD_PSH    1<<9
#define TCP_MOD_ACK    1<<10
#define TCP_MOD_URG    1<<11
#define TCP_MOD_ECN    1<<12
#define TCP_MOD_CWR    1<<13
#define TCP_MOD_WINDOW 1<<14
#define TCP_MOD_CHECK  1<<15
#define TCP_MOD_URGPTR 1<<16

/* Options
 */
sendip_option tcp_opts[] = {
	{"s",1,"TCP source port","0"},
	{"d",1,"TCP destination port","0"},
	{"n",1,"TCP sequence number","Random"},
	{"a",1,"TCP ack number","0"},
	{"t",1,"TCP data offset","Correct"},
	{"r",1,"TCP header reserved field EXCLUDING ECN and CWR bits","0"},
	{"fe",1,"TCP ECN bit (rfc2481)","0 (options are 0,1,r)"},
	{"fc",1,"TCP CWR bit (rfc2481)","0 (options are 0,1,r)"},
	{"fu",1,"TCP URG bit","0, or 1 if -tu specified (options are 0,1,r)"},
	{"fa",1,"TCP ACK bit","0, or 1 if -ta specified (options are 0,1,r)"},
	{"fp",1,"TCP PSH bit","0 (options are 0,1,r)"},
	{"fr",1,"TCP RST bit","0 (options are 0,1,r)"},
	{"fs",1,"TCP SYN bit","1 (options are 0,1,r)"},
	{"ff",1,"TCP FIN bit","0 (options are 0,1,r)"},
	{"w",1,"TCP window size","65535"},
	{"c",1,"TCP checksum","Correct"},
	{"u",1,"TCP urgent pointer","0"},
	{"onum",1,"TCP option as string of hex bytes (length is always correct)","(no options)"},
	{"oeol",0,"TCP option: end of list", NULL },
	{"onop",0,"TCP option: no op", NULL },
	{"omss",1,"TCP option: maximum segment size", NULL },
	{"owscale",1,"TCP option: window scale (rfc1323)", NULL },
	{"osackok",0,"TCP option: allow selective ack (rfc2018)", NULL },
	{"osack",1,"TCP option: selective ack (rfc2018), format is l_edge1:r_edge1,l_edge2:r_edge2...", NULL },
	{"ots",1,"TCP option: timestamp (rfc1323), format is tsval:tsecr", NULL }
};

#endif  /* _SENDIP_TCP_H */
