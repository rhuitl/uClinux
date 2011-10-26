/* rip.h
 */
#ifndef _SENDIP_RIP_H
#define _SENDIP_RIP_H

/* RIP PACKET STRUCTURES
 */
typedef struct {
	u_int8_t command;
	u_int8_t version;
	u_int16_t res;
	u_int16_t addressFamily;
	u_int16_t routeTagOrAuthenticationType;
} rip_header;

typedef struct {
	u_int32_t address;
	u_int32_t subnetMask;
	u_int32_t nextHop;
	u_int32_t metric;
} rip_options;

/* Defines for which parts have been modified
 */
#define RIP_MOD_COMMAND   1
#define RIP_MOD_VERSION   1<<1
#define RIP_MOD_ADDRFAM   1<<2
#define RIP_MOD_ROUTETAG  1<<3
#define RIP_IS_AUTH       1<<4

/* Options
 */
sendip_option rip_opts[] = {
	{"v",1,"RIP version","2"},
	{"c",1,
	 "RIP command (1=request, 2=response, 3=traceon (obsolete), 4=traceoff (obsolete), 5=poll (undocumented), 6=poll entry (undocumented)","1"},
	{"e",1,"Add a RIP entry.  Format is: Address family:route tag:address:subnet mask:next hop:metric","2:0:0.0.0.0:255.255.255.0:0.0.0.0:16, any option my be left out to use the default"},
	{"a",1,"RIP authenticat packet, argument is the password; do not use any other RIP options on this RIP header",NULL},
	{"d",0,"RIP default request - get router's entire routing table; do not use any other RIP options on this RIP header",NULL}
};

/* Helpful macros */
#define RIP_NUM_ENTRIES(d) (((d)->alloc_len-sizeof(rip_header))/sizeof(rip_options))
#define RIP_ADD_ENTRY(d) { (d)->data = realloc((d)->data,(d)->alloc_len+sizeof(rip_options)); (d)->alloc_len+=sizeof(rip_options); }
#define RIP_OPTION(d) ((rip_options *)((u_int32_t *)((d)->data)+((d)->alloc_len>>2)-(sizeof(rip_options)>>2)))
#endif  /* _SENDIP_RIP_H */
