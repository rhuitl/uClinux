/* Copyright (c) 2007 by Errata Security */
#ifndef __SEAPER_H
#define __SEAPER_H

struct SeapName;
struct SeapValue;


struct SeapName
{
	char *name;
	struct SeapValue *values;
	struct SeapName *next;
};

struct SeapValue
{
	char *value;
	unsigned length;

	struct SeapName *names;
	struct SeapValue *next;
};

struct TCPRECORD {
	unsigned ip_ver;
	unsigned char ip_src[16];
	unsigned char ip_dst[16];
	unsigned short tcp_src;
	unsigned short tcp_dst;

	union {
		struct {
			unsigned char from[128];
			unsigned char to[128];
			unsigned char subject[128];
			unsigned is_data:1;
			unsigned is_body:1;
		} smtp;
	} app;

};

struct Seaper
{
	int linktype;
	int something_found;
	struct SeapName *records;

	struct TCPRECORD *session;
	struct TCPRECORD sessions[65536];
};

void process_record(struct Seaper *seap, ...);

#define SAMPLE(proto,name,type,data,sizes) process_record(seap, "TEST",REC_SZ,proto,-1,name,type,data,sizes,0)


enum RECORD_FORMAT {
	REC_END,
	REC_SZ,			/* zero-terminated string, length should be -1 */
	REC_PRINTABLE,	/* printable string, length should be length of the string */
	REC_MACADDR,	/* MAC address, length should be 6 */
	REC_UNSIGNED,
	REC_HEX24,
	REC_IPv4,		/* IP address in decimal-dot notation, such as [192.168.10.3] */
	REC_IPv6,
	REC_FRAMESRC,
	REC_FRAMEDST,
	REC_OID,		/* ASN.1 OBJECT IDENTIFIER */
	REC_HEXSTRING,

};

#define RUNSIGNED(name,val) name,REC_UNSIGNED,&val,sizeof(val)
#define RSZ(name,val) name,REC_SZ,val,-1
#define RPRINT(name,val,val_len) name,REC_PRINTABLE,val,val_len

#define JUICE process_record

#endif /*__SEAPER_H*/
