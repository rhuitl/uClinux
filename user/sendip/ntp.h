/* ntp.h
 */
#ifndef _SENDIP_NTP_H
#define _SENDIP_NTP_H

typedef struct {
	u_int32_t intpart;
	u_int32_t fracpart;
} ntp_ts;

/* NTP HEADER
 */
typedef struct {
	/* TODO BYTEORDER!!! */
	u_int8_t leap:2;     
	u_int8_t status:6;  
	u_int8_t type;
	/* END TODO */

	u_int16_t precision;
	u_int32_t error;
	u_int32_t drift;
	union {
		u_int32_t ipaddr;
		char id[4];
	} reference;
	ntp_ts reference_ts;
	ntp_ts originate_ts;
	ntp_ts receive_ts;
	ntp_ts transmit_ts;
} ntp_header;

/* Defines for which parts have been modified
 */
#define NTP_MOD_LEAP      (1)
#define NTP_MOD_STATUS    (1<<1)
#define NTP_MOD_TYPE      (1<<2)
#define NTP_MOD_PRECISION (1<<3)
#define NTP_MOD_ERROR     (1<<4)
#define NTP_MOD_DRIFT     (1<<5)
#define NTP_MOD_REF       (1<<6)
#define NTP_MOD_REFERENCE (1<<7)
#define NTP_MOD_ORIGINATE (1<<8)
#define NTP_MOD_RECEIVE   (1<<9)
#define NTP_MOD_TRANSMIT  (1<<10)

/* Options
 */
sendip_option ntp_opts[] = {
	{"l",1,"NTP Leap Indicator","00 (no warning)"},
	{"s",1,"NTP status","0 (clock operating OK)"},
	{"t",1,"NTP type","0 (unspecified)"},
	{"p",1,"NTP precision","0"},
	{"e",1,"NTP estimated error","0.0"},
	{"d",1,"NTP estimated drift rate","0.0"},
	{"r",1,"NTP reference clock ID (string or IP or number)","0"},
	{"f",1,"NTP reference timestamp","0.0"},
	{"o",1,"NTP originate timestamp","0.0"},
	{"a",1,"NTP arrival (receive) timestamp","0.0"},
	{"x",1,"NTP xmit (transmit) timestamp","0.0"}
};

#endif  /* _SENDIP_NTP_H */
