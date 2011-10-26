/*----------------------------------------------------------------------------
 * bgp.c   - bgp module for SendIP
 *
 * Copyright (C) David Ball for Project Purple, August 2001
 *----------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "sendip_module.h"


/*
 * Roughly stolen from arpa/nameser.h
 */
#define GETSHORT(ptr) (ntohs(                              \
    ((u_int16_t)((u_int8_t *)(ptr))[0] << 8) |             \
    ((u_int16_t)((u_int8_t *)(ptr))[1])                    \
))

#define GETLONG(ptr) (ntohl(                               \
    ((u_int32_t)((u_int8_t *)(ptr))[0] << 24) |            \
    ((u_int32_t)((u_int8_t *)(ptr))[1] << 16) |            \
    ((u_int32_t)((u_int8_t *)(ptr))[2] << 8)  |            \
    ((u_int32_t)((u_int8_t *)(ptr))[3])                    \
))

#define PUTSHORT(ptr, s) {                                 \
    u_int16_t v = htons((u_int16_t)(s));                   \
    *((u_int8_t *)(ptr)) = v >> 8;                         \
    *(((u_int8_t *)(ptr)) + 1) = v;                        \
}

#define PUTLONG(ptr, l) {                                  \
    u_int32_t v = htonl((u_int32_t)(l));                    \
    *((u_int8_t *)(ptr)) = v >> 24;                        \
    *(((u_int8_t *)(ptr)) + 1) = v >> 16;                  \
    *(((u_int8_t *)(ptr)) + 2) = v >> 8;                   \
    *(((u_int8_t *)(ptr)) + 3) = v;                        \
}


/*
 * Defines for which parts have been modified
 */
const u_int32_t BGP_MOD_LENGTH =   0x00000001;
const u_int32_t BGP_MOD_OPT_LEN =  0x00000002;
const u_int32_t BGP_MOD_WDR_LEN =  0x00000004;
const u_int32_t BGP_MOD_ATTR_LEN = 0x00000008;


/*
 * Parts of BGP messages
 */
typedef enum {
	BGP_HEADER,
	BGP_OPEN,
	BGP_OPEN_OPT,
	BGP_UPDATE_WDR_LEN,
	BGP_UPDATE_WDR,
	BGP_UPDATE_ATTR_LEN,
	BGP_UPDATE_ATTR,
	BGP_UPDATE_NLRI,
	BGP_NOTFN
} bgp_msg_part;


/*
 * Options
 */
sendip_option bgp_opts[] = {
	{ "m", TRUE, "BGP Marker field (format is <hex byte>:<hex byte>:...)", 
	  "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF" },
	{ "l", TRUE, "Packet length", "Correct" },
	{ "t", TRUE, "Message Type (1 OPEN, 2 UPDATE, 3 NOTIFICATION, 4 "
	  "KEEPALIVE",
	  "4 (KEEPALIVE)" },
	{ "o", TRUE, "Open message.  Format is <version>:<AS number>:"
	  "<Hold time>:<BGP Identifier>:<Options length>", 
	  "4:1:90:127.0.0.1:Correct  (Any parameter can be omitted to get "
	  "the default)" },
	{ "oo", TRUE, "Optional OPEN parameter.  Format is <Type>:<Length>:"
	  "<Value>   - value is in hex bytes separated by :s", 
	  "Length may be omitted to get correct value" },
	{ "ul", TRUE, "Withdrawn routes length", "Correct" },
	{ "uw", TRUE, "Withdrawn route.  Format is x.x.x.x/n:<bytes "
	  "for prefix>", 
	  "Bytes field may be omitted to use the correct number" },
	{ "us", TRUE, "Attributes length", "Correct" },
	{ "ua", TRUE, "Attribute.  Format is <flags>:<type>:"
	  "<length length (1 or 2):<length>:<data>", 
	  "The length fields may be omitted to use the correct value" },
	{ "un", TRUE, "NLRI Prefix.  Format is as for -buw", "As for -buw" },
	{ "n", TRUE, "Notification.  Format is <code>:<subcode>:<data>", 
	  "Data may be omitted for no data" },
};

/*
 * Option char
 */
const char bgp_opt_char = 'b';


/*
 * Gaping buffer overrun - make sure this is long enough :)
 */
const u_int32_t  BGP_BUFLEN = 1400;

/*static*/ bgp_msg_part  bgp_prev_part;
/*static*/ u_int8_t     *bgp_len_ptr = NULL;
/*static*/ u_int8_t     *bgp_opt_len_ptr = NULL;
/*static*/ u_int8_t     *bgp_wdr_len_ptr = NULL;
/*static*/ u_int8_t     *bgp_attr_len_ptr = NULL;


sendip_data *initialize (void)
{
	sendip_data *data = NULL;
	u_int8_t    *ptr;
	
	data = malloc(sizeof(sendip_data));
	
	if (data != NULL) {
		memset(data, 0, sizeof(sendip_data));
		data->data = malloc(BGP_BUFLEN);
		if (data->data == NULL) {
			free(data);
			data = NULL;
		}
	}
	
	if (data != NULL) {
		memset(data->data, 0, BGP_BUFLEN);
		ptr = data->data;
		
		memset(data->data, 0xFF, 16);
		ptr += 16;
		bgp_len_ptr = ptr;
		PUTSHORT(ptr, 19);
		ptr += 2;
		*ptr++ = 4;
		
		data->alloc_len = ptr - (u_int8_t *)data->data;
		bgp_prev_part = BGP_HEADER;
	} 
	return (data);
}


static u_int32_t bgp_parse_bytes (u_int8_t   *buf,
                                  char       *arg,
                                  char      **new_arg,
                                  u_int32_t   limit,
                                  int         base,
                                  char        stopc)
{
	u_int8_t *ptr = buf;
	char     *arg_ptr = arg;
	
	while (*arg_ptr != '\0' && *arg_ptr != stopc && limit > 0) {
		*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, base);
		if (*arg_ptr != '\0' && *arg_ptr != stopc) {
			arg_ptr++;
		}
		limit--;
	}
	
	if (new_arg != NULL) {
		*new_arg = arg_ptr;
	}
	
	return (ptr - buf);
}


static u_int32_t bgp_parse_nlri (u_int8_t *buf,
                                 char     *arg)
{
	u_int8_t *ptr = buf;
	char     *arg_ptr = arg;
	char     *new_arg_ptr;
	u_int8_t  bytes;
	
	ptr++;
	(void)bgp_parse_bytes(ptr, arg_ptr, &arg_ptr, 4, 10, '\0');
	*buf = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
	if (*arg_ptr != '\0') {
		arg_ptr++;
	}
	bytes = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
	if (arg_ptr != new_arg_ptr) {
		ptr += bytes;
	} else if (*buf > 0) {
		ptr += ((*buf - 1) >> 3) + 1;
	}

	return (ptr - buf);
}


bool do_opt (char        *optstring,
             char        *optarg,
             sendip_data *pack)
{
	u_int8_t *ptr = (u_int8_t *)pack->data + pack->alloc_len;
	u_int8_t *rem_ptr = NULL;
	char     *arg_ptr = NULL;
	char     *new_arg_ptr = NULL;
	bool	  rc = TRUE;
	bool	  len_mod = FALSE;
	u_int8_t  bytes;

	switch (optstring[1]) {
	case 'm':
		rem_ptr = (u_int8_t *)pack->data;
		(void)bgp_parse_bytes(rem_ptr, optarg, NULL, 16, 16, '\0');
		break;
	case 'l':
		rem_ptr = (u_int8_t *)pack->data + 16;
		PUTSHORT(rem_ptr, (u_int16_t)strtoul(optarg, NULL, 10));
		pack->modified |= BGP_MOD_LENGTH;
		break;
	case 't':
		rem_ptr = (u_int8_t *)pack->data + 18;
		*rem_ptr = (u_int8_t)strtoul(optarg, NULL, 0);
		break;
	case 'o':
		switch (optstring[2]) {
		case '\0':
			if (bgp_prev_part != BGP_HEADER) {
				usage_error("Open message must come immediately "
				            "after header\n");
				rc = FALSE;
			} else {
				arg_ptr = optarg;
				*ptr = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				if (arg_ptr == new_arg_ptr) {
					*ptr = 4;
				}
				ptr++;
				
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				PUTSHORT(ptr, (u_int16_t)strtoul(arg_ptr, &new_arg_ptr, 10));
				if (arg_ptr == new_arg_ptr) {
					PUTSHORT(ptr, 1);
				}
				ptr += 2;
				
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				PUTSHORT(ptr, (u_int16_t)strtoul(arg_ptr, &new_arg_ptr, 10));
				if (arg_ptr == new_arg_ptr) {
					PUTSHORT(ptr, 90);
				}
				ptr += 2;
				
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				(void)bgp_parse_bytes(ptr, arg_ptr, &new_arg_ptr, 4, 10, ':');
				if (arg_ptr == new_arg_ptr) {
					PUTLONG(ptr, 0x7F000001);
				}
				ptr += 4;
				
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				*ptr = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				if (arg_ptr == new_arg_ptr) {
					*ptr = 0;
				} else {
					pack->modified |= BGP_MOD_OPT_LEN;
				}
				bgp_opt_len_ptr = ptr;
				ptr++;
				
				bgp_prev_part = BGP_OPEN;
			}
			break;
		
		case 'o':
			if (bgp_prev_part != BGP_OPEN && 
			    bgp_prev_part != BGP_OPEN_OPT) {
				usage_error("Open options must occur after open "
				            "message\n");
				rc = FALSE;
			} else {
				rem_ptr = ptr;
				arg_ptr = optarg;
				*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				
				*ptr = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				if (arg_ptr == new_arg_ptr) {
					*ptr = 0;
				} else {
					len_mod = TRUE;
				}
				ptr++;
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				
				ptr += bgp_parse_bytes(ptr, arg_ptr, NULL, 0xFF, 16, '\0');
				
				if (!len_mod) {
					*(rem_ptr + 1) = ptr - rem_ptr;
				}
				if (!(pack->modified & BGP_MOD_OPT_LEN)) {
					*bgp_opt_len_ptr += ptr - rem_ptr;
				}
				bgp_prev_part = BGP_OPEN_OPT;
			}
			break;
		
		default:
			fprintf(stderr, "Unrecognised BGP OPEN option: %s\n", 
			        optstring);
			rc = FALSE;
		}
		break;
		
	case 'u':
		switch(optstring[2]) {
		case 'l':
			if (bgp_prev_part != BGP_HEADER) {
				usage_error("Update message must come immediately "
				            "after header\n");
				rc = FALSE;
			} else {
				bgp_wdr_len_ptr = ptr;
				PUTSHORT(ptr, (u_int16_t)strtoul(optarg, NULL, 10));
				ptr += 2;
				pack->modified |= BGP_MOD_WDR_LEN;
				bgp_prev_part = BGP_UPDATE_WDR_LEN;
			}
			break;
		
		case 'w':
			if (bgp_prev_part == BGP_HEADER) {
				bgp_wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				bgp_prev_part = BGP_UPDATE_WDR_LEN;
			}
		
			if (bgp_prev_part != BGP_UPDATE_WDR && 
			    bgp_prev_part != BGP_UPDATE_WDR_LEN) {
				usage_error("Unfeasible routes must occur immediately "
				            "after header or -bul\n");
				rc = FALSE;
			} else {
				rem_ptr = ptr;
				ptr += bgp_parse_nlri(ptr, optarg);
				
				if (!(pack->modified & BGP_MOD_WDR_LEN)) {
					PUTSHORT(bgp_wdr_len_ptr, 
					         GETSHORT(bgp_wdr_len_ptr) + ptr - rem_ptr);
				}
				bgp_prev_part = BGP_UPDATE_WDR;
			}
			break;
			
		case 's':
			if (bgp_prev_part == BGP_HEADER) {
				bgp_wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				bgp_prev_part = BGP_UPDATE_WDR_LEN;
			}
		
			if (bgp_prev_part != BGP_UPDATE_WDR_LEN &&
			    bgp_prev_part != BGP_UPDATE_WDR) {
				usage_error("Path Attributes must come after "
				            "unfeasible routes (if any), "
				            "or after header\n");
				rc = FALSE;
			} else {
				bgp_attr_len_ptr = ptr;
				PUTSHORT(ptr, (u_int16_t)strtoul(optarg, NULL, 10));
				ptr += 2;
				pack->modified |= BGP_MOD_ATTR_LEN;
				bgp_prev_part = BGP_UPDATE_ATTR_LEN;
			}
			break;
			
		case 'a':
			if (bgp_prev_part == BGP_HEADER) {
				bgp_wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				bgp_prev_part = BGP_UPDATE_WDR_LEN;
			}
			
			if (bgp_prev_part == BGP_UPDATE_WDR_LEN || 
			    bgp_prev_part == BGP_UPDATE_WDR) {
				bgp_attr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				bgp_prev_part = BGP_UPDATE_ATTR_LEN;
			}
			
			if (bgp_prev_part != BGP_UPDATE_ATTR_LEN &&
			    bgp_prev_part != BGP_UPDATE_ATTR) {
				usage_error("Path Attributes must come after "
				            "unfeasible routes (if any), "
				            "or after header\n");
				rc = FALSE;
			} else {
				rem_ptr = ptr;
				arg_ptr = optarg;
				
				*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 16);
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				
				*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				
				bytes = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				if (arg_ptr != new_arg_ptr) {
					if (bytes <= 1) {
						bytes = 1;
					} else {
						bytes = 2;
					}
				} else {
					if (*rem_ptr & 0x10) {
						bytes = 2;
					} else {
						bytes = 1;
					}
				}
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}
				
				if (bytes == 1) {
					*ptr++ = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				} else {
					PUTSHORT(ptr, (u_int16_t)strtoul(arg_ptr, &new_arg_ptr, 10));
					ptr += 2;
				}
				if (arg_ptr != new_arg_ptr) {
					len_mod = TRUE;
				}
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}

				if (bytes == 1) {
					ptr += bgp_parse_bytes(ptr, arg_ptr, NULL, 0xFF, 16, '\0');
				} else {
					ptr += bgp_parse_bytes(ptr, arg_ptr, NULL, 0xFFFF, 16, 
					                       '\0');
				}
				
				if (!len_mod) {
					if (bytes == 1) {
						*(rem_ptr + 2) = ptr - rem_ptr - 3;
					} else {
						PUTSHORT(rem_ptr + 2, ptr - rem_ptr - 4);
					}
				}
				
				if (!(pack->modified & BGP_MOD_ATTR_LEN)) {
					PUTSHORT(bgp_attr_len_ptr, 
					         GETSHORT(bgp_attr_len_ptr) + ptr - rem_ptr);
				}
				bgp_prev_part = BGP_UPDATE_ATTR;
			}
			break;
			
		case 'n':
			if (bgp_prev_part == BGP_HEADER) {
				bgp_wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				bgp_prev_part = BGP_UPDATE_WDR_LEN;
			}
			
			if (bgp_prev_part == BGP_UPDATE_WDR_LEN ||
			    bgp_prev_part == BGP_UPDATE_WDR) {
				bgp_attr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				bgp_prev_part = BGP_UPDATE_ATTR_LEN;
			}

			if (bgp_prev_part != BGP_UPDATE_ATTR_LEN &&
			    bgp_prev_part != BGP_UPDATE_ATTR &&
			    bgp_prev_part != BGP_UPDATE_NLRI) {
				usage_error("NLRI must come after Unfeasible routes and "
				            "attributes, if any, or after header\n");
				rc = FALSE;
			} else {
				rem_ptr = ptr;
				ptr += bgp_parse_nlri(ptr, optarg);
				
				bgp_prev_part = BGP_UPDATE_NLRI;
			}
			break;
			
		default:
			fprintf(stderr, "Unrecognised BGP UPDATE option: %s\n", optstring);
			rc = FALSE;
		}
		break;
		
	case 'n':
		if (bgp_prev_part != BGP_HEADER) {
			usage_error("Notification must come immediately after header\n");
			rc = FALSE;
		} else {
			arg_ptr = optarg;
			*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
			if (*arg_ptr != '\0') {
				arg_ptr++;
			}
			
			*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
			if (*arg_ptr != '\0') {
				arg_ptr++;
			}
			
			ptr += bgp_parse_bytes(ptr, arg_ptr, NULL, 0xFFFF, 16, '\0');
			
			bgp_prev_part = BGP_NOTFN;
		}
		break;
		
	default:
		fprintf(stderr, "Unrecognised BGP option: %s", optstring);
		rc = FALSE;
	}
	
	if (rc) {
		pack->alloc_len = ptr - (u_int8_t *)pack->data;
		if (!(pack->modified & BGP_MOD_LENGTH)) {
			PUTSHORT(bgp_len_ptr, pack->alloc_len);
		}
	}
	
	return (rc);
}


bool finalize (char        *hdrs,
               sendip_data *headers[],
               sendip_data *data,
               sendip_data *pack)
{
	if (hdrs[strlen(hdrs) - 1] != 't') {
		usage_error("WARNING: BGP should be carried over TCP\n");
	}
	return TRUE;
}


int num_opts (void)
{
	return (sizeof(bgp_opts)/sizeof(sendip_option));
}


sendip_option *get_opts (void)
{
	return (bgp_opts);
}


char get_optchar (void)
{
	return (bgp_opt_char);
}
