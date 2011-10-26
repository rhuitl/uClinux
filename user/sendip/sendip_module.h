#ifndef _SENDIP_MODULE_H
#define _SENDIP_MODULE_H

#include <stdio.h>   // for fprintf

#include "types.h"

/* Options
 */
typedef struct {
	const char *optname;
	const bool arg;
	const char *description;
	const char *def;
} sendip_option;

/* Data
 */
typedef struct {
	void *data;
	int alloc_len;
	unsigned int modified;
} sendip_data;

/* Prototypes */
#ifndef _SENDIP_MAIN
sendip_data *initialize(void);
bool do_opt(char *optstring, char *optarg, sendip_data *pack);
bool set_addr(char *hostname, sendip_data *pack);
bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack);
int num_opts(void);
sendip_option *get_opts(void);
char get_optchar(void);

#endif  /* _SENDIP_MAIN */

#define usage_error(x) fprintf(stderr,x)

extern u_int16_t csum(u_int16_t *packet, int packlen);
extern int compact_string(char *data_out);

#endif  /* _SENDIP_MODULE_H */
