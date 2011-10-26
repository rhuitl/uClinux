/* config file parser functions
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id: conffile.h 6321 2005-12-14 15:30:03Z /C=DE/ST=Berlin/L=Berlin/O=Netfilter Project/OU=Development/CN=laforge/emailAddress=laforge@netfilter.org $
 * 
 * This code is distributed under the terms of GNU GPL */

#ifndef _CONFFILE_H
#define _CONFFILE_H

#include <sys/types.h>

/* errors returned by config functions */
enum {
	ERRNONE = 0,
	ERROPEN,	/* unable to open config file */
	ERROOM,		/* out of memory */
	ERRMULT,	/* non-multiple option occured more  than once */
	ERRMAND,	/* mandatory option not found */
	ERRUNKN,	/* unknown config key */
	ERRSECTION,	/* section not found */
};

/* maximum line lenght of config file entries */
#define LINE_LEN 		255

/* maximum lenght of config key name */
#define CONFIG_KEY_LEN		30

/* maximum lenght of string config value */
#define CONFIG_VAL_STRING_LEN	225

/* valid config types */
#define CONFIG_TYPE_INT		0x0001
#define CONFIG_TYPE_STRING	0x0002
#define CONFIG_TYPE_CALLBACK	0x0003

/* valid config options */
#define CONFIG_OPT_NONE		0x0000
#define CONFIG_OPT_MANDATORY	0x0001
#define CONFIG_OPT_MULTI	0x0002

struct config_entry {
	char key[CONFIG_KEY_LEN];	/* name of config directive */
	u_int8_t type;			/* type; see above */
	u_int8_t options;		/* options; see above  */
	u_int8_t hit;			/* found? */
	union {
		char string[CONFIG_VAL_STRING_LEN];
		int value;
		int (*parser)(const char *argstr);
	} u;
};

struct config_keyset {
	unsigned int num_ces;
	struct config_entry ces[];
};

/* if an error occurs, config_errce is set to the erroneous ce */
extern struct config_entry *config_errce;

/* tell us the name of the config file */
int config_register_file(const char *file);

/* parse the config file */
int config_parse_file(const char *section, struct config_keyset *kset);

#endif /* ifndef _CONFFILE_H */
