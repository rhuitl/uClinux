/* cfg.h  -  Configuration file parser */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef CFG_H
#define CFG_H

typedef enum { cft_strg,cft_flag,cft_link,cft_end } CONFIG_TYPE;

typedef struct {
    CONFIG_TYPE type;
    char *name;
    void *action;
    void *data;
    void *context;
} CONFIG;

#define RAID_EXTRA_BOOT "raid-extra-boot"

extern CONFIG cf_top[],cf_identify[],cf_options[],cf_all[],cf_kernel[],
  cf_image[],cf_other[],cf_disk[],cf_partitions[],cf_partition[],
  cf_map_drive[],cf_change_rules[],cf_change_rule[],cf_change[],
  cf_change_dsc[],cf_bitmap[];

extern FILE *pw_file;


int cfg_open(char *name);

/* Opens the configuration file. Returns the file descriptor of the open
   file. */

void cfg_error(char *msg,...);

/* Signals an error while parsing the configuration file and terminates the
   program. */

void cfg_init(CONFIG *table);

/* Initializes the specified table. */

void cfg_set(CONFIG *table,char *item,char *value,void *context);

/* Sets the specified variable in table. If the variable has already been set
   since the last call to cfg_init, a warning message is issued if the context
   keys don't match or a fatal error is reported if they do. */

void cfg_unset(CONFIG *table,char *item);

/* Unsets the specified variable in table. It is a fatal error if the variable
   was not set. */

int cfg_parse(CONFIG *table);

/* Parses the configuration file for variables contained in table. A non-zero
   value is returned if a variable not found in table has been met. Zero is
   returned if EOF has been reached. */

int cfg_get_flag(CONFIG *table,char *item);

/* Returns one if the specified variable is set, zero if it isn't. */

char *cfg_get_strg(CONFIG *table,char *item);

/* Returns the value of the specified variable if it is set, NULL otherwise. */


FILE *cfg_pw_open(void);
/* open the password file, creating a new file if  passw  is set. */

void cfg_bitmap_only(void);
/* allow only the "bitmap" keywords */

#if BETA_TEST
void cfg_alpha_check(void);
/* check for tables in alphabetical order */
#endif


#endif
