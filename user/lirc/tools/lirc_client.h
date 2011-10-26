/*      $Id: lirc_client.h,v 5.4 2000/11/09 17:51:00 columbus Exp $      */

/****************************************************************************
 ** lirc_client.h ***********************************************************
 ****************************************************************************
 *
 * lirc_client - common routines for lircd clients
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 
 
#ifndef LIRC_CLIENT_H
#define LIRC_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#define LIRC_ALL ((char *) (-1))

enum lirc_flags {none=0x00,
		 once=0x01,
		 quit=0x02,
		 mode=0x04,
		 ecno=0x08,
		 startup_mode=0x10
};

struct lirc_list
{
	char *string;
	struct lirc_list *next;
};

struct lirc_code
{
	char *remote;
	char *button;
	struct lirc_code *next;
};

struct lirc_config
{
	char *current_mode;
	struct lirc_config_entry *next;
	struct lirc_config_entry *first;
};

struct lirc_config_entry
{
	char *prog;
	struct lirc_code *code;
	unsigned int rep;
	struct lirc_list *config;
	char *change_mode;
	unsigned int flags;
	
	char *mode;
	struct lirc_list *next_config;
	struct lirc_code *next_code;

	struct lirc_config_entry *next;
};

int lirc_init(char *prog,int verbose);
int lirc_deinit(void);

int lirc_readconfig(char *file,struct lirc_config **config,
		    int (check)(char *s));
void lirc_freeconfig(struct lirc_config *config);

/* obsolete */
char *lirc_nextir(void);
/* obsolete */
char *lirc_ir2char(struct lirc_config *config,char *code);

int lirc_nextcode(char **code);
int lirc_code2char(struct lirc_config *config,char *code,char **string);

#ifdef __cplusplus
}
#endif

#endif
