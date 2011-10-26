/*      $Id: slinke.h,v 5.1 2000/07/13 19:01:41 columbus Exp $      */

/****************************************************************************
 ** slinke.h ****************************************************************
 ****************************************************************************
 *
 * slinke - simple hack to convert Nirvis Systems Device Files to LIRC
 + config files
 *
 * Copyright (C) 2000 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifndef _SLINK_H
#define _SLINK_H

int get_val(char *buffer, ...);
int get_data(char *s,ir_code *data,int *bits);
void strtoupper(char *s);
int append_code(struct ir_remote *r,ir_code code,char *name);
char *trim(char *s);
int fill_struct(struct ir_remote *r,FILE *f,char **desc);
struct ir_remote *read_slinke(char *filename,char **desc);
void get_pre_data(struct ir_remote *remote);
void get_post_data(struct ir_remote *remote);

#endif
