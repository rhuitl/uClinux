/*      $Id: dump_config.h,v 5.1 1999/09/02 20:03:53 columbus Exp $      */

/****************************************************************************
 ** dump_config.h ***********************************************************
 ****************************************************************************
 *
 * dump_config.h - dumps data structures into file
 *
 * Copyright (C) 1998 Pablo d'Angelo <pablo@ag-trek.allgaeu.org>
 *
 */ 

#ifndef  _DUMP_CONFIG_H
#define  _DUMP_CONFIG_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "ir_remote.h"

void fprint_comment(FILE *f,struct ir_remote *rem);
void fprint_flags(FILE *f, int flags);
void fprint_remotes(FILE *f, struct ir_remote *all);
void fprint_remote_head(FILE *f, struct ir_remote *rem);
void fprint_remote_foot(FILE *f, struct ir_remote *rem);
void fprint_remote_signal_head(FILE *f, struct ir_remote *rem);
void fprint_remote_signal_foot(FILE *f, struct ir_remote *rem);
void fprint_remote_signal(FILE *f,struct ir_remote *rem, struct ir_ncode *codes);
void fprint_remote_signals(FILE *f, struct ir_remote *rem);
void fprint_remote(FILE *f, struct ir_remote *rem);

#endif
