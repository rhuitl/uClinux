/*
 * $Id: arjsec_h.h,v 1.1.1.1 2002/03/28 00:01:19 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ARJSEC_H.C are declared here.
 *
 */

#ifndef ARJSEC_H_INCLUDED
#define ARJSEC_H_INCLUDED

#define ARJSEC_SIG_MAXLEN        80     /* Maximum signature length */

/* Prototypes */

int get_arjsec_signature(FILE *stream, long offset, char *signature, int iter);
int verify_reg_name(char *key1, char *key2, char *name, char *validation);
void create_reg_key(char *key1, char *key2, char *name, char *validation);

#endif
