/*
 * $Id: arj_user.h,v 1.1.1.1 2002/03/28 00:02:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ARJ_USER.C are declared here.
 *
 */

#ifndef ARJ_USER_INCLUDED
#define ARJ_USER_INCLUDED

/* Prototypes */

void arj_user_msg(FMSG *text);
int test_host_os(int os);
char *form_prot_name();
int destfile_extr_validation();
void write_index_entry(char *prefix);
#if SFX_LEVEL>=ARJ
void perform_cmd(int cmd);
#else
void perform_cmd();
#endif

#if SFX_LEVEL<=ARJSFX
void process_archive();
#endif

#endif
