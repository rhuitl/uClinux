/*
 * $Id: ea_mgr.h,v 1.1.1.1 2002/03/28 00:02:20 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in EA_MGR.C are declared here.
 *
 *
 */

#ifndef EA_MGR_INCLUDED
#define EA_MGR_INCLUDED

unsigned int get_ea_size(char *name);
unsigned int get_eablk_size(char FAR *blk);
unsigned int get_num_eas(char FAR *blk);
int discard_ea(char *name);
int query_ea(char FAR **dest, char *name, int skip_ln);
int set_ea(char FAR *i_eas, char *name);
int detect_ea(char *name);
int resolve_longname(char *dest, char *name);

#endif

