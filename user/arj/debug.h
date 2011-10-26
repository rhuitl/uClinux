/*
 * $Id: debug.h,v 1.1.1.1 2002/03/28 00:02:10 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in DEBUG.C are declared here.
 *
 */

#ifndef DEBUG_INCLUDED
#define DEBUG_INCLUDED

/* Prototypes */

#ifdef DEBUG
int debug_report(char *module, unsigned int line, char sign);
#define debug_assert(f) if(!(f)) debug_report(dbg_cur_file, __LINE__, 'A')
#else
#define debug_assert(f)
#endif

#endif
