/*
 * $Id: bindings.h,v 1.2 2003/02/07 17:21:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file defines basic constants depending on the given SFX_LEVEL
 *
 */

#ifndef BINDINGS_INCLUDED
#define BINDINGS_INCLUDED

#define C_DEFS_INCLUDED
#include <c_defs.h>

/* If the SFX_LEVEL is not given, default to the lowest one ever possible */

#ifndef SFX_LEVEL
 #ifdef SFL
  #define SFX_LEVEL              SFL
 #else
  #define SFX_LEVEL                0
 #endif
#endif

/* Bindings (SFX_LEVEL grades) */

#define ARJ                        4
#define ARJSFXV                    3
#define ARJSFX                     2
#define ARJSFXJR                   1

#if SFX_LEVEL>=ARJ
 #define FMSG_ST
 #define FARDATA                 FAR
 #define FARCODE                        /* Just indicates the far code model */
 #define EXTR_LEVEL  ARJ_X_SUPPORTED
#else
 #define FARDATA
 #define EXTR_LEVEL        ARJ_X_SFX
#endif

#if defined(USE_COLORS)&&(SFX_LEVEL>=ARJ||defined(REARJ))
 #define COLOR_OUTPUT
#endif

/* Debug information record. */

#ifdef DEBUG
 #define DEBUGHDR(fname) static char dbg_cur_file[]=fname; \
                         static int dbg_dummy;
#else
 #define DEBUGHDR(fname)
#endif

#endif
