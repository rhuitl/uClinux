/*
 * $Id: exe_sear.h,v 1.1.1.1 2002/03/28 00:02:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in EXE_SEAR.C are declared here.
 *
 *
 */

#ifndef EXE_SEAR_INCLUDED
#define EXE_SEAR_INCLUDED

/* Prototypes */

void fetch_sfx();
void fetch_sfxjr();
void fetch_sfxv();
void fetch_sfxstub();

#if SFX_LEVEL<=ARJSFXV
void sfx_seek();
#endif

#endif
