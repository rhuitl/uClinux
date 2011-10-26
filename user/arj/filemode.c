/*
 * $Id: filemode.c,v 1.1.1.1 2002/03/28 00:02:55 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This module contains  nothing more than a set of "r", "rb", "rb+" and other
 * file access modes, to conserve space in DGROUP.
 *
 */

#include "bindings.h"

/* File modes */

#if defined(ARJUTIL)||SFX_LEVEL>=ARJSFXV||defined(REARJ)||defined(REGISTER)
 char m_r[]="r";
#endif
#if defined(ARJUTIL)||SFX_LEVEL>=ARJSFX
 char m_w[]="w";
#endif
#if defined(ARJUTIL)||SFX_LEVEL>=ARJSFX||defined(REARJ)
 char m_rb[]="rb";
#endif
#if defined(ARJUTIL)||SFX_LEVEL>=ARJSFX||defined(REGISTER)||defined(REARJ)
 char m_rbp[]="rb+";
#endif
#if SFX_LEVEL>=ARJSFXV
 char m_rp[]="r+";
#endif
#if SFX_LEVEL>=ARJSFX||defined(REARJ)
 char m_wb[]="wb";
#endif
#if SFX_LEVEL>=ARJ
 char m_wbp[]="wb+";
#endif
#if SFX_LEVEL>=ARJ||defined(REARJ)
 char m_a[]="a";
#endif
#ifdef ARJUTIL
 char m_abp[]="ab+";
#endif

