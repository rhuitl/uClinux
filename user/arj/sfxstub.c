/*
 * $Id: sfxstub.c,v 1.2 2003/06/22 11:12:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This is a portable version of the SFX stub.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

static char strform[]="%s";

/* Main routine */

int main()
{
 printf(strform, M_SFXSTUB_BANNER);
 printf(strform, M_SFXSTUB_BLURB_1);
 printf(strform, M_SFXSTUB_BLURB_2);
 return(0);
}
