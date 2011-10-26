/*
 * $Id: chk_fmsg.c,v 1.2 2003/02/07 17:21:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * The purpose of this module is to check the integrity of the message section
 * by comparing its CRC-32 with the stored value.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Checks the integrity of FMSG section. Reports CRC error in case of CRC
   mismatch. */

void check_fmsg(int skip_check)
{
 FMSGP *index_ptr;
 #if SFX_LEVEL>=ARJ
  char fmsg_buf[MSGTEXT_MAX];
 #endif

 crc32term=CRC_MASK;
 #if SFX_LEVEL>=ARJ
 if(skip_check!=CHKMSG_SKIP)
 #else
 if(skip_check==CHKMSG_SKIP)
 #endif
 {
  for(index_ptr=FARMSGS; *index_ptr!=NULL; index_ptr++)
  {
   #ifdef FMSG_ST
    far_strcpyn((char FAR *)fmsg_buf, (char FAR *)*index_ptr, sizeof(fmsg_buf));
    crc32_for_string(fmsg_buf);
   #else
    crc32_for_string(*index_ptr);
   #endif
  }
  if(crc32term!=FARMSGS_CRC32)
   error(M_CRC_ERROR);
 }
 #if SFX_LEVEL<=ARJSFXV
 else
 {
  msg_cprintf(0, strform, M_SFX_USAGE);
  msg_cprintf(0, strform, M_SFX_COMMANDS);
 }
 #endif
}
