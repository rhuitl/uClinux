/*
 * $Id: arjsec_h.c,v 1.5 2003/05/07 18:55:51 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * The high-level ARJ-security envelope  verification routine is contained  in
 * this module.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Returns ARJ-security signature and 0 when successful. */

#if SFX_LEVEL>=ARJSFX
int get_arjsec_signature(FILE *stream, long offset, char *signature, int iter)
{
#if SFX_LEVEL<=ARJSFXV&&!defined(COMMERCIAL)
 return(0);
#else
 unsigned char tail[ARJSEC_RECORD_SIZE];
 unsigned long tmp_tail[8];
 unsigned long block[8];                /* CRC accumulation */
 unsigned char *dest;
 int i;
 /* We need to retain the position when processing ARJSFX archives */
 #if SFX_LEVEL<=ARJSFXV
  unsigned long cur_pos;
  int c;
 #endif

 #if SFX_LEVEL<=ARJSFXV
  msg_cprintf(0, M_VERIFYING_ARJSEC);
  cur_pos=ftell(stream);
 #endif
 fseek(stream, offset, SEEK_SET);
 if(fread(tail, 1, sizeof(tail), stream)!=ARJSEC_RECORD_SIZE)
  return(1);
 #if SFX_LEVEL>=ARJ
  fseek(stream, 0L, SEEK_SET);
 #endif
 crc32term=CRC_MASK;
 crc32_for_block(tail, ARJSEC_RECORD_SIZE-4);
 if(crc32term!=mget_dword(&tail[ARJSEC_RECORD_SIZE-4]))
  return(1);
 dest=tail+40;
 for(i=0; i<76; i++)
  *(dest++)^=0x80|tail[8+i%32];
 memcpy(signature, tail+40, 76);
 /* The owner's name is already stored at this point, now just make sure that
    we have the envelope in its original, unmodified form. */
 #if SFX_LEVEL>=ARJ
  dest=tail+40;
  arjsec_newblock(block+4);
  while(*dest!='\0')
   arjsec_crcterm(block+4, *(dest++));
  arjsec_invert(block+4);
  arjsec_read(block, stream, offset);
  #ifdef WORDS_BIGENDIAN  
  for (i=0;i<sizeof(tmp_tail)>>2;i++)
   tmp_tail[i]=mget_dword(tail+8+(i<<2));
  #else
  memcpy(tmp_tail, tail+8, sizeof(tmp_tail));
  #endif
  arjsec_term(block+4, tmp_tail, iter);
  i=0;
  if(tmp_tail[0]!=block[0])
   i++;
  if(tmp_tail[1]!=block[1])
   i++;
  if(tmp_tail[2]!=block[2])
   i++;
  if(tmp_tail[3]!=block[3])
   i++;
  arjsec_invert(block);
  arjsec_xor(block, block+4);
  if(tmp_tail[4]!=block[0])
   i++;
  if(tmp_tail[5]!=block[1])
   i++;
  if(tmp_tail[6]!=block[2])
   i++;
  if(tmp_tail[7]!=block[3])
   i++;
 #else
  #ifdef WORDS_BIGENDIAN  
  for (i=0;i<sizeof(tmp_tail)>>2;i++)
   tmp_tail[i]=mget_dword(tail+8+(i<<2));
  #else
  memcpy(tmp_tail, tail+8, sizeof(tmp_tail));
  #endif
  rewind(stream);
  dest=signature;
  arjsec_newblock(block+4);
  while(*dest!='\0')
   arjsec_crcterm(block+4, *(dest++));
  arjsec_invert(block+4);
  arjsec_newblock(block);
  while(--offset>=0L&&(c=fgetc(stream))!=EOF)
   arjsec_crcterm(block, (char)c);
  arjsec_invert(block);
  arjsec_term(block+4, tmp_tail, iter);
  i=0;
  if(memcmp(tmp_tail, block, 16))
   i++;
  arjsec_invert(block);
  block[0]^=block[4];
  block[1]^=block[5];
  block[2]^=block[6];
  block[3]^=block[7];
  if(memcmp(tmp_tail+4, block, 16))
   i++;
  fseek(stream, cur_pos, SEEK_SET);
  if(i==0)
  {
   msg_cprintf(0, M_VALID_ENVELOPE);
   valid_envelope=1;
  }
 #endif
 return(i);                            /* Number of errors */
#endif
}
#endif

/* Verifies registration information */

#if SFX_LEVEL>=ARJ||defined(REARJ)||defined(ARJUTIL)
int verify_reg_name(char *key1, char *key2, char *name, char *validation)
{
 unsigned long encrypt_pad[8], sec_blk[8];
 int i;
 char c, j;

 #if defined(WORDS_BIGENDIAN)&&!defined(ARJUTIL)
 for (i=0;i<8;i++)
  encrypt_pad[i]=mget_dword(validation+(i<<2));
 #else
 memcpy(encrypt_pad, validation, 32);
 #endif
 arjsec_newblock(sec_blk+4);
 for(i=0; key1[i]!='\0'; i++)
  arjsec_crcterm(sec_blk+4, (unsigned char)toupper(key1[i]));
 arjsec_invert(sec_blk+4);
 arjsec_newblock(sec_blk);
 for(i=0; key2[i]!='\0'; i++)
  arjsec_crcterm(sec_blk, (unsigned char)toupper(key2[i]));
 j='\0';
 for(i=0; name[i]!='\0'; i++)
 {
  c=toupper(name[i]);
  if(c!=' '||j!=' ')
   arjsec_crcterm(sec_blk, c);
  j=c;
 }
 arjsec_invert(sec_blk);
 arjsec_term(sec_blk+4, encrypt_pad, ARJSEC_ITER);
 i=0;
 if(encrypt_pad[0]!=sec_blk[0])
  i++;
 if(encrypt_pad[1]!=sec_blk[1])
  i++;
 if(encrypt_pad[2]!=sec_blk[2])
  i++;
 if(encrypt_pad[3]!=sec_blk[3])
  i++;
 arjsec_invert(sec_blk);
 if((sec_blk[0]^sec_blk[4])!=encrypt_pad[4])
  i++;
 if((sec_blk[1]^sec_blk[5])!=encrypt_pad[5])
  i++;
 if((sec_blk[2]^sec_blk[6])!=encrypt_pad[6])
  i++;
 if((sec_blk[3]^sec_blk[7])!=encrypt_pad[7])
  i++;
 return(i);
}
#endif
