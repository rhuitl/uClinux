/*
 * $Id: gost40.c,v 1.3 2003/04/27 20:54:42 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file  contains  the routines that  provide 40-bit GOST encryption with
 * dependence on previously encrypted data.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Local variables */

static unsigned long default_key[8]={3, 10, 6, 12, 5, 9, 0, 7};
static int last_bytes=0;                /* Number of significant bytes in the
                                           last block */

static unsigned long back_code[2]={0L}; /* Recently encrypted data */
static unsigned long gost40_key[8]={0L};/* Automatically generated key */
#ifdef WORDS_BIGENDIAN
static const int ord[8]={3,2,1,0,7,6,5,4};
#define bf(x) ord[x]
static void adjust_byte_order(char *p,const int len)
{
int l4;

for (l4=len>>2;l4;l4--)
  {
  char tmp,*p1,*p2;

   p1   =  p +1;
   p2   =  p1+1;
   tmp  = *p2;
  *p2++ = *p1;
  *p1-- =  tmp;
   tmp  = *p1;
  *p1   = *p2;
  *p2   =  tmp;
   p    =  p2+1;
  }
}
#else
#define bf(x) (x)
#endif

void codec(void (*fct)(unsigned char*, unsigned char*, int), unsigned char *buf, int len)
{
#ifdef WORDS_BIGENDIAN
if (!(len&7) && !last_bytes) adjust_byte_order(buf,len);
#endif
(*fct)(buf,buf,len);
#ifdef WORDS_BIGENDIAN
if (!(len&7) && !last_bytes) adjust_byte_order(buf,len);
#endif
}

/* GOST encoding/decoding loop */

static void gost40_loop(unsigned long *src, unsigned long *dest, unsigned long *key)
{
 unsigned long mod1, mod2;
 int i;

 mod1=src[0];
 mod2=src[1];
 for(i=0; i<3; i++)
 {
  mod2^=gost_term(mod1+key[0]);
  mod1^=gost_term(mod2+key[1]);
  mod2^=gost_term(mod1+key[2]);
  mod1^=gost_term(mod2+key[3]);
  mod2^=gost_term(mod1+key[4]);
  mod1^=gost_term(mod2+key[5]);
  mod2^=gost_term(mod1+key[6]);
  mod1^=gost_term(mod2+key[7]);
 }
 mod2^=gost_term(mod1+key[7]);
 mod1^=gost_term(mod2+key[6]);
 mod2^=gost_term(mod1+key[5]);
 mod1^=gost_term(mod2+key[4]);
 mod2^=gost_term(mod1+key[3]);
 mod1^=gost_term(mod2+key[2]);
 mod2^=gost_term(mod1+key[1]);
 mod1^=gost_term(mod2+key[0]);
 dest[0]=mod2;
 dest[1]=mod1;
}

/* Encoding sequence */

static void gost40_encode(unsigned char *src, unsigned char *dest, int len)
{
 unsigned long *tmp_sptr;               /* Pointer to source area */
 unsigned long *tmp_dptr;               /* Pointer to target area */
 int remainder;                         /* Number of bytes in the last block */
 unsigned char *bc_offset;              /* Offset within back_code */

 remainder=len%8;
 if(remainder==0&&last_bytes==0)
 {
  tmp_sptr=(unsigned long *)src;
  tmp_dptr=(unsigned long *)dest;
  len>>=3;
  while(len--!=0)
  {
   gost40_loop(back_code, back_code, gost40_key);
   back_code[0]=tmp_dptr[0]=tmp_sptr[0]^back_code[0];
   back_code[1]=tmp_dptr[1]=tmp_sptr[1]^back_code[1];
   tmp_sptr+=2;
   tmp_dptr+=2;
  }
 }
 else
 {
  bc_offset=(unsigned char *)back_code;
  while(len--!=0)
  {
   if(last_bytes==0)
    gost40_loop(back_code, back_code, gost40_key);
   bc_offset[bf(last_bytes)]=*(dest++)=*(src++)^bc_offset[bf(last_bytes)];
   last_bytes++;
   last_bytes%=8;
  }
 }
}

/* Decoding sequence */

static void gost40_decode(unsigned char *src, unsigned char *dest, int len)
{
 unsigned long *tmp_sptr;
 unsigned long *tmp_dptr;
 int remainder;
 unsigned long d_data;                  /* Decoded data collector */
 unsigned char *bc_offset;              /* Offset within back_code */
 unsigned char dec_sym;                 /* Currently processed symbol */

 remainder=len%8;
 if(remainder==0&&last_bytes==0)
 {
  tmp_sptr=(unsigned long *)src;
  tmp_dptr=(unsigned long *)dest;
  len>>=3;
  while(len--!=0)
  {
   gost40_loop(back_code, back_code, gost40_key);
   d_data=tmp_sptr[0];
   tmp_dptr[0]=d_data^back_code[0];
   back_code[0]=d_data;
   d_data=tmp_sptr[1];
   tmp_dptr[1]=d_data^back_code[1];
   back_code[1]=d_data;
   tmp_sptr+=2;
   tmp_dptr+=2;
  }
 }
 else
 {
  bc_offset=(unsigned char *)back_code;
  while(len--!=0)
  {
   if(last_bytes==0)
    gost40_loop(back_code, back_code, gost40_key);
   dec_sym=*(src++);
   *(dest++)=dec_sym^bc_offset[bf(last_bytes)];
   bc_offset[bf(last_bytes++)]=dec_sym;
   last_bytes%=8;
  }
 }
}

/* Creates an unique encoding key from the given seed */

static void gost40_crtkey(unsigned long *seed)
{
 unsigned long tmp_key[8];
 int i;

 memcpy(tmp_key, gost40_key, sizeof(tmp_key));
 gost40_loop(seed, back_code, default_key);
 for(i=0; i<KEYGEN_ITERATIONS; i++)
  gost40_encode((unsigned char *)tmp_key, (unsigned char *)tmp_key, sizeof(tmp_key));
 memcpy(gost40_key, tmp_key, sizeof(gost40_key));
}

/* Initializes the GOST 28147-89 encryption module */

void gost40_init(unsigned char modifier)
{
 char *gp_ptr;                          /* Pointer to garble password */
 char *key_ptr;                         /* Pointer to key field */
 int ckey;                              /* Current key element */
 unsigned long l_modifier[2];           /* Initializer for key creation loop */

 memset(gost40_key, 0, sizeof(gost40_key));
 key_ptr=(char *)gost40_key;
 gp_ptr=garble_password;
 for(ckey=0; ckey<64; ckey++)
 {
  key_ptr[bf(ckey%5)]+=*(gp_ptr++)<<ckey%7;
  if(*gp_ptr=='\0')
   gp_ptr=garble_password;
 }
 l_modifier[0]=garble_ftime;
 l_modifier[1]=(long)(signed char)modifier;
 last_bytes=0;
 calc_gost_pattern();
 gost40_crtkey(l_modifier);
 gost40_loop(l_modifier, back_code, gost40_key);
}

/* Encoding routine for interfacing with ARJ */

void gost40_encode_stub(char *data, int len)
{
 codec(gost40_encode, (unsigned char *)data, len);
}

/* Decoding routine for interfacing with ARJ */

void gost40_decode_stub(char *data, int len)
{
 codec(gost40_decode, (unsigned char *)data, len);
}

