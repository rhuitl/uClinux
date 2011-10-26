/*
 * $Id: arjcrypt.c,v 1.5 2003/06/22 11:12:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file is a small module that  performs stand-alone strong GOST 28147-89
 * encryption.
 *
 */

#include "arj.h"

#if TARGET==DOS
 #include <dos.h>
 #include "gost_asm.h"
 #include "det_x86.h"
#elif TARGET==OS2
#endif
#include "msg_crp.h"

#include "arjcrypt.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* OS/2 DLL variable */

#if TARGET==OS2&&COMPILER==MSC
 int _acrtused=0;
#endif

/* To identify ourselves, we must have a signature: */

static char id[]="NortheastXXXXXXXX";   /* Currently unused */
#if TARGET==DOS
 static char signature[]=ARJCRYPT_SIG;
 static void entry();
 static unsigned short entry_point=(unsigned short)&entry;
 static int use_32=0;                   /* Allow 32-bit instructions */
#endif

/* Local data */

static unsigned long default_key[8]={3, 10, 6, 12, 5, 9, 0, 7};
static int last_bytes=0;                /* Number of significant bytes in the
					   last block */
static unsigned long back_code[2]={0L}; /* Recently encrypted data */
static unsigned long ext_code[2]={0L};  /* The code used by gost_cipher() */
static unsigned long gost_key[8]={0L};  /* Encryption key */
static unsigned long gost64_key[16]={0L};/* ARJCRYPT v 2.0 encryption key */
static int flags=0;                     /* Encryption type */
static int key64_len=0;                 /* Length of ARJCRYPT v 2 intial
					   encryption password */

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

static void codec(void (*fct)(unsigned char FAR *, unsigned char FAR *, int), unsigned char FAR *buf, int len)
{
if (!(len&7) && !last_bytes) adjust_byte_order(buf,len);
(*fct)(buf,buf,len);
if (!(len&7) && !last_bytes) adjust_byte_order(buf,len);
}
#else

#define bf(x) (x)

#define codec(fct,buf,len) (fct(buf,buf,len))
#endif


/* GOST encoding/decoding loop */

static void gost_loop(unsigned long *src, unsigned long *dest, unsigned long *key)
{
 unsigned long mod1, mod2;
 int i;

 #if TARGET==DOS
  if(use_32)
  {
   gost_loop_32(src, dest, key);
   return;
  }
 #endif
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

/* So-called "gamma"-ciphering that does both encoding and decoding */

static void gost_cipher_proc(unsigned char FAR *src, unsigned char FAR *dest, int len)
{
 unsigned long FAR *tmp_sptr;           /* Pointer to source area */
 unsigned long FAR *tmp_dptr;           /* Pointer to target area */
 int remainder;                         /* Number of bytes in the last block */

 remainder=len%8;
 if(remainder==0&&last_bytes==0)
 {
  tmp_sptr=(unsigned long *)src;
  tmp_dptr=(unsigned long *)dest;
  len>>=3;
  while(len--!=0)
  {
   back_code[0]+=GOST_I_PAT_LO;
   if(back_code[0]<GOST_I_PAT_LO)
    back_code[0]++;
   back_code[1]+=GOST_I_PAT_HI;
   if(back_code[1]<GOST_I_PAT_HI)
    back_code[1]++;
   gost_loop(back_code, ext_code, gost_key);
   tmp_dptr[0]=tmp_sptr[0]^ext_code[0];
   tmp_dptr[1]=tmp_sptr[1]^ext_code[1];
   tmp_sptr+=2;
   tmp_dptr+=2;
  }
 }
 else
 {
  while(len--!=0)
  {
   if(last_bytes==0)
   {
    back_code[0]+=GOST_I_PAT_LO;
    if(back_code[0]<GOST_I_PAT_LO)
     back_code[0]++;
    back_code[1]+=GOST_I_PAT_HI;
    if(back_code[1]<GOST_I_PAT_HI)
     back_code[1]++;
    gost_loop(back_code, ext_code, gost_key);
   }
   *(dest++)=*(src++)^ext_code[bf(last_bytes)];
   last_bytes%=8;
  }
 }
}

/* Encoding sequence */

static void gost_encode(unsigned char FAR *src, unsigned char FAR *dest, int len)
{
 unsigned long FAR *tmp_sptr;           /* Pointer to source area */
 unsigned long FAR *tmp_dptr;           /* Pointer to target area */
 int remainder;                         /* Number of bytes in the last block */
 unsigned char *bc_offset;              /* Offset within back_code */

 remainder=len%8;
 if(remainder==0&&last_bytes==0)
 {
  tmp_sptr=(unsigned long FAR *)src;
  tmp_dptr=(unsigned long FAR *)dest;
  len>>=3;
  while(len--!=0)
  {
   gost_loop(back_code, back_code, gost_key);
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
    gost_loop(back_code, back_code, gost_key);
   bc_offset[bf(last_bytes)]=*(dest++)=*(src++)^bc_offset[bf(last_bytes)];
   last_bytes++;
   last_bytes%=8;
  }
 }
}

/* Decoding sequence */

static void gost_decode(unsigned char FAR *src, unsigned char FAR *dest, int len)
{
 unsigned long FAR *tmp_sptr;           /* Pointer to source area */
 unsigned long FAR *tmp_dptr;           /* Pointer to target area */
 int remainder;                         /* Number of bytes in the last block */
 unsigned long d_data;                  /* Decoded data collector */
 unsigned char *bc_offset;              /* Offset within back_code */
 unsigned char dec_sym;                 /* Currently processed symbol */

 remainder=len%8;
 if(remainder==0&&last_bytes==0)
 {
  tmp_sptr=(unsigned long FAR *)src;
  tmp_dptr=(unsigned long FAR *)dest;
  len>>=3;
  while(len--!=0)
  {
   gost_loop(back_code, back_code, gost_key);
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
    gost_loop(back_code, back_code, gost_key);
   dec_sym=*(src++);
   *(dest++)=dec_sym^bc_offset[bf(last_bytes)];
   bc_offset[bf(last_bytes++)]=dec_sym;
   last_bytes%=8;
  }
 }
}

/* Copies <len> characters of a string, appending a null byte to the result */

static int far_strncpy(char FAR *dest, char FAR *src, int limit)
{
 int k;
 char *d;

 d=dest;
 for(k=0; k<limit; k++)
 {
  if(*src!='\0')
   *(d++)=*(src++);
  else
  {
   *d='\0';
   break;
  }
 }
 #ifdef WORDS_BIGENDIAN
 adjust_byte_order(dest,limit);
 #endif
 return(k);
}

/* Key creation */

static void gost_crtkey(unsigned long *seed)
{
 unsigned long tmp_key[8];
 int i;

 memcpy(tmp_key, gost_key, sizeof(tmp_key));
 gost_loop(seed, back_code, default_key);
 for(i=0; i<KEYGEN_ITERATIONS; i++)
  gost_encode((unsigned char FAR *)tmp_key, (unsigned char FAR *)tmp_key, sizeof(tmp_key));
 if(flags!=ENCRYPT_GOST256&&key64_len>sizeof(gost_key))
 {
  for(i=0; i<8; i++)
   gost_key[i]=gost64_key[i+8];
  for(i=0; i<KEYGEN_ITERATIONS; i++)
   gost_encode((unsigned char FAR *)tmp_key, (unsigned char FAR *)tmp_key, sizeof(tmp_key));
 }
 memcpy(gost_key, tmp_key, sizeof(gost_key));
}

/* Simplified string output routine */

#if TARGET==DOS
static void out_str(char *str)
{
 union REGS r;

 r.h.ah=0x40;
 r.x.bx=1;
 r.x.cx=strlen(str);
 r.x.dx=(unsigned short)str;
 intdos(&r, &r);
}
#endif

/* Main routine - just a stub. Don't even need it in an OS/2 DLL. */

#if TARGET==DOS
int main()
{
 out_str(M_ARJCRYPT_BANNER);
 return(0);
}
#endif

/* External entry */

#if TARGET==DOS
static void entry()
#elif TARGET==OS2
EXPENTRY entry(struct arjcrypt_exblock FAR *exblock_ptr)
#elif TARGET==WIN32
VOID entry(struct arjcrypt_exblock FAR *exblock_ptr)
#else
void entry(struct arjcrypt_exblock FAR *exblock_ptr)
#endif
{
 #if TARGET==DOS
  static unsigned short rcx, rdx;
  struct arjcrypt_exblock FAR *exblock_ptr;
 #endif
 unsigned long modifier[2];

 #if TARGET==DOS
  asm{
   mov word ptr rcx, cx
   mov word ptr rdx, dx
  }
  exblock_ptr=MK_FP(rcx, rdx);
 #endif
 switch(exblock_ptr->mode)
 {
  case ARJCRYPT_INIT:
   #if TARGET==DOS
    use_32=detect_x86()==0x386;
   #endif
   memset(gost_key, 0, sizeof(gost_key));
   far_strncpy((char FAR *)gost_key, exblock_ptr->password, sizeof(gost_key));
   modifier[0]=exblock_ptr->l_modifier[0];
   modifier[1]=exblock_ptr->l_modifier[1];
   flags=ENCRYPT_GOST256;
   last_bytes=0;
   calc_gost_pattern();
   gost_crtkey(modifier);
   gost_loop(modifier, back_code, gost_key);
   exblock_ptr->rc=ARJCRYPT_RC_INITIALIZED;
   break;
  case ARJCRYPT_V2_INIT:
   #if TARGET==DOS
    use_32=detect_x86()==0x386;
   #endif
   memset(gost_key, 0, sizeof(gost_key));
   far_strncpy((char FAR *)gost_key, exblock_ptr->password, sizeof(gost_key));
   memset(gost64_key, 0, sizeof(gost64_key));
   key64_len=far_strncpy((char FAR *)gost64_key, exblock_ptr->password, sizeof(gost64_key));
   modifier[0]=exblock_ptr->l_modifier[0];
   modifier[1]=exblock_ptr->l_modifier[1];
   flags=exblock_ptr->flags;
   last_bytes=0;
   calc_gost_pattern();
   gost_crtkey(modifier);
   gost_loop(modifier, back_code, gost_key);
   exblock_ptr->rc=(flags==ENCRYPT_GOST256||key64_len<=32)?ARJCRYPT_RC_INITIALIZED:ARJCRYPT_RC_INIT_V2;
   break;
  case ARJCRYPT_ENCODE:
   codec(gost_encode, exblock_ptr->data, exblock_ptr->len);
   exblock_ptr->rc=ARJCRYPT_RC_OK;
   break;
  case ARJCRYPT_DECODE:
   codec(gost_decode, exblock_ptr->data, exblock_ptr->len);
   exblock_ptr->rc=ARJCRYPT_RC_OK;
   break;
  case ARJCRYPT_CIPHER:
  case ARJCRYPT_DECIPHER:
   codec(gost_cipher_proc, exblock_ptr->data, exblock_ptr->len);
   exblock_ptr->rc=ARJCRYPT_RC_OK;
   break;
  default:
   exblock_ptr->rc=ARJCRYPT_RC_ERROR;
   break;
 }
 #if TARGET==DOS
  exblock_ptr->ret_addr();
 #endif
}
