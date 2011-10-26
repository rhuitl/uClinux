/*
 * $Id: decode.c,v 1.3 2003/04/12 16:15:59 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * The data decompression procedures are located in this module.
 *
 */

#include <setjmp.h>

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Delays for errors with garbled files */

#if SFX_LEVEL>=ARJ
 #define BADTABLE_G_DELAY          2
#else
 #define BADTABLE_G_DELAY          5
#endif

/* Local variables */

static jmp_buf decode_proc;             /* Jump buffer for decoding procedure */

#if SFX_LEVEL>=ARJSFXV
unsigned short FAR *c_table;
unsigned short FAR *pt_table;
#else
unsigned short c_table[CTABLESIZE];
unsigned short pt_table[PTABLESIZE];
#endif
short blocksize;
static long count;

/* Fills the input buffer */

void fillbuf(int n)
{
 #ifdef DEBUG
  int bbrc;
 #endif

 while(bitcount<n)
 {
  bitbuf=(bitbuf<<bitcount)|((unsigned int)byte_buf>>(8-bitcount));
  n-=bitcount;
  if(compsize>0)
  {
   compsize--;
   if(file_packing)
   {
    /* This slows the things down quite a lot so we won't put this in the
       release version (despite of what ARJ Software Inc. does in v 3.04!) */
    #ifdef DEBUG
     errno=0;                           /* ASR fix 11/10/2000 -- POSIX/MS C */
     bbrc=fgetc(aistream);
     if(errno!=0)
      msg_cprintf(0, M_DECODE_CRIT_ERROR);
     if(bbrc<0)
      msg_cprintf(0, M_DECODE_EOF);
     byte_buf=(unsigned char)bbrc;
    #else
     byte_buf=(unsigned char)fgetc(aistream);
    #endif
   }
   else                                 /* ASR improvement for RAM-to-RAM */
   {
    byte_buf=*packblock_ptr++;
    packmem_remain--;
   }
   if(file_garbled)
    garble_decode(&byte_buf, 1);
  }
  else
   byte_buf=0;
  bitcount=8;
 }
 bitcount-=n;
 bitbuf=(bitbuf<<n)|(byte_buf>>(8-n));
 byte_buf<<=n;
}

/* Reads a series of bits into the input buffer */

static int getbits(int n)
{
 int rc;

 rc=bitbuf>>(CODE_BIT-n);
 fillbuf(n);
 return(rc);
}

/* Creates a table for decoding */

#if SFX_LEVEL>=ARJSFXV
static void NEAR make_table(int nchar, unsigned char *bitlen, int tablebits, unsigned short FAR *table, int tablesize)
#else
static void NEAR make_table(int nchar, unsigned char *bitlen, int tablebits, unsigned short *table, int tablesize)
#endif
{
 unsigned short count[17], weight[17], start[18];
#if SFX_LEVEL>=ARJSFXV
 unsigned short FAR *p;
#else
 unsigned short *p;
#endif
 unsigned int i, k, len, ch, jutbits, avail, nextcode, mask;

 for(i=1; i<=16; i++)
  count[i]=0;
 for(i=0; (int)i<nchar; i++)
  count[bitlen[i]]++;
 start[1]=0;
 for(i=1; i<=16; i++)
  start[i+1]=start[i]+(count[i]<<(16-i));
 if(start[17]!=(unsigned short)(1<<16))
 {
  if(file_garbled)
  {
   arj_delay(BADTABLE_G_DELAY);
   #if SFX_LEVEL>=ARJSFXV
    msg_cprintf(H_ERR, M_BADTABLE_G);
   #else
    error(M_BADTABLE_G);
   #endif
  }
  else
   #if SFX_LEVEL>=ARJSFXV
    msg_cprintf(H_ERR, M_BADTABLE);
   #else
    error(M_BADTABLE);
   #endif
  #if SFX_LEVEL>=ARJSFXV
   longjmp(decode_proc, 1);
  #endif
 }
 jutbits=16-tablebits;
 for(i=1; (int)i<=tablebits; i++)
 {
  start[i]>>=jutbits;
  weight[i]=1<<(tablebits-i);
 }
 while(i<=16)
 {
  weight[i]=1<<(16-i);
  i++;
 }
 i=start[tablebits+1]>>jutbits;
 if(i!=(unsigned short)(1<<16))
 {
  k=1<<tablebits;
  while(i!=k)
   table[i++]=0;
 }
 avail=nchar;
 mask=1<<(15-tablebits);
 for(ch=0; (int)ch<nchar; ch++)
 {
  if((len=bitlen[ch])!=0)
  {
   k=start[len];
   nextcode=k+weight[len];
   if((int)len<=tablebits)
   {
    if(nextcode>(unsigned int)tablesize)
    {
     if(file_garbled)
     {
      arj_delay(BADTABLE_G_DELAY);
      #if SFX_LEVEL>=ARJSFXV
       msg_cprintf(H_ERR, M_BADTABLE_G);
      #else
       error(M_BADTABLE_G);
      #endif
     }
     else
      #if SFX_LEVEL>=ARJSFXV
       msg_cprintf(H_ERR, M_BADTABLE);
      #else
       error(M_BADTABLE);
      #endif
     longjmp(decode_proc, 1);
    }
    for(i=start[len]; i<nextcode; i++)
    {
     stop_optimizer();                  /* VisualAge C++ v 3.65 fix */
     table[i]=ch;
    }
   }
   else
   {
    p=&table[k>>jutbits];
    i=len-tablebits;
    while(i!=0)
    {
     if(*p==0)
     {
      right[avail]=left[avail]=0;
      *p=avail;
      avail++;
     }
     if(k&mask)
      p=&right[*p];
     else
      p=&left[*p];
     k<<=1;
     i--;
    }
    *p=ch;
   }
   start[len]=nextcode;
  }
 }
}

/* Reads length of data pending */

void read_pt_len(int nn, int nbit, int i_special)
{
 int i, n;
 short c;
 unsigned short mask;

 n=getbits(nbit);
 if(n==0)
 {
  c=(short)getbits(nbit);
  for(i=0; i<nn; i++)
   pt_len[i]=0;
  for(i=0; i<PTABLESIZE; i++)
   pt_table[i]=c;
 }
 else
 {
  i=0;
  /* ASR fix to prevent overrun -- 04/12/1999 */
  if(n>=NPT)                            /* FIX */
   n=NPT;                               /* FIX */
  while(i<n)
  {
   c=bitbuf>>13;
   if(c==7)
   {
    mask=1<<12;
    while(mask&bitbuf)
    {
     mask>>=1;
     c++;
    }
   }
   fillbuf((c<7)?3:(int)(c-3));
   pt_len[i++]=(unsigned char)c;
   if(i==i_special)
   {
    c=getbits(2);
    while(--c>=0)
     pt_len[i++]=0;
   }
  }
  while(i<nn)
   pt_len[i++]=0;
  make_table(nn, pt_len, 8, pt_table, PTABLESIZE);
 }
}

/* Reads a character table */

void read_c_len()
{
 short i, c, n;
 unsigned short mask;

 n=getbits(CBIT);
 if(n==0)
 {
  c=getbits(CBIT);
  for(i=0; i<NC; i++)
   c_len[i]=0;
  for(i=0; i<CTABLESIZE; i++)
   c_table[i]=c;
 }
 else
 {
  i=0;
  while(i<n)
  {
   c=pt_table[bitbuf>>8];
   if(c>=NT)
   {
    mask=1<<7;
    do
    {
     if(bitbuf&mask)
      c=right[c];
     else
      c=left[c];
     mask>>=1;
    } while(c>=NT);
   }
   fillbuf((int)(pt_len[c]));
   if(c<=2)
   {
    if(c==0)
     c=1;
    else if(c==1)
    {
     c=getbits(4);
     c+=3;
    }
    else
    {
     c=getbits(CBIT);
     c+=20;
    }
    while(--c>=0)
     c_len[i++]=0;
   }
   else
    c_len[i++]=(unsigned char)(c-2);
  }
  while(i<NC)
   c_len[i++]=0;
  make_table(NC, c_len, 12, c_table, CTABLESIZE);
 }
}

/* Decodes a single character */

static unsigned short NEAR decode_c()
{
 unsigned short j, mask;

 if(blocksize==0)
 {
  blocksize=getbits(CODE_BIT);
  read_pt_len(NT, TBIT, 3);
  read_c_len();
  read_pt_len(NP, PBIT, -1);
 }
 blocksize--;
 j=c_table[bitbuf>>4];
 if(j>=NC)
 {
  mask=1<<3;
  do
  {
   if(bitbuf&mask)
    j=right[j];
   else
    j=left[j];
   mask>>=1;
  } while(j>=NC);
 }
 fillbuf(c_len[j]);
 return(j);
}

/* Decodes a control character */

static unsigned short NEAR decode_p()
{
 unsigned short j, mask;

 j=pt_table[bitbuf>>8];
 if(j>=NP)
 {
  mask=1<<7;
  do
  {
   if(bitbuf&mask)
    j=right[j];
   else
    j=left[j];
   mask>>=1;
  } while(j>=NP);
 }
 fillbuf(pt_len[j]);
 if(j!=0)
 {
  j--;
  j=(1<<j)+getbits(j);
 }
 return(j);
}

/* Initializes memory for decoding */

static void NEAR decode_start()
{
 blocksize=0;
 #if SFX_LEVEL>=ARJSFXV
  if((c_table=farcalloc((unsigned long)CTABLESIZE, (unsigned long)sizeof(short)))==NULL)
   error(M_OUT_OF_MEMORY);
  if((pt_table=farcalloc((unsigned long)PTABLESIZE, (unsigned long)sizeof(short)))==NULL)
   error(M_OUT_OF_MEMORY);
 #endif
 decode_start_stub();
}

#if SFX_LEVEL>=ARJSFXV

/* Releases memory used for decoding */

static void NEAR decode_end()
{
 farfree(c_table);
 farfree(pt_table);
 decode_end_stub();
}

#endif

/* Decodes the entire file */

void decode(int action)
{
 short i;
 short r;
 short c;
 static short j;

 #if SFX_LEVEL>=ARJSFXV
 if(!setjmp(decode_proc))
 {
 #endif
  #if SFX_LEVEL>=ARJSFXV
   dec_text=malloc_msg(DICSIZ);
  #endif
  decode_start();
  display_indicator(0L);
  count=origsize;
  r=0;
  while(count>0L)
  {
   if((c=decode_c())<=UCHAR_MAX)
   {
    dec_text[r]=(unsigned char)c;
    count--;
    if(++r>=DICSIZ)
    {
     r=0;
     display_indicator(origsize-count);
     if(extraction_stub(dec_text, DICSIZ, action))
      goto termination;
    }
   }
   else
   {
    j=c-(UCHAR_MAX+1-THRESHOLD);
    count-=(unsigned long)j;
    i=r-decode_p()-1;
    if(i<0)
     i+=DICSIZ;
    if(r>i&&r<DICSIZ-MAXMATCH-1)
    {
     while(--j>=0)
      dec_text[r++]=dec_text[i++];
    }
    else
    {
     while(--j>=0)
     {
      dec_text[r]=dec_text[i];
      if(++r>=DICSIZ)
      {
       r=0;
       display_indicator(origsize-count);
       if(extraction_stub(dec_text, DICSIZ, action))
        goto termination;
      }
      if(++i>=DICSIZ)
       i=0;
     }
    }
   }
  }
 #if SFX_LEVEL>=ARJSFXV
 }
 #endif
 if(r>0)
  extraction_stub(dec_text, r, action);
termination:;
 #if SFX_LEVEL>=ARJSFXV
  decode_end();
  free(dec_text);
 #endif
}

#if SFX_LEVEL>=ARJ

/* Backward pointer decoding */

static short decode_ptr()
{
 short c, width, plus, pwr;

 plus=0;
 pwr=1<<9;
 for(width=9; width<13; width++)
 {
  c=getbits(1);
  if(c==0)
   break;
  plus+=pwr;
  pwr<<=1;
 }
 if(width!=0)
  c=getbits(width);
 c+=plus;
 return(c);
}

/* Reference length decoding */

static short decode_len()
{
 short c, width, plus, pwr;

 plus=0;
 pwr=1;
 for(width=0; width<7; width++)
 {
  c=getbits(1);
  if(c==0)
   break;
  plus+=pwr;
  pwr<<=1;
 }
 if(width!=0)
  c=getbits(width);
 c+=plus;
 return(c);
}

/* Decodes the entire file, using method 4 */

void decode_f(int action)
{
 int i;
 int j;
 int c;
 int r;
 static unsigned long ncount;

 if(ntext==NULL)
  ntext=malloc_msg(FDICSIZ);
 decode_start_stub();
 display_indicator(0L);
 ncount=0L;
 r=0;
 while(ncount<origsize)
 {
  c=decode_len();
  if(c==0)
  {
   ncount++;
   ntext[r]=(unsigned char)(bitbuf>>8);
   fillbuf(8);
   if(++r>=FDICSIZ)
   {
    r=0;
    display_indicator(ncount);
    if(extraction_stub(ntext, FDICSIZ, action))
     goto termination;
   }
  }
  else
  {
   j=c-1+THRESHOLD;
   ncount+=(unsigned long)j;
   if((i=r-decode_ptr()-1)<0)
    i+=FDICSIZ;
   while(j-->0)
   {
    ntext[r]=ntext[i];
    if(++r>=FDICSIZ)
    {
     r=0;
     display_indicator(ncount);
     if(extraction_stub(ntext, FDICSIZ, action))
      goto termination;
    }
    if(++i>=FDICSIZ)
     i=0;
   }
  }
 }
 if(r>0)
  extraction_stub(ntext, r, action);
 termination:
 decode_end_stub();
 /* ASR fix - otherwise destroy it in final_cleanup() -- 15/08/2001 */
 #ifdef TILED
  free(ntext);
  ntext=NULL;
 #endif
}

#endif
