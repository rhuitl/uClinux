/*
 * $Id: arjsec_l.c,v 1.3 2004/04/17 11:39:42 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Various low-level ARJ-security calculation  routines are  contained in this
 * module.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* This file should not compiled for noncommercial SFXV at all! */

#if defined(COMMERCIAL)||SFX_LEVEL<ARJSFX||SFX_LEVEL>ARJSFXV

/* Seed table */

#if SFX_LEVEL>=ARJ||defined(REARJ)
 #define SHORT_SEED
#endif

#ifdef SHORT_SEED
static unsigned char arjsec_seeds[]={0xDD, 0x90, 0x53, 0x1D,
                                     0x77, 0x59, 0xEF, 0x3D};
#else
static unsigned short arjsec_seeds[]={0xDD0D, 0x4920, 0x5503, 0x614D,
                                      0x6767, 0x6569, 0xDEFF, 0x030D};
#endif

#if SFX_LEVEL>=ARJ

/* Appends an ARJ-SECURITY envelope to the file, returning a nonzero value if
   failed. */

int create_envelope(FILE *stream, unsigned long offset, int iter)
{
 #ifndef COMMERCIAL
  return(1);
 #else
  /* Code removed! */
  return(1);
 #endif
}

#endif

/* Basic processing of the given signature. Separate term variables are used
   so the code will be optimized by placing some of them into GP registers. */

void arjsec_term(unsigned long *block, unsigned long *dest, int iter)
{
 unsigned long block_acc[4];
 unsigned long exchange[16];            /* Intermediate buffer */
 int i;
 unsigned long chksum;                  /* Checksum of block_acc */
 unsigned short term0, term1, term2, term3;

 exchange[0]=dest[0];
 exchange[1]=dest[1];
 exchange[2]=dest[2];
 exchange[3]=dest[3];
 exchange[4]=dest[4];
 exchange[5]=dest[5];
 exchange[6]=dest[6];
 exchange[7]=dest[7];
 exchange[8]=block[0];
 exchange[9]=block[1];
 exchange[10]=block[2];
 exchange[11]=block[3];
 exchange[12]=0x81406215;
 exchange[13]=0x4B435021;
 exchange[14]=0x89ABCDEF;
 exchange[15]=0x08088405;
 block_acc[0]=block[0];
 block_acc[1]=block[1];
 block_acc[2]=block[2];
 block_acc[3]=block[3];
 chksum=block_acc[0]+block_acc[1]+block_acc[2]+block_acc[3];
 for(i=0; i<iter; i++)
 {
  chksum=(chksum<<(32-i%32))|(chksum>>(i%32));
  chksum*=(((unsigned long)i<<1)|1);
  chksum^=block_acc[i%4]>>(unsigned long)((i>>2)%31);
  chksum^=block_acc[(i>>3)&3]<<((i>>5)%31);
  chksum=crc32_for_char(chksum, (unsigned char)(i%256));
  term0=(unsigned short)(chksum>>0)%8;
  term1=(unsigned short)(chksum>>5)%8;
  term2=(unsigned short)(chksum>>11)%16;
  term3=(unsigned short)(chksum>>17)%16;
  #ifdef SHORT_SEED
   term2^=((unsigned short)arjsec_seeds[term0]>>4)%16;
  #else
   term2^=((unsigned short)arjsec_seeds[term0]>>8)%16;
  #endif
  term3^=arjsec_seeds[term1]%16;
  if(term1>=8&&term1<=11)
   term1%=8;
  if(term1==term2)
   term2=((term2+1)%16);
  if(term1==term3)
   term3=((term3+1)%16);
  switch(term0)
  {
   case 0:
    exchange[term1]+=exchange[term2]-exchange[term3];
    break;
   case 1:
    exchange[term1]*=((exchange[term2]^exchange[term3])|1L);
    break;
   case 2:
    exchange[term1]=exchange[term1]<<(term2*2+term3%2)|exchange[term1]>>(32-(term2*2+term3%2));
    break;
   case 3:
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)(exchange[term2]>>0));
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)(exchange[term2]>>8));
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)(exchange[term2]>>16));
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)(exchange[term2]>>24));
    exchange[term1]^=exchange[term3];
    break;
   case 4:
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)((exchange[term2]^exchange[term3])>>0));
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)((exchange[term2]^exchange[term3])>>8));
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)((exchange[term2]^exchange[term3])>>16));
    exchange[term1]=crc32_for_char(exchange[term1], (unsigned char)((exchange[term2]^exchange[term3])>>24));
    break;
   case 5:
    exchange[term1]+=(unsigned long)((term2<<4)+term3);
    break;
   case 6:
    exchange[term1]-=(unsigned long)((term2<<4)+term3);
    break;
   case 7:
    exchange[term1]*=(exchange[term2]*2L+1L);
    exchange[term1]+=exchange[(term2^term3)|8L];
    exchange[term1]*=(exchange[term3]&exchange[term2])|0x1234567;
    break;
  }
 }
 dest[0]=exchange[0];
 dest[1]=exchange[1];
 dest[2]=exchange[2];
 dest[3]=exchange[3];
 dest[4]=exchange[4];
 dest[5]=exchange[5];
 dest[6]=exchange[6];
 dest[7]=exchange[7];
}

#if (SFX_LEVEL>=ARJ)||defined(REARJ)||defined(ARJUTIL)

/* Decodes encrypted ARJ-security data */

void arjsec_xor(unsigned long *dest, unsigned long *src)
{
 dest[0]^=src[0];
 dest[1]^=src[1];
 dest[2]^=src[2];
 dest[3]^=src[3];
}

#endif

/* Prepares a garble block with a special pattern */

void arjsec_newblock(unsigned long *dest)
{
 dest[3]=0xFFFFFFFF;
 dest[0]=0xDB7E936C;
 dest[1]=0x5AD6F7EF;
 dest[2]=0x1951C153;
}

/* Performs a CRC inversion upon the given encrypted block */

void arjsec_invert(unsigned long *block)
{
 unsigned long tmp_block[3];
 int i;

 tmp_block[2]=block[0];
 tmp_block[1]=block[1];
 tmp_block[0]=block[2];
 for(i=0; i<29; i++)
 {
  tmp_block[2]=crc32_for_char(tmp_block[2], (unsigned char)((i<<0)|(tmp_block[1]>>24)));
  tmp_block[2]=crc32_for_char(tmp_block[2], (unsigned char)((i<<1)|(tmp_block[1]>>16)));
  tmp_block[2]=crc32_for_char(tmp_block[2], (unsigned char)((i<<2)|(tmp_block[1]>>8)));
  tmp_block[2]=crc32_for_char(tmp_block[2], (unsigned char)((i<<3)|(tmp_block[1]>>0)));
  tmp_block[1]=crc32_for_char(tmp_block[1], (unsigned char)((i<<0)|(tmp_block[0]>>24)));
  tmp_block[1]=crc32_for_char(tmp_block[1], (unsigned char)((i<<1)|(tmp_block[0]>>16)));
  tmp_block[1]=crc32_for_char(tmp_block[1], (unsigned char)((i<<2)|(tmp_block[0]>>8)));
  tmp_block[1]=crc32_for_char(tmp_block[1], (unsigned char)((i<<3)|(tmp_block[0]>>0)));
  tmp_block[0]=crc32_for_char(tmp_block[0], (unsigned char)((i<<0)|((tmp_block[2]+tmp_block[1])>>24)));
  tmp_block[0]=crc32_for_char(tmp_block[0], (unsigned char)((i<<1)|((tmp_block[2]+tmp_block[1])>>16)));
  tmp_block[0]=crc32_for_char(tmp_block[0], (unsigned char)((i<<2)|((tmp_block[2]+tmp_block[1])>>8)));
  tmp_block[0]=crc32_for_char(tmp_block[0], (unsigned char)((i<<3)|((tmp_block[2]+tmp_block[1])>>0)));
 }
 block[3]^=0xFFFFFFFF;
 block[0]=tmp_block[2];
 block[1]=tmp_block[1];
 block[2]=tmp_block[0];
}

/* Performs CRC rotation in the block, based on the character given */

void arjsec_crcterm(unsigned long *block, unsigned char c)
{
 unsigned short hi, lo, t;

 block[3]=crc32_for_char(block[3], c);
 block[0]=crc32_for_char(block[0]^block[1], (unsigned char)(c^(unsigned char)block[2]));
 block[1]*=((block[0]>>16)<<16)+(unsigned long)((unsigned short)block[0]|((unsigned short)c)<<8|1);
 block[1]++;
 block[2]+=block[0];
 block[2]+=crc32_for_char(block[1], (unsigned char)block[0]);
 hi=(unsigned short)(block[2]>>16);
 lo=(unsigned short)block[2];
 hi=(hi<<(c%16))+(hi>>(16-c%16));
 t=hi&0x8000;
 hi<<=1;
 hi+=lo%2;
 lo=(lo>>1)+t;
 lo=(lo<<(16-c%16))+(lo>>(c%16));
 block[2]=((unsigned long)hi<<16)+(unsigned long)lo;
}

#if SFX_LEVEL>=ARJ

/* Reads an ARJ-security envelope from the file, performing some preliminary
   analysis. */

void arjsec_read(unsigned long *block, FILE *stream, unsigned long len)
{
 unsigned char tmp_block[512];
 unsigned char *tmp_bptr;
 unsigned char c;
 int buf_len;
 int bytes_read;
 unsigned long term, term2;
 unsigned short lo, lo2, hi2, hi, t;

 arjsec_newblock(block);
 while(len>0)
 {
  buf_len=(len>sizeof(tmp_block))?sizeof(tmp_block):len;
  bytes_read=fread(tmp_block, 1, buf_len, stream);
  tmp_bptr=tmp_block;
  if(bytes_read==0)
   break;
  len-=(unsigned long)bytes_read;
  crc32term=block[3];
  crc32_for_block(tmp_block, bytes_read);
  block[3]=crc32term;
  while((--bytes_read)>=0)
  {
   c=*(tmp_bptr++);
   term=block[0]^block[1];
   term=(term>>8)^((unsigned long)get_crc32tab((term%256)^c^(unsigned char)block[2]));
   block[0]=term;
   term2=(((term>>16)<<16)+(((unsigned long)c<<8)+1))|(term%65536L);
   lo=(unsigned short)block[1];
   hi=(unsigned short)(block[1]>>16);
   lo2=(unsigned short)term2;
   hi2=(unsigned short)(term2>>16);
   hi*=lo2;
   hi2=hi2*lo+hi;
   term=((unsigned long)lo*(unsigned long)lo2)+(((unsigned long)hi2)<<16L)+1L;
   block[1]=term;
   block[2]+=block[0];
   term=(term>>8)^get_crc32tab((term%256)^(unsigned char)block[0]);
   term+=block[2];
   hi=(unsigned short)(term>>16);
   lo=(unsigned short)term;
   hi=(hi<<(c%16))+(hi>>(16-c%16));
   t=hi&0x8000;
   hi<<=1;
   hi+=lo%2;
   lo=(lo>>1)+t;
   lo=(lo<<(16-c%16))+(lo>>(c%16));
   block[2]=((unsigned long)hi<<16)+(unsigned long)lo;
  }
 }
 arjsec_invert(block);
}

#endif

#endif /* !COMMERCIAL */
