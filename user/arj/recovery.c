/*
 * $Id: recovery.c,v 1.5 2003/05/03 22:18:48 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This module contains a set of procedures to create and use special recovery
 * records (XRJ files) introduced with ARJ v 2.55.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

#define DEFAULT_PROTPAD_SIZE    1024    /* Protection data granularity */
#define MAX_BLOCK_SIZE          4096    /* Maximum size of temporary block */
#define DIVISOR_BITS              10    /* Depends on data granularity */
#define PROTBLOCK_HDR_SIZE        14    /* Header of protection block */
#define PROT_SIG_SIZE              6    /* Signature size */

/* Local variables */

static char prot_sig[]="PSigx";         /* Protection block signature */
static char blocks_numstr[]="%3dx ";    /* Number of blocks to process */
static char prot_ticker[]=".";          /* Block counter */
static unsigned long prot_blk_size=0L;  /* Size of std. protection block */

/* Calculates CRC-16 of the given block. The result differs from the one given
   by CCITT V.41 CRC-16. */

static unsigned short crc16_for_block(char *data, int len)
{
 int remain;
 unsigned char *tmp_dptr;
 unsigned short crc16term;

 tmp_dptr=(unsigned char *)data;
 crc16term=0;
 for(remain=len; remain>0; remain--)
 {
  crc16term=crc16tab[crc16term>>8]^((crc16term<<8)|(unsigned short)(*(tmp_dptr++)));
 }
 return(crc16term^0xAAAA);
}

/* Returns number of bytes needed to hold the temporary block */

static int calc_protpad_size(int len)
{
 long tmp_len, divisor;

 tmp_len=(long)len+1;
 while(1)
 {
  divisor=2L;
  while(divisor*divisor<=tmp_len)
  {
   if(tmp_len%divisor==0L)
    break;
   else
    divisor++;
  }
  if(tmp_len%divisor!=0L)
   break;
  tmp_len++;
 }
 return((int)tmp_len);
}

/* Returns the proportion of protection data size to archive size, per mille */

static long calc_protdata_pct(unsigned long protsize, unsigned long archsize)
{
 int dec;

 for(dec=0; dec<3; dec++)
 {
  if(protsize<=0x19999999)
   protsize*=10L;
  else
   archsize/=10L;
 }
 if(archsize==0)
  return(0);
 else
  return(protsize/archsize);
}

/* Relocates the protection data */

static void relocate_protdata(char *dest, char *src, int len)
{
 int i;

 for(i=0; i<len; i++)
  *(dest++)=*(src++);
}

/* Returns the overall size of protection data */

unsigned long calc_protdata_size(unsigned long limit, int threshold)
{
 unsigned int ct;

 if(prot_blk_size==0L)
 {
  prot_blk_size=(DEFAULT_PROTPAD_SIZE-
                 ((unsigned long)
                  (calc_protpad_size(DEFAULT_PROTPAD_SIZE)+
                   4-DEFAULT_PROTPAD_SIZE)*2L+PROTBLOCK_HDR_SIZE))>>1;
  if(prot_blk_size>16384L)
   prot_blk_size=16384L;
 }
 ct=0;
 while(prot_blk_size>MAX_BLOCK_SIZE)
 {
  prot_blk_size>>=1;
  ct++;
 }
 prot_blk_size*=DEFAULT_PROTPAD_SIZE;
 prot_blk_size>>=(DIVISOR_BITS-ct);
 return((((limit>>(DIVISOR_BITS-ct))/prot_blk_size+1L)*
         threshold*DEFAULT_PROTPAD_SIZE)<<2);
}

/* Creates a protection file for the given archive */

int create_protfile(FILE *stream, unsigned long offset, int state)
{
 int protpad_size;
 int pad1_size, pad2_size;
 int block_size;
 char *pad_array[4];
 char *protpad, *protpad_r;
 char *single_pad, *single_pad_r;
 char *protpad_bck;
 unsigned long ifile_size;              /* Input file size */
 unsigned long block_offset;
 int block_divisor;
 int total_blocks;                      /* Total number of MAX_BLOCK_SIZE-byte
                                           blocks in the recovery file. */
 int cur_block;                         /* 0-relative */
 int pad_ctr;
 int section_size;                      /* Number of bytes read */
 unsigned long crc32_tmp;
 long per_mille;
 unsigned long data_offset;

 protpad_size=calc_protpad_size(DEFAULT_PROTPAD_SIZE);
 pad1_size=protpad_size+4-DEFAULT_PROTPAD_SIZE;
 pad2_size=(pad1_size<<1)+PROTBLOCK_HDR_SIZE;
 block_size=(DEFAULT_PROTPAD_SIZE-pad2_size)>>1;
 #ifndef __32BIT__
  if(block_size>MAX_BLOCK_SIZE)
   block_size=MAX_BLOCK_SIZE;
 #else
  if(block_size>16384)
   block_size=16384;
 #endif
 protpad=malloc_msg(protpad_size+2);
 protpad_r=malloc_msg(protpad_size+2);
 single_pad=malloc_msg(DEFAULT_PROTPAD_SIZE+2);
 single_pad_r=malloc_msg(DEFAULT_PROTPAD_SIZE+2);
 protpad_bck=malloc_msg(protpad_size+2);
 pad_array[0]=single_pad;
 pad_array[1]=protpad;
 pad_array[2]=protpad_r;
 pad_array[3]=single_pad_r;
 fseek(stream, 0L, SEEK_END);
 ifile_size=ftell(stream);
 fseek(stream, 0L, SEEK_END);
 file_write(prot_sig, 1, PROT_SIG_SIZE, stream);
 fseek(stream, 0L, SEEK_END);
 data_offset=ftell(stream);
 block_offset=(unsigned long)block_size;
 for(block_divisor=0; block_offset>MAX_BLOCK_SIZE; block_divisor++)
  block_offset>>=1;
 block_offset*=(unsigned long)DEFAULT_PROTPAD_SIZE;
 block_offset>>=(DIVISOR_BITS-block_divisor);
 total_blocks=((ifile_size>>(DIVISOR_BITS-block_divisor))/block_offset+1);
 total_blocks=state?offset:offset*total_blocks;
 msg_cprintf(0, M_WORKING);
 msg_cprintf(0, (FMSG *)blocks_numstr, total_blocks);
 for(cur_block=0; cur_block<total_blocks; cur_block++)
 {
  msg_cprintf(0, (FMSG *)prot_ticker);
  for(pad_ctr=0; pad_ctr<protpad_size; pad_ctr++)
   protpad_r[pad_ctr]=protpad[pad_ctr]='\0';
  for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE; pad_ctr++)
   single_pad_r[pad_ctr]=single_pad[pad_ctr]='\0';
  block_divisor=0;
  block_offset=(unsigned long)cur_block*(unsigned long)DEFAULT_PROTPAD_SIZE;
  while(block_offset<ifile_size)
  {
   fseek(stream, block_offset, SEEK_SET);
   section_size=min(DEFAULT_PROTPAD_SIZE, (ifile_size-block_offset));
   section_size=fread(protpad_bck+1, 1, section_size, stream);
   protpad_bck[0]='\0';
   for(pad_ctr=section_size+1; pad_ctr<protpad_size; pad_ctr++)
    protpad_bck[pad_ctr]='\0';
   for(pad_ctr=0; pad_ctr<protpad_size; pad_ctr++)
   {
    protpad[pad_ctr]^=protpad_bck[pad_ctr];
    protpad_r[pad_ctr]^=protpad_bck[(pad_ctr+block_divisor)%protpad_size];
   }
   crc32term=(unsigned long)
             crc16_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
   crc32_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
   crc32_tmp=crc32term;
   pad_ctr=(pad1_size<<1)+((block_divisor<<2)>>1)+DIVISOR_BITS;
   if(pad_ctr+1>=DEFAULT_PROTPAD_SIZE)
    error(M_PROTECT_BUG);
   mput_word(crc32_tmp,     &single_pad  [pad_ctr]);
   mput_word(crc32_tmp>>16, &single_pad_r[pad_ctr]);
   block_offset+=(unsigned long)total_blocks*
                 (unsigned long)DEFAULT_PROTPAD_SIZE;
   block_divisor++;
  }
  for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
  {
   section_size=protpad_size-pad1_size;
   single_pad_r[pad_ctr+10]=single_pad[pad_ctr+10]=
                              protpad[section_size+pad_ctr];
   single_pad_r[pad_ctr+pad1_size+10]=single_pad[pad_ctr+pad1_size+10]=
                                        protpad_r[section_size+pad_ctr];
  }
  mput_word  ( 0x1111,               &single_pad  [0]);
  mput_word  ( 0x1111,               &single_pad_r[0]);
  mput_word  ( total_blocks,         &single_pad  [2]);
  mput_word  ( total_blocks,         &single_pad_r[2]);
  mput_word  ( DEFAULT_PROTPAD_SIZE, &single_pad  [4]);
  mput_word  ( DEFAULT_PROTPAD_SIZE, &single_pad_r[4]);
  mput_dword ( ifile_size,           &single_pad  [6]);
  mput_dword ( ifile_size,           &single_pad_r[6]);
  for(block_divisor=0; block_divisor<4; block_divisor++)
  {
   relocate_protdata(protpad_bck+4, pad_array[block_divisor],
                     DEFAULT_PROTPAD_SIZE-4);
   crc32term=CRC_MASK;
   crc32_for_block(protpad_bck+4, DEFAULT_PROTPAD_SIZE-4);
   mput_dword(crc32term, protpad_bck);
   fseek(stream, (unsigned long)DEFAULT_PROTPAD_SIZE*
         (unsigned long)cur_block+(unsigned long)block_divisor*
         (unsigned long)total_blocks*(unsigned long)DEFAULT_PROTPAD_SIZE+
         data_offset, SEEK_SET);
   file_write(protpad_bck, 1, DEFAULT_PROTPAD_SIZE, stream);
  }
 }
 fseek(stream, 0L, SEEK_END);
 block_offset=ftell(stream)-data_offset;
 per_mille=calc_protdata_pct(block_offset, ifile_size);
 nputlf();
 msg_cprintf(0, M_PROT_RATIO, block_offset, per_mille/10L, (int)(per_mille%10L));
 free(protpad);
 free(protpad_r);
 free(single_pad);
 free(single_pad_r);
 free(protpad_bck);
 return(0);
}

/* Aborts the recovery process, saying "too much damage" */

static void abort_recovery()
{
 error(M_RECOVERY_ABORTED);
}

/* Checks for a protection signature */

unsigned long chk_prot_sig(FILE *stream, unsigned long rp_ofs)
{
 unsigned long sig_offset=0L;
 unsigned long fsize;
 char c;
 char pad[10];

 fseek(stream, 0L, SEEK_END);
 fsize=ftell(stream);
 while(rp_ofs<fsize)
 {
  fseek(stream, rp_ofs, SEEK_SET);
  c=fgetc(stream);
  while(rp_ofs<fsize)
  {
   if(c!=prot_sig[0])
    c=fgetc(stream);
   else
   {
    c=fgetc(stream);
    if(c==prot_sig[1])
     break;
   }
   rp_ofs++;
  }
  if(rp_ofs>=fsize)
   break;
  if(fread(pad, 1, PROT_SIG_SIZE-2, stream)!=PROT_SIG_SIZE-2)
   break;
  if(!strcmp(prot_sig+2, pad))
  {
   sig_offset=ftell(stream);
   if(rp_ofs!=0)
    break;
  }
  rp_ofs++;
 }
 return(sig_offset);
}

/* Verifies and/or repairs a damaged archive */

int recover_file(char *name, char *protname, char *rec_name, int test_mode,
                 unsigned long sig_offset)
{
 unsigned int cur_stream;
 unsigned int cur_section;
 unsigned long block_offset;
 unsigned long ifile_size;
 unsigned long orig_ifile_size;         /* Size of undamaged input file
                                           (stored in the protection file) */
 unsigned long dest_file_size;          /* Size of output file (number of bytes
                                           to write) */
 int errors;                            /* Total number of damaged sections */
 int protpad_size;
 int pad1_size;
 int section_size;                      /* Number of bytes read */
 int total_blocks;
 int data_damage;                       /* Data damage flag */
 int damage_level;                      /* 0, 1 or 2 (highest) */
 int damage_flag, pad_damage_flag;
 int pad_flag, bck_pad_flag;            /* Section damage flag */
 int rec_size=0, bck_rec_size=0;        /* Recovered sections size */
 char *protpad, *protpad_r;
 char *single_pad, *single_pad_r;
 char *protpad_bck;
 FILE *astream, *xstream;               /* ARJ and XRJ files */
 FILE *ostream;                         /* Destination file */
 int pad_ctr;
 unsigned long rd_offset;               /* Offset of recovery data within
                                           xstream */
 int ins_lf=0;

 errors=0;
 protpad_size=calc_protpad_size(DEFAULT_PROTPAD_SIZE); /* -> EBX */
 pad1_size=protpad_size+4-DEFAULT_PROTPAD_SIZE;
 protpad=malloc_msg(protpad_size+2);
 protpad_r=malloc_msg(protpad_size+2);
 single_pad=malloc_msg(DEFAULT_PROTPAD_SIZE+2);
 single_pad_r=malloc_msg(DEFAULT_PROTPAD_SIZE+2);
 protpad_bck=malloc_msg(protpad_size+2);
 astream=file_open_noarch(name, m_rb);
 if(file_exists(protname))
 {
  xstream=file_open_noarch(protname, m_rb);
  rd_offset=0L;
 }
 else
 {
  xstream=astream;
  rd_offset=chk_prot_sig(xstream, sig_offset);
  if(rd_offset==0L)
  {
   if(test_mode)
   {
    msg_cprintf(0, M_NO_PROT_DATA);
    nputlf();
    return(0);
   }
   else
    error(M_NO_PROT_DATA);
  }
 }
 fseek(astream, 0L, SEEK_END);
 ifile_size=ftell(astream);
 if(rd_offset!=0L)
  ifile_size=rd_offset-6L;
 fseek(xstream, rd_offset, SEEK_SET);
 fread(single_pad, 1, DEFAULT_PROTPAD_SIZE, xstream);
 crc32term=CRC_MASK;
 crc32_for_block(single_pad+4, DEFAULT_PROTPAD_SIZE-4);
 /* Possible XRJ damage */
 if(mget_dword(&single_pad[0])!=crc32term||
    mget_word (&single_pad[4])!=0x1111)
 {
  fseek(xstream, (long)DEFAULT_PROTPAD_SIZE*3+rd_offset, SEEK_SET);
  fread(single_pad, 1, DEFAULT_PROTPAD_SIZE, xstream);
  crc32term=CRC_MASK;
  crc32_for_block(single_pad+4, DEFAULT_PROTPAD_SIZE-4);
  if(mget_dword(&single_pad[0])!=crc32term||
     mget_word (&single_pad[4])!=0x1111)
   error(M_RECOVERY_CRC_DAMAGED);
 }
 fseek(xstream, rd_offset, SEEK_SET);
 total_blocks=mget_word(&single_pad[6]);
 orig_ifile_size=mget_dword(&single_pad[10]);
 if(ifile_size==orig_ifile_size)
 {
  fseek(astream, 0L, SEEK_SET);
  msg_cprintf(0, M_WORKING);
  for(cur_stream=0; cur_stream<total_blocks; cur_stream++)
  {
   msg_cprintf(0, (FMSG *)prot_ticker);
   ins_lf=1;
   damage_level=0;
   fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                  (unsigned long)cur_stream+rd_offset, SEEK_SET);
   fread(single_pad, 1, DEFAULT_PROTPAD_SIZE, xstream);
   crc32term=CRC_MASK;
   crc32_for_block(single_pad+4, DEFAULT_PROTPAD_SIZE-4);
   if (mget_dword(&single_pad[0])!=crc32term)
   damage_level=2;
   fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                  (unsigned long)cur_stream+
                  3L*(unsigned long)DEFAULT_PROTPAD_SIZE*
                  (unsigned long)total_blocks+rd_offset, SEEK_SET);
   fread(single_pad_r, 1, DEFAULT_PROTPAD_SIZE, xstream);
   crc32term=CRC_MASK;
   crc32_for_block(single_pad_r+4, DEFAULT_PROTPAD_SIZE-4);
   if(mget_dword(&single_pad_r[0])!=crc32term)
   {
    if(damage_level==2)
    {
     if(ins_lf)
     {
      nputlf();
      ins_lf=0;
     }
     msg_cprintf(0, M_RECOVERY_2CRC_DAMAGED);
     abort_recovery();
    }
    damage_level=1;
   }
   for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-14; pad_ctr++)
   {
    single_pad[pad_ctr]=single_pad[pad_ctr+14];
    single_pad_r[pad_ctr]=single_pad_r[pad_ctr+14];
   }
   fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
         (unsigned long)cur_stream+(unsigned long)DEFAULT_PROTPAD_SIZE*
         (unsigned long)total_blocks+rd_offset, SEEK_SET);
   fread(protpad, 1, DEFAULT_PROTPAD_SIZE, xstream);
   crc32term=CRC_MASK;
   crc32_for_block(protpad+4, DEFAULT_PROTPAD_SIZE-4);
   damage_flag=(mget_dword(&protpad[0])!=crc32term)?1:0;
   if(!damage_flag)
   {
    for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-4; pad_ctr++)
     protpad[pad_ctr]=protpad[pad_ctr+4];
    for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
    {
     if(damage_level==2)
      protpad[pad_ctr+protpad_size-pad1_size]=single_pad_r[pad_ctr];
     else
      protpad[pad_ctr+protpad_size-pad1_size]=single_pad[pad_ctr];
    }
   }
   fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                  (unsigned long)cur_stream+2L*
                  (unsigned long)DEFAULT_PROTPAD_SIZE*
                  (unsigned long)total_blocks+rd_offset, SEEK_SET);
   fread(protpad_r, 1, DEFAULT_PROTPAD_SIZE, xstream);
   crc32term=CRC_MASK;
   crc32_for_block(protpad_r+4, DEFAULT_PROTPAD_SIZE-4);
   pad_damage_flag=(mget_dword(&protpad_r[0])!=crc32term)?1:0;
   if(!pad_damage_flag)
   {
    for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-4; pad_ctr++)
     protpad_r[pad_ctr]=protpad_r[pad_ctr+4];
    for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
    {
     if(damage_level==2)
      protpad_r[pad_ctr+protpad_size-pad1_size]=
       single_pad_r[pad1_size+pad_ctr];
     else
      protpad_r[pad_ctr+protpad_size-pad1_size]=
       single_pad[pad1_size+pad_ctr];
    }
   }
   cur_section=0;
   block_offset=(unsigned long)cur_stream*(unsigned long)DEFAULT_PROTPAD_SIZE;
   while(block_offset<ifile_size)
   {
    fseek(astream, block_offset, SEEK_SET);
    section_size=(int)min((unsigned long)DEFAULT_PROTPAD_SIZE,
                          (ifile_size-block_offset));
    section_size=fread(protpad_bck+1, 1, section_size, astream);
    protpad_bck[0]='\0';
    for(pad_ctr=section_size+1; pad_ctr<protpad_size; pad_ctr++)
     protpad_bck[pad_ctr]='\0';
    crc32term=(unsigned long)
              crc16_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
    crc32_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
    if(damage_level==0||damage_level==1)
    {
     if(mget_word(&single_pad[(pad1_size<<1)+((cur_section<<2)>>1)])!=
        (unsigned short)(crc32term%65536L))
      goto recovery;
    }
    if(damage_level==0||damage_level==2)
    {
     if(mget_word     
        (&single_pad_r[(pad1_size<<1)+((cur_section<<2)>>1)])!=
        (unsigned short)(crc32term>>16))
      goto recovery;
    }
    block_offset+=(unsigned long)
                  DEFAULT_PROTPAD_SIZE*(unsigned long)total_blocks;
    cur_section++;
   }
  }
  if(test_mode==2)
   goto recovery;
 }
 else
 {
recovery:
  nputlf();
  if(test_mode!=1)
  {
   atstream=ostream=file_open_noarch(rec_name, m_wbp);
   fseek(astream, 0L, SEEK_SET);
   errors=0;
   for(dest_file_size=min(ifile_size, orig_ifile_size);
       dest_file_size>0;
       dest_file_size-=(unsigned long)section_size)
   {
    section_size=min(DEFAULT_PROTPAD_SIZE, dest_file_size);
    if(fread(single_pad, 1, section_size, astream)!=section_size)
     break;
    if(fwrite(single_pad, 1, section_size, ostream)!=section_size)
     break;
   }
   for(dest_file_size=
       (ifile_size>=orig_ifile_size)?0:orig_ifile_size-ifile_size;
       dest_file_size>0;
       dest_file_size-=(unsigned long)section_size)
   {
    section_size=min(DEFAULT_PROTPAD_SIZE, dest_file_size);
    if(fwrite(single_pad, 1, section_size, ostream)!=section_size)
     break;
   }
   fseek(ostream, 0L, SEEK_END);
   if(ftell(ostream)!=orig_ifile_size)
    error(M_DISK_FULL);
   ifile_size=orig_ifile_size;
   for(cur_stream=0; cur_stream<total_blocks; cur_stream++)
   {
    msg_cprintf(0, (FMSG *)prot_ticker);
    ins_lf=1;
    damage_level=0;
    fseek(xstream,
          (unsigned long)DEFAULT_PROTPAD_SIZE*(unsigned long)cur_stream+
          rd_offset, SEEK_SET);
    fread(single_pad, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(single_pad+4, DEFAULT_PROTPAD_SIZE-4);
    if(mget_dword(&single_pad[0])!=crc32term)
     damage_level=2;
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
          (unsigned long)cur_stream+3L*(unsigned long)DEFAULT_PROTPAD_SIZE*
          (unsigned long)total_blocks+rd_offset, SEEK_SET);
    fread(single_pad_r, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(single_pad_r+4, DEFAULT_PROTPAD_SIZE-4);
    if(mget_dword(&single_pad_r[0])!=crc32term)
    {
     if(damage_level==2)
     {
      if(ins_lf)
      {
       nputlf();
       ins_lf=0;
      }
      msg_cprintf(0, M_RECOVERY_2CRC_DAMAGED);
      abort_recovery();
     }
     damage_level=1;
    }
    for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-14; pad_ctr++)
    {
     single_pad[pad_ctr]=single_pad[pad_ctr+14];
     single_pad_r[pad_ctr]=single_pad_r[pad_ctr+14];
    }
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
          (unsigned long)cur_stream+(unsigned long)DEFAULT_PROTPAD_SIZE*
          (unsigned long)total_blocks+rd_offset, SEEK_SET);
    fread(protpad, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(protpad+4, DEFAULT_PROTPAD_SIZE-4);
    damage_flag=(mget_dword(&protpad[0])!=crc32term)?1:0;
    if(!damage_flag)
    {
     for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-4; pad_ctr++)
      protpad[pad_ctr]=protpad[pad_ctr+4];
     for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
     {
      if(damage_level==2)
       protpad[pad_ctr+protpad_size-pad1_size]=single_pad_r[pad_ctr];
      else
       protpad[pad_ctr+protpad_size-pad1_size]=single_pad[pad_ctr];
     }
    }
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)cur_stream+2L*
                   (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)total_blocks+rd_offset, SEEK_SET);
    fread(protpad_r, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(protpad_r+4, DEFAULT_PROTPAD_SIZE-4);
    pad_damage_flag=(mget_dword(&protpad_r[0])!=crc32term)?1:0;
    if(!pad_damage_flag)
    {
     for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-4; pad_ctr++)
      protpad_r[pad_ctr]=protpad_r[pad_ctr+4];
     for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
     {
      if(damage_level==2)
       protpad_r[pad_ctr+protpad_size-pad1_size]=
        single_pad_r[pad1_size+pad_ctr];
      else
       protpad_r[pad_ctr+protpad_size-pad1_size]=
        single_pad[pad1_size+pad_ctr];
     }
    }
    cur_section=0;
    bck_pad_flag=pad_flag=-1;
    block_offset=(unsigned long)cur_stream*(unsigned long)DEFAULT_PROTPAD_SIZE;
    while(block_offset<ifile_size)
    {
     fseek(ostream, block_offset, SEEK_SET);
     section_size=fread(protpad_bck+1, 1, DEFAULT_PROTPAD_SIZE, ostream);
     protpad_bck[0]='\0';
     for(pad_ctr=section_size+1; pad_ctr<protpad_size; pad_ctr++)
      protpad_bck[pad_ctr]='\0';
     data_damage=0;
     crc32term=(unsigned long)
               crc16_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
     crc32_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
     if(damage_level==0||damage_level==1)
     {
      if (mget_word
          (&single_pad[(pad1_size<<1)+((cur_section<<2)>>1)])!=
          (unsigned short)(crc32term%65536L))
       data_damage=1;
     }
     if(damage_level==0||damage_level==2)
     {
      if (mget_word
         (&single_pad_r[(pad1_size<<1)+((cur_section<<2)>>1)])!=
         (unsigned short)(crc32term>>16))
       data_damage=1;
     }
     if(data_damage)
     {
      errors++;
      if(ins_lf)
      {
       nputlf();
       ins_lf=0;
      }
      msg_cprintf(0, M_SECTION_DAMAGED, cur_stream, cur_section);
      if(bck_pad_flag==-1)
      {
       bck_pad_flag=cur_section;
       rec_size=section_size;
      }
      else if(pad_flag==-1)
      {
       pad_flag=cur_section;
       bck_rec_size=section_size;
      }
      else
       abort_recovery();
     }
     else
     {
      for(pad_ctr=0; pad_ctr<protpad_size; pad_ctr++)
      {
       protpad[pad_ctr]^=protpad_bck[pad_ctr];
       protpad_r[pad_ctr]^=protpad_bck[(pad_ctr+cur_section)%protpad_size];
      }
     }
     block_offset+=(unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)total_blocks;
     cur_section++;
    }
    if(bck_pad_flag!=-1)
    {
     if(damage_flag!=0&&pad_damage_flag!=0&&bck_pad_flag!=-1)
      abort_recovery();
     else
     {
      if(damage_flag==0&&pad_damage_flag==0)
      {
       if(pad_flag==-1)
       {
        fseek(ostream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)cur_stream+
                       (unsigned long)bck_pad_flag*
                       (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)total_blocks, SEEK_SET);
        fwrite(protpad+1, 1, rec_size, ostream);
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
       }
       else
       {
        protpad_bck[0]='\0';
        cur_section=0;
        for(pad_ctr=1; pad_ctr<protpad_size; pad_ctr++)
        {
         protpad_bck[(cur_section+pad_flag-bck_pad_flag)%protpad_size]=
          protpad_bck[cur_section]^protpad[cur_section]^
          protpad_r[(cur_section+protpad_size-bck_pad_flag)%protpad_size];
         cur_section=(cur_section+pad_flag-bck_pad_flag)%protpad_size;
        }
        fseek(ostream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)cur_stream+
                       (unsigned long)pad_flag*
                       (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)total_blocks, SEEK_SET);
        fwrite(protpad_bck+1, 1, bck_rec_size, ostream);
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
        for(pad_ctr=1; pad_ctr<protpad_size; pad_ctr++)
         protpad_bck[pad_ctr]^=protpad[pad_ctr];
        fseek(ostream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)cur_stream+
                       (unsigned long)bck_pad_flag*
                       (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)total_blocks, SEEK_SET);
        fwrite(protpad_bck+1, 1, rec_size, ostream);
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
       }
      }
      else
      {
       if(pad_damage_flag!=0)
       {
        if(pad_flag!=-1)
         abort_recovery();
        fseek(ostream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)cur_stream+
                       (unsigned long)bck_pad_flag*
                       (unsigned long)DEFAULT_PROTPAD_SIZE*
                       (unsigned long)total_blocks, SEEK_SET);
        fwrite(protpad+1, 1, rec_size, ostream);
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
       }
       else
       {
        if(damage_flag!=0)
        {
         if(pad_flag!=-1)
          abort_recovery();
         for(pad_ctr=1; pad_ctr<protpad_size; pad_ctr++)
          protpad_bck[pad_ctr]=
           protpad_r[(pad_ctr+protpad_size-bck_pad_flag)%protpad_size];
         fseek(ostream,
               (unsigned long)DEFAULT_PROTPAD_SIZE*
               (unsigned long)cur_stream+
               (unsigned long)bck_pad_flag*
               (unsigned long)DEFAULT_PROTPAD_SIZE*
               (unsigned long)total_blocks, SEEK_SET);
         fwrite(protpad_bck+1, 1, rec_size, ostream);
         if(ins_lf)
         {
          nputlf();
          ins_lf=0;
         }
         msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
        }
       }
      }
     }
    }
   }
   if(rd_offset!=0L)
    create_protfile(ostream, total_blocks, 1);
   fclose(ostream);
   atstream=NULL;
  }
  else
  {
   fseek(astream, 0L, SEEK_SET);
   errors=0;
   ifile_size=orig_ifile_size;
   for(cur_stream=0; cur_stream<total_blocks; cur_stream++)
   {
    msg_cprintf(0, (FMSG *)prot_ticker);
    ins_lf=1;
    damage_level=0;
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)cur_stream+rd_offset, SEEK_SET);
    fread(single_pad, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(single_pad+4, DEFAULT_PROTPAD_SIZE-4);
    if(mget_dword(&single_pad[0])!=crc32term)
      damage_level=2;
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)cur_stream+
                   3L*(unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)total_blocks+rd_offset, SEEK_SET);
    fread(single_pad_r, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(single_pad_r+4, DEFAULT_PROTPAD_SIZE-4);
    if(mget_dword(&single_pad_r[0])!=crc32term)
    {
     if(damage_level==2)
     {
      if(ins_lf)
      {
       nputlf();
       ins_lf=0;
      }
      msg_cprintf(0, M_RECOVERY_2CRC_DAMAGED);
      abort_recovery();
     }
     damage_level=1;
    }
    for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-14; pad_ctr++)
    {
     single_pad[pad_ctr]=single_pad[pad_ctr+14];
     single_pad_r[pad_ctr]=single_pad_r[pad_ctr+14];
    }
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)cur_stream+
                   (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)total_blocks+rd_offset, SEEK_SET);
    fread(protpad, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(protpad+4, DEFAULT_PROTPAD_SIZE-4);
    damage_flag=(mget_dword(&protpad[0])!=crc32term)?1:0;
    if(!damage_flag)
    {
     for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-4; pad_ctr++)
      protpad[pad_ctr]=protpad[pad_ctr+4];
     for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
     {
      if(damage_level==2)
       protpad[pad_ctr+protpad_size-pad1_size]=single_pad_r[pad_ctr];
      else
       protpad[pad_ctr+protpad_size-pad1_size]=single_pad[pad_ctr];
     }
    }
    fseek(xstream, (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)cur_stream+2L*
                   (unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)total_blocks+rd_offset, SEEK_SET);
    fread(protpad_r, 1, DEFAULT_PROTPAD_SIZE, xstream);
    crc32term=CRC_MASK;
    crc32_for_block(protpad_r+4, DEFAULT_PROTPAD_SIZE-4);
    pad_damage_flag=(mget_dword(&protpad_r[0])!=crc32term)?1:0;
    if(!pad_damage_flag)
    {
     for(pad_ctr=0; pad_ctr<DEFAULT_PROTPAD_SIZE-4; pad_ctr++)
      protpad_r[pad_ctr]=protpad_r[pad_ctr+4];
     for(pad_ctr=0; pad_ctr<pad1_size; pad_ctr++)
     {
      if(damage_level==2)
       protpad_r[pad_ctr+protpad_size-pad1_size]=
        single_pad_r[pad1_size+pad_ctr];
      else
       protpad_r[pad_ctr+protpad_size-pad1_size]=
        single_pad[pad1_size+pad_ctr];
     }
    }
    cur_section=0;
    bck_pad_flag=pad_flag=-1;
    block_offset=(unsigned long)cur_stream*(unsigned long)DEFAULT_PROTPAD_SIZE;
    while(block_offset<ifile_size)
    {
     fseek(astream, block_offset, SEEK_SET);
     section_size=fread(protpad_bck+1, 1, DEFAULT_PROTPAD_SIZE, astream);
     protpad_bck[0]='\0';
     for(pad_ctr=section_size+1; pad_ctr<protpad_size; pad_ctr++)
      protpad_bck[pad_ctr]='\0';
     data_damage=0;
     crc32term=(unsigned long)
               crc16_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
     crc32_for_block(protpad_bck+1, DEFAULT_PROTPAD_SIZE);
     if(damage_level==0||damage_level==1)
     {
      if(mget_word
         (&single_pad[(pad1_size<<1)+((cur_section<<2)>>1)])!=
         (unsigned short)(crc32term%65536L))
       data_damage=1;
     }
     if(damage_level==0||damage_level==2)
     {
      if(mget_word
         (&single_pad_r[(pad1_size<<1)+((cur_section<<2)>>1)])!=
         (unsigned short)(crc32term>>16))
       data_damage=1;
     }
     if(data_damage)
     {
      errors++;
      if(ins_lf)
      {
       nputlf();
       ins_lf=0;
      }
      msg_cprintf(0, M_SECTION_DAMAGED, cur_stream, cur_section);
      if(bck_pad_flag==-1)
      {
       bck_pad_flag=cur_section;
       rec_size=section_size;
      }
      else if(pad_flag==-1)
      {
       pad_flag=cur_section;
       bck_rec_size=section_size;
      }
      else
       abort_recovery();
     }
     else
     {
      for(pad_ctr=0; pad_ctr<protpad_size; pad_ctr++)
      {
       protpad[pad_ctr]^=protpad_bck[pad_ctr];
       protpad_r[pad_ctr]^=protpad_bck[(pad_ctr+cur_section)%protpad_size];
      }
     }
     block_offset+=(unsigned long)DEFAULT_PROTPAD_SIZE*
                   (unsigned long)total_blocks;
     cur_section++;
    }
    if(bck_pad_flag!=-1)
    {
     if(damage_flag!=0&&pad_damage_flag!=0&&bck_pad_flag!=-1)
      abort_recovery();
     else
     {
      if(damage_flag==0&&pad_damage_flag==0)
      {
       if(pad_flag==-1)
       {
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
       }
       else
       {
        protpad_bck[0]='\0';
        cur_section=0;
        for(pad_ctr=1; pad_ctr<protpad_size; pad_ctr++)
        {
         protpad_bck[(cur_section+pad_flag-bck_pad_flag)%protpad_size]=
          protpad_bck[cur_section]^protpad[cur_section]^
          protpad_r[(cur_section+protpad_size-bck_pad_flag)%protpad_size];
         cur_section=(cur_section+pad_flag-bck_pad_flag)%protpad_size;
        }
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
        for(pad_ctr=1; pad_ctr<protpad_size; pad_ctr++)
         protpad_bck[pad_ctr]^=protpad[pad_ctr];
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
       }
      }
      else
      {
       if(pad_damage_flag!=0)
       {
        if(pad_flag!=-1)
         abort_recovery();
        if(ins_lf)
        {
         nputlf();
         ins_lf=0;
        }
        msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
       }
       else
       {
        if(damage_flag!=0)
        {
         if(pad_flag!=-1)
          abort_recovery();
         for(pad_ctr=1; pad_ctr<protpad_size; pad_ctr++)
          protpad_bck[pad_ctr]=
           protpad_r[(pad_ctr+protpad_size-bck_pad_flag)%protpad_size];
         if(ins_lf)
         {
          nputlf();
          ins_lf=0;
         }
         msg_cprintf(0, M_SECTION_RECOVERED, cur_stream);
        }
       }
      }
     }
    }
   }
  }
 }
 if(ins_lf)
  nputlf();
 if(rd_offset==0L)
  fclose(xstream);
 fclose(astream);
 free(protpad);
 free(protpad_r);
 free(single_pad);
 free(single_pad_r);
 free(protpad_bck);
 return(errors?0:1);
}
