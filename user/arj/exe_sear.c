/*
 * $Id: exe_sear.c,v 1.3 2003/10/16 10:32:46 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Routines that fetch overlay data are located in this file.
 *
 */

#include "arj.h"

#ifdef ELF_EXECUTABLES
 #ifdef __QNXNTO__
    #include <libelf.h>
 #else
    #include <elf.h>
 #endif /* __QNXNTO__ */
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* ARJSFX module order */

#define MN_SFXJR                   1
#define MN_SFX                     2
#define MN_SFXV                    3
#define MN_SFXSTUB                 4

/* Define the ELF magic numbers if not defined yet */

#if defined(ELF_EXECUTABLES)&&!defined(ELFMAG)
 static char elfmag[4]={'E', 'L', 'F', 0x7F};
 #define ELFMAG elfmag
 #define SELFMAG 4
#endif

#if SFX_LEVEL>=ARJ

/* Local variables */

static char overlay_sig[]="RJ_SFX";

/* Looks for ARJ_SFX signature */

static void browse(FILE *stream)
{
 char buf[256];
 unsigned long cur_pos, sig_pos;
 int bytes_read;
 int i;
 char *buf_ptr;

 while(1)
 {
  cur_pos=ftell(stream);
  bytes_read=fread(buf, 1, sizeof(buf), stream);
  if(bytes_read<=0)
   error(M_CANTREAD);
  buf_ptr=buf;
  i=0;
  while(i<bytes_read)
  {
   if(*buf_ptr=='A'&&!strcmp(buf_ptr+1, overlay_sig))
   {
    sig_pos=cur_pos+(unsigned long)i;
    if(mget_dword(buf_ptr+8)==sig_pos)
     goto loc_hdr;
   }
   i++;
   buf_ptr++;
  }
  if(bytes_read==sizeof(buf))
   fseek(stream, -16L, SEEK_CUR);
 }
 loc_hdr:
 cur_pos+=(unsigned long)i+12L;
 fseek(stream, cur_pos, SEEK_SET);
}

/* Writes the contents of a FAR block to the output stream */

static void farblock_output(FILE *stream, char FAR *block, unsigned long len)
{
 #ifdef TILED
  while(len-->0)
  {
   if(fputc((int)*(block++), stream)==EOF)
    error(M_DISK_FULL);
  }
 #else
  file_write(block, 1, len, stream);
 #endif
}

#endif

/* Reads the EXE size from the header */

static unsigned long get_exe_size(FILE *stream)
{
 #if SFX_LEVEL>=ARJ
  unsigned long result=EXESIZE_ARJ;
 #elif SFX_LEVEL==ARJSFXV
  unsigned long result=EXESIZE_ARJSFXV;
 #else
  unsigned long result=EXESIZE_ARJSFX;
 #endif
 #ifndef ELF_EXECUTABLES
  unsigned int remainder, blocks;
 #else
  Elf32_Ehdr ehdr;
  Elf32_Shdr shdr;
  unsigned long ref_point;
  unsigned long cur_pos;
  unsigned int i;
 #endif

 #ifndef ELF_EXECUTABLES                /* Presume standard DOS or OS/2 EXE */
  fseek(stream, 2L, SEEK_SET);
  remainder=fget_word(stream);
  blocks=fget_word(stream);
  result=(unsigned long)(blocks-1)*512L+(unsigned long)remainder;
  return(result);
 #else                                  /* ELF (Linux, OS/2 PPC, Solaris...) */
  fread(&ehdr, 1, sizeof(ehdr), stream);
  if(memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
   return(0);
  result=ehdr.e_shoff+(unsigned long)ehdr.e_shentsize*ehdr.e_shnum;
  fseek(stream, ehdr.e_shoff, SEEK_SET);
  for(i=0; i<ehdr.e_shnum; i++)
  {
   fseek(stream, ehdr.e_shoff+(unsigned long)i*ehdr.e_shentsize, SEEK_SET);
   cur_pos=ftell(stream);
   fread(&shdr, 1, sizeof(shdr), stream);
   ref_point=shdr.sh_offset+shdr.sh_size;
   /* Ignore uninitialized sections (BSS) */
   if(ref_point>result&&shdr.sh_type!=SHT_NOBITS)
    result=ref_point;
  }
  return(result);
 #endif
}

#if SFX_LEVEL>=ARJ

/* Performs all actions related to picking a block */

static void fetch_block(int num)
{
 FILE *stream;
 unsigned long exe_size;
 int t_num;
 unsigned long t_pos;
 char buf[256];
 int block_len;
 int bytes_read;
 unsigned int desc_word;

 stream=file_open_noarch(exe_name, m_rb);
 exe_size=get_exe_size(stream);
 fseek(stream, exe_size, SEEK_SET);
 t_pos=0L;
 for(t_num=0; t_num<num; t_num++)
 {
  fseek(stream, t_pos, SEEK_CUR);
  browse(stream);
  t_pos=fget_longword(stream);
 }
 crc32term=CRC_MASK;
 block_len=(int)min(sizeof(buf), t_pos);
 while(t_pos>0)
 {
  bytes_read=fread(buf, 1, block_len, stream);
  if(bytes_read<=0)
   break;
  crc32_for_block(buf, bytes_read);
  farblock_output(aostream, (char FAR *)buf, (unsigned long)bytes_read);
  t_pos-=(unsigned long)bytes_read;
  block_len=(int)min(sizeof(buf), t_pos);
 }
 fclose(stream);
 desc_word=SFXDESC_NONSFX;
 if(create_sfx==SFXCRT_SFX&&multivolume_option)
  desc_word=SFXDESC_SFXV;
 else if(create_sfx==SFXCRT_SFX)
  desc_word=SFXDESC_SFX;
 else if(create_sfx==SFXCRT_SFXJR)
  desc_word=SFXDESC_SFXJR;
 fput_word(desc_word, aostream);
 if(is_registered)
  desc_word=REG_ID;
 fput_word(desc_word, aostream);
 crc32term^=CRC_MASK;
 fput_dword(crc32term, aostream);
}

/* Picks the ARJSFX and stores ARJSFX run-time data */

void fetch_sfx()
{
 fetch_block(MN_SFX);
}

/* Picks the ARJSFXJR and stores ARJSFXJR run-time data */

void fetch_sfxjr()
{
 fetch_block(MN_SFXJR);
}

/* Picks the ARJSFXV and stores ARJSFXV run-time data */

void fetch_sfxv()
{
 fetch_block(MN_SFXV);
}

/* Picks the SFXSTUB */

void fetch_sfxstub()
{
 fetch_block(MN_SFXSTUB);
}

#endif

#if SFX_LEVEL<=ARJSFXV

/* SFX seek routine */

void sfx_seek()
{
 unsigned long exe_size;
 unsigned long fcrc;
 unsigned int block_size, bytes_read;
 char buf[256];

 exe_size=get_exe_size(aistream);
 fseek(aistream, exe_size, SEEK_SET);
 main_hdr_offset=find_header(0, aistream);
 fseek(aistream, -8L, SEEK_CUR);
 exe_size=ftell(aistream);
 reg_id=fget_word(aistream);            /* Descriptive word */
 reg_id=fget_word(aistream);
 fcrc=fget_longword(aistream);
 if(reg_id!=REG_ID)
  reg_id=0;
 fseek(aistream, 0L, SEEK_SET);
 crc32term=CRC_MASK;
 block_size=min((unsigned long)sizeof(buf), exe_size);
 while(exe_size>0L)
 {
  bytes_read=fread(buf, 1, block_size, aistream);
  if(bytes_read==0)
   break;
  crc32_for_block(buf, bytes_read);
  exe_size-=(unsigned long)bytes_read;
  block_size=min((unsigned long)block_size, exe_size);
 }
 if((crc32term^CRC_MASK)!=fcrc&&!skip_integrity_test)
  error(M_DAMAGED_SFX);
 fseek(aistream, main_hdr_offset, SEEK_SET);
}

#endif
