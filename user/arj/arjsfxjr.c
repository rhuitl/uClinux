/*
 * $Id: arjsfxjr.c,v 1.8 2004/04/17 11:39:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This is the source for ARJSFXJR, the smallest SFX module.
 *
 */

#include "arj.h"

#include <fcntl.h>
#if TARGET!=UNIX
 #include <io.h>
 #include <share.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if COMPILER!=BCC
 #include <signal.h>
 #include <time.h>
#endif

#if TARGET==DOS
 #include <dos.h>                       /* Weird, eh? */
#endif

#if TARGET==UNIX
 #include <utime.h>
 #include <unistd.h>
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Local variables */

static int file_type;
static int aistream;                    /* ARJSFXJR does not use FILE * */
static unsigned short bitbuf;
static int bitcount;
static unsigned char subbitbuf;
static long compsize;
static long origsize;
static char in_cache[CACHE_SIZE_SFXJR]; /* Cache for incoming data */
static char *in_cache_ptr;              /* Pointer to fetch incoming data */
static int fill_level;                  /* Cache fill level */
static unsigned short reg_id;           /* ARJSFX registration ID */
static unsigned int basic_hdr_size;
static char header[HEADERSIZE_MAX];
static unsigned long header_crc;
static unsigned char first_hdr_size;
static unsigned char arj_flags;
static unsigned int method;
static unsigned long ftime_stamp;
static unsigned long file_crc;
static unsigned short entry_pos;
static unsigned int file_mode;
static char *hdr_filename;
static char *hdr_comment;
static char filename[FILENAME_MAX];
static char comment[COMMENT_MAX];
static char archive_name[FILENAME_MAX];
static unsigned char dec_text[DICSIZ];
static unsigned short left[2*NC-1];
static unsigned short right[2*NC-1];
static unsigned char pt_len[NPT];
static unsigned short c_table[CTABLESIZE];
static unsigned short pt_table[PTABLESIZE];
static unsigned char c_len[NC];
static int blocksize;
static char cmd_args[SFX_COMMAND_SIZE+1];
static int st_argc;
static char nullstr[]="";
static char test_mode=0;                /* 1 if test mode (-t) is enabled */
static int atstream=0;                  /* Output file handle */
static int overwrite_existing=0;        /* -o enables this mode */
static int allow_skipping=0;            /* (-n) no errors on skipped files */
static unsigned int errors=0;           /* Number of errors */
static unsigned int warnings=0;         /* Number of non-fatal errors */
static unsigned int total_files=0;      /* Total number of files in archive */
static int unpack_in_progress=0;        /* Unpack procedure indicator */
static char *dest_dir=nullstr;          /* Destination directory */
static char pathsep_sfxjr[]="\\:";      /* A simplified path separator list */

/* Local forward-referenced functions */

static void decode();

/* Converts a numerical variable to string */

static void numtostr(unsigned int n, char *str)
{
 char *sptr;
 int i, j;
 char t;

 i=0;
 sptr=str;
 *sptr='\0';
 do
 {
  sptr[++i]=(char)(n%10)+'0';
  n/=10U;
 } while(n!=0);
 for(j=0; j<=i; j++)
 {
  t=str[i];
  str[i]=str[j];
  str[j]=t;
  i--;
 }
}

/* The only screen output routine */

static void sfxjr_puts(FMSG *str)
{
 static char s_cr='\r';
 #ifdef FMSG_ST
  char c;
 #endif

 #if TARGET==DOS&&COMPILER==BORLAND
  kbhit();                              /* Don't know/care why it's here */
 #endif
 while(*str!='\0')
 {
  if(*str=='\n')
   _write(1, &s_cr, 1);
  #ifdef FMSG_ST
   c=*str;
   _write(1, &c, 1);
  #else
   _write(1, str, 1);
  #endif
  str++;
 }
}

/* Writes a LF */

static void nputlf()
{
 static char s_crlf[]={'\r', '\n'};

 _write(1, &s_crlf, 2);
}

/* Error output routine. Very simplified, like all others. */

static void error(FMSG *errmsg)
{
 nputlf();
 sfxjr_puts(errmsg);
 nputlf();
 exit(ARJSFXJR_ERL_ERROR);
}

/* Converts a filename to the format used in current OS (simply substitutes
   the UNIX separators with DOS ones) */

static void name_to_hdr(char *name)
{
 int i;

 for(i=0; name[i]!='\0'; i++)
 {
  if(name[i]==PATHSEP_UNIX)
   name[i]=PATHSEP_DEFAULT;
 }
}

/* Looks for a path separator in the given filename/pathnamee */

static char *find_pathsep(char *name)
{
 if(*name=='\0')
  return(NULL);
 while(*name!='\0')
 {
  if(*name==PATHSEP_DEFAULT)
   return(name);
  name++;
 }
 return((file_type==ARJT_DIR)?name:NULL);
}

/* Creates the necessary subdirectories before extracting a file */

static void create_subdir_tree(char *name)
{
 char tmp_name[FILENAME_MAX];
 int rc;
 char *nptr;

 nptr=name;
 /* Skip over preceding drive specifications */
 if(nptr[0]!='\0'&&nptr[1]==':')
  nptr+=2;
 if(nptr[0]=='.')
 {
  if(nptr[1]=='.'&&nptr[2]==PATHSEP_DEFAULT)
   nptr++;
  if(nptr[1]==PATHSEP_DEFAULT)
   nptr++;
 }
 if(nptr[0]!=PATHSEP_DEFAULT)
  nptr++;
 while((nptr=find_pathsep(nptr))!=NULL)
 {
  strcpy(tmp_name, name);
  tmp_name[nptr-name]='\0';
  #if TARGET==UNIX
   rc=chmod(tmp_name, 0755);
  #else
   rc=_chmod(tmp_name, 0);
  #endif
  if(rc==-1)
  {
   #if TARGET!=UNIX&&!defined(__EMX__)
    if(mkdir(tmp_name))
     return;
   #else
    if(mkdir(tmp_name, 666))
     return;
   #endif
  }
  else
   if(!(rc&FATTR_DIREC))
    return;
  nptr++;
 }
}


#ifdef WORDS_BIGENDIAN
#define mget_byte(p) (*(unsigned char FAR *)(p)&0xFF)


/* Reads two bytes from the input archive */

unsigned int mget_word(char *p)
{
 unsigned int b0, b1;

 b0=mget_byte(p);
 b1=mget_byte(p+1);
 return (b1<<8)|b0;
}
#else
#define mget_word(p) (*(unsigned short *)(p)&0xFFFF)
#endif

/* Reads four bytes from the input archive */

#ifdef WORDS_BIGENDIAN
unsigned long mget_dword(char *p)
{
 unsigned long w0, w1;

 w0=mget_word(p);
 w1=mget_word(p+2);
 return (w1<<16)|w0;
}
#else
#define mget_dword(p) (*(unsigned long *)(p))
#endif

unsigned int fget_word()
{
 char b[2];

 if(_read(aistream, b, 2)!=2)
  error(M_CANTREAD);
#ifdef WORDS_BIGENDIAN
 return (mget_byte(b+1)<<8)|mget_byte(b);
#else
 return mget_word(b);
#endif
}

/* Reads four bytes from the input archive */

unsigned long fget_dword()
{
 char b[4];

 if(_read(aistream, b, 4)!=4)
  error(M_CANTREAD);
#ifdef WORDS_BIGENDIAN
 return (mget_word(b+2)<<16)|mget_word(b); 
#else
 return mget_dword(b);
#endif
}

/* Reads N bits from the input file into the buffer */

static void fillbuf(int n)
{
 unsigned int nbytes;

 bitbuf=(bitbuf<<n)&0xFFFF;             /* lose the first n bits */
 while(n>bitcount)
 {
  bitbuf|=subbitbuf<<(n-=bitcount);
  if(compsize!=0L)
  {
   if(fill_level<=0)
   {
    nbytes=(unsigned int)min(compsize, (long)CACHE_SIZE_SFXJR);
    fill_level=_read(aistream, in_cache, nbytes);
    if(fill_level<0)
     error(M_CANTREAD);
    in_cache_ptr=in_cache;
   }
   subbitbuf=(unsigned char)*in_cache_ptr++;
   fill_level--;
   compsize--;
  }
  else
   subbitbuf=0;
  bitcount=CHAR_BIT;
 }
 bitbuf|=subbitbuf>>(bitcount-=n);
}

/* Reads and returns N bits */

static unsigned short getbits(int n)
{
 unsigned short x;

 x=bitbuf>>(CHAR_BIT*2-n);
 fillbuf(n);
 return(x);
}

/* Initializes bitwise reading mode */

static void init_getbits()
{
 fill_level=0;
 bitbuf=0;
 subbitbuf=0;
 bitcount=0;
 fillbuf(CHAR_BIT*2);
}

/* Reads a block from the file, updating CRC */

static int fread_crc(char *buffer, int count)
{
 int n;

 n=_read(aistream, buffer, count);
 if(n>0)
 {
  origsize+=(unsigned long)n;
  crc32_for_block(buffer, n);
 }
 return(n);
}

/* Writes the output buffer to a file, updating the CRC */

static void fwrite_crc(char *buffer, int count)
{
 crc32_for_block(buffer, count);
 if(!test_mode)
 {
  if(_write(atstream, buffer, count)<count)
   error(M_DISK_FULL);
 }
}

/* Reads the registration ID from the archive */

static void get_reg_id()
{
 _lseek(aistream, -2L, SEEK_CUR);
 reg_id=fget_word();
}

/* Looks for an archive header within the SFX */

static void find_sfx_header()
{
 #ifndef ELF_EXECUTABLES
  unsigned int remainder, blocks;
 #endif
 unsigned long exe_pos;

 /* Hack for MZ executables */
 #ifndef ELF_EXECUTABLES
  _lseek(aistream, 2L, SEEK_SET);
  remainder=fget_word();
  blocks=fget_word();
  exe_pos=(blocks-1)*512L+remainder;
 #else
  exe_pos=0L;
 #endif
 do
 {
  while(exe_pos<HSLIMIT_ARJSFXJR)
  {
   _lseek(aistream, (long)exe_pos, SEEK_SET);
   if(fget_word()==HEADER_ID)
    break;
   exe_pos++;
  }
  if((basic_hdr_size=fget_word())<=HEADERSIZE_MAX)
  {
   crc32term=CRC_MASK;
   fread_crc(header, basic_hdr_size);
   if((crc32term^CRC_MASK)==fget_dword())
   {
    _lseek(aistream, (long)exe_pos, SEEK_SET);
    return;
   }
  }
  exe_pos++;
 } while(exe_pos<HSLIMIT_ARJSFXJR);
}

/* Reads a compressed file header. Skips through any extended headers. */

static int read_header()
{
 unsigned short header_id;
 
 /* Strictly check the header ID */
 if(fget_word()!=HEADER_ID)
  error(M_BAD_HEADER);
 if((basic_hdr_size=fget_word())==0)
  return(0);
 if(basic_hdr_size>HEADERSIZE_MAX)
  error(M_BAD_HEADER);
 crc32term=CRC_MASK;
 fread_crc(header, basic_hdr_size);
 if((header_crc=fget_dword())!=(crc32term^CRC_MASK))
  error(M_HEADER_CRC_ERROR);
 /* Selectively fetch header values */
 first_hdr_size=header[0];
 arj_flags=header[4];
 method=(unsigned int)header[5];
 file_type=(unsigned int)header[6];
 ftime_stamp=mget_dword(header+8);
 compsize=mget_dword(header+12);
 origsize=mget_dword(header+16);
 file_crc=mget_dword(header+20);
 entry_pos=mget_word(header+24);
 file_mode=mget_dword(header+26);
 hdr_filename=header+first_hdr_size;
 strncpy(filename, hdr_filename, FILENAME_MAX);
 filename[FILENAME_MAX-1]='\0';
 if(arj_flags&PATHSYM_FLAG)
  name_to_hdr(filename);
 if((long)origsize<0||(long)compsize<0)
  error(M_BAD_HEADER);
 hdr_comment=header+strlen(hdr_filename)+first_hdr_size+1;
 strncpy(comment, hdr_comment, COMMENT_MAX);
 comment[COMMENT_MAX-1]='\0';
 /* Skip over extended headers, if any */
 while((header_id=fget_word())!=0)
  _lseek(aistream, (long)header_id+4L, SEEK_CUR);
 return(1);
}

/* Unarchives a stored file */

static void unstore()
{
 int fetch_size;

 while(compsize!=0L)
 {
  fetch_size=(int)min(compsize, (unsigned long)DICSIZ);
  compsize-=(unsigned long)fetch_size;
  if(_read(aistream, dec_text, fetch_size)!=fetch_size)
   error(M_CANTREAD);
  fwrite_crc(dec_text, fetch_size);
  sfxjr_puts(M_SFXJR_TICKER);
 }
}

/* Skips an archived file */

static void skip_file(FMSG *reason)
{
 sfxjr_puts(reason);
 sfxjr_puts(M_SKIPPED);
 sfxjr_puts((FMSG *)filename);
 nputlf();
 _lseek(aistream, compsize, SEEK_CUR);
}

/* Unpacks a single file, making all necessary checks */

static int unpack_file()
{
 int c;
 char tmp_name[FILENAME_MAX];

 if(!test_mode)
 {
  strcpy(tmp_name, dest_dir);
  strcat(tmp_name, filename);
  strcpy(filename, tmp_name);
  atstream=_open(filename, O_BINARY|O_RDONLY);
  if(atstream>=0)
  {
   _close(atstream);
   if(!overwrite_existing)
   {
    skip_file(M_FILE_EXISTS);
    if(!allow_skipping)
     warnings++;
    return(0);
   }
  }
  create_subdir_tree(filename);
  if(file_type!=ARJT_DIR&&(atstream=open(filename, O_CREAT|O_TRUNC|O_BINARY|O_RDWR, S_IREAD|S_IWRITE))<0)
  {
   skip_file(M_CANTOPEN_F);
   errors++;
   return(0);
  }
  unpack_in_progress=1;
 }
 sfxjr_puts(M_EXTRACTING);
 sfxjr_puts(filename);
 c=strlen(filename);
 while(c++<12)
  sfxjr_puts(M_VD_SPACE);
 crc32term=CRC_MASK;
 sfxjr_puts(M_VD_SPACE);
 if(file_type!=ARJT_DIR)
 {
  if(method>0)
   decode();
  else
   unstore();
  if(!test_mode)
   _close(atstream);
 }
 if(!test_mode)
 {
  #if TARGET==UNIX
   {
    struct utimbuf ut;

    ut.actime=ut.modtime=ftime_stamp;
    utime(filename, &ut);
   }
  #elif TARGET==WIN32
   file_setftime(filename, ftime_stamp);
  #else
   if((atstream=_open(filename, O_BINARY|O_RDWR))>0)
   {
    file_setftime_on_hf(atstream, ftime_stamp);
    _close(atstream);
   }
  #endif
  #if COMPILER==BCC
   _chmod(filename, 1, file_mode&STD_ATTRS);
  #elif COMPILER==MSC||COMPILER==MSVC
   #if TARGET==DOS
    _dos_setfileattr(filename, file_mode&STD_ATTRS);
   #elif TARGET==OS2
    DosSetFileMode(filename, file_mode&STD_ATTRS, 0L);
   #elif TARGET==WIN32
    SetFileAttributes(filename, file_mode&STD_ATTRS);
   #endif
  #endif
 }
 atstream=0;
 unpack_in_progress=0;
 if((crc32term^CRC_MASK)==file_crc)
  sfxjr_puts(M_OK);
 else
 {
  sfxjr_puts(M_CRC_ERROR);
  errors++;
 }
 nputlf();
 return(1);
}

/* Analyzes command-line parameters */

static int analyze_arg(char *arg)
{
 if(arg[0]=='-')
 {
  switch(arg[1])
  {
   case 'n':
   case 'N':
    allow_skipping=1;
    return(0);
   case 'o':
   case 'O':
    overwrite_existing=1;
    return(0);
   case 't':
   case 'T':
    test_mode=1;
    return(0);
   case '*':
    return(0);
   default:
    return(1);
  }
 }
 else
 {
  if(dest_dir[0]!='\0'||strchr(pathsep_sfxjr, arg[strlen(arg)-1])==NULL)
   return(1);
  dest_dir=arg;
 }
 return(0);
}

/* ARJSFXJR allows comment preprocessing, too... */

static char *preprocess_comment(char *comment)
{
 int arg_rc;
 char ctr;
 char *aptr, *endptr;

 if(comment[0]==')'&&comment[1]==')')
 {
  comment+=2;
  arg_rc=0;
  aptr=cmd_args;
  for(ctr=1; ctr<sizeof(cmd_args)&&*comment!='\0'&&*comment!='}'; ctr++)
  {
   *aptr=*comment;
   if(*aptr==' ')
    *aptr='\0';
   comment++;
   aptr++;
  }
  *aptr='\0';
  endptr=aptr;
  aptr=cmd_args;

  while((endptr-aptr)>0)
  {
   while(*aptr=='\0')
    aptr++;
   if((endptr-aptr)>0)
   {
    arg_rc=analyze_arg(aptr);
    while(*aptr!='\0'&&(endptr-aptr)>0)
     aptr++;
   }
  }
  if(arg_rc)
   error(M_INVALID_SWITCH);
  if(*comment=='\n')
   comment++;
 }
 return(comment);
}

/* SFX opening routine */

static void process_archive()
{
 char *cmt_ptr;
 char numfiles[10];

 if((aistream=_open(archive_name, O_BINARY|O_RDONLY))<0)
 {
  sfxjr_puts(M_CANTOPEN);
  sfxjr_puts((FMSG *)archive_name);
  nputlf();
  exit(ARJSFXJR_ERL_FATAL);
 }
 sfxjr_puts(M_PROCESSING_ARCHIVE);
 sfxjr_puts((FMSG *)archive_name);
 nputlf();
 find_sfx_header();
 get_reg_id();
 if(reg_id!=REG_ID)
  reg_id=0;
 if(!read_header())
  error(M_BAD_HEADER);
 cmt_ptr=comment;
 if(st_argc==1)
  cmt_ptr=preprocess_comment(cmt_ptr);
 sfxjr_puts((FMSG *)cmt_ptr);
 while(read_header())
  if(unpack_file())
   total_files++;
 numtostr(total_files, numfiles);
 /* German NLS fix -- ASR 12/10/2000 */
 #if LOCALE==LANG_de
  sfxjr_puts(numfiles);
  sfxjr_puts(M_FILES);
  sfxjr_puts(M_EXTRACTED);
 #else
  sfxjr_puts(M_EXTRACTED);
  sfxjr_puts(numfiles);
  sfxjr_puts(M_FILES);
 #endif
 nputlf();
 _close(aistream);
}

/* Ctrl+Break handler */

#if COMPILER==BCC
static int ctrlc_handler()
#else
static void ctrlc_handler(int sig)
#endif
{
 sfxjr_puts(M_BREAK_SIGNALED);
 exit(ARJSFXJR_ERL_FATAL);
 #if COMPILER==BCC
  return(0);
 #endif
}

/* Pre-exit cleanup routine */

static void final_cleanup(void)
{
 if(atstream!=0)
  _close(atstream);
 if(unpack_in_progress)
  unlink(filename);
}

/* Main routine */

int main(int argc, char **argv)
{
 int arg_rc;
 unsigned int i;

 st_argc=argc;
 arg_rc=0;
 for(i=1; i<argc; i++)
  arg_rc=analyze_arg(argv[i]);
 sfxjr_puts(M_ARJSFX_BANNER);
 nputlf();
 if(arg_rc)
  error(M_INVALID_SWITCH);
 build_crc32_table();
 #ifndef SKIP_GET_EXE_NAME
  get_exe_name(archive_name);
 #else
  get_exe_name(archive_name, argv[0]);
 #endif
 atexit(final_cleanup);
 #if COMPILER==BCC
  ctrlbrk(ctrlc_handler);
 #else
  signal(SIGINT, ctrlc_handler);
 #endif
 process_archive();
 if(errors!=0)
  error(M_FOUND_ERRORS);
 return((warnings>0)?ARJSFXJR_ERL_ERROR:ARJSFXJR_ERL_SUCCESS);
}

/* Creates a table for decoding */

static void NEAR make_table(int nchar, unsigned char *bitlen, int tablebits, unsigned short *table, int tablesize)
{
 unsigned short count[17], weight[17], start[18];
 unsigned short *p;
 unsigned int i, k, len, ch, jutbits, avail, nextcode, mask;

 for(i=1; i<=16; i++)
  count[i]=0;
 for(i=0; (int)i<nchar; i++)
  count[bitlen[i]]++;
 start[1]=0;
 for(i=1; i<=16; i++)
  start[i+1]=start[i]+(count[i]<<(16-i));
 if(start[17]!=(unsigned short)(1<<16))
  error(M_BADTABLE);
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
     error(M_BADTABLE);
    for(i=start[len]; i<nextcode; i++)
     table[i]=ch;
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
      *p=avail++;
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
  c=getbits(nbit);
  for(i=0; i<nn; i++)
   pt_len[i]=0;
  for(i=0; i<PTABLESIZE; i++)
   pt_table[i]=c;
 }
 else
 {
  i=0;
  if(n>=NPT)                            /* ASR fix to prevent overrun */
   n=NPT;
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
  make_table(nn, pt_len, 8, pt_table, sizeof(pt_table));
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
     c=getbits(4)+3;
    else
     c=getbits(CBIT)+20;
    while(--c>=0)
     c_len[i++]=0;
   }
   else
    c_len[i++]=(unsigned char)(c-2);
  }
  while(i<NC)
   c_len[i++]=0;
  make_table(NC, c_len, 12, c_table, sizeof(c_table));
 }
}

/* Decodes a single character */

static unsigned short decode_c()
{
 unsigned short j, mask;

 if(blocksize==0)
 {
  blocksize=getbits(16);
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
   j=(bitbuf&mask)?right[j]:left[j];
   mask>>=1;
  } while(j>=NC);
 }
 fillbuf((int)(c_len[j]));
 return(j);
}

/* Decodes a pointer to already decoded data */

static unsigned short decode_p()
{
 unsigned short j, mask;

 j=pt_table[bitbuf>>8];
 if(j>=NP)
 {
  mask=1<<7;
  do
  {
   j=(bitbuf&mask)?right[j]:left[j];
   mask>>=1;
  } while(j>=NP);
 }
 fillbuf((int)(pt_len[j]));
 if(j!=0)
 {
  j--;
  j=(1<<j)+getbits((int)j);
 }
 return(j);
}

/* Initiates the decoding */

static void decode_start()
{
 blocksize=0;
 init_getbits();
}

/* Decodes the entire file */

static void decode()
{
 short i;
 short r;
 short c;
 static short j;
 unsigned long count;

 decode_start();
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
    sfxjr_puts(M_SFXJR_TICKER);
    fwrite_crc(dec_text, DICSIZ);
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
      sfxjr_puts(M_SFXJR_TICKER);
      fwrite_crc(dec_text, DICSIZ);
     }
     if(++i>=DICSIZ)
      i=0;
    }
   }
  }
 }
 if(r>0)
  fwrite_crc(dec_text, r);
}
