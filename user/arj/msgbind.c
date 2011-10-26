/*
 * $Id: msgbind.c,v 1.6 2004/04/17 11:39:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file creates the  message files  for all ARJ modules. It  is essential
 * that it does not make use of any  ARJ modules (MISC.C and so on) because it
 * is the first file of the project.
 *
 */

/* We need to manually include the needed files because ARJ.H may contain
   references to missing message header files */

#include "environ.h"
#include "defines.h"
#include "filemode.h"
#include "misc.h"
#include "crc32.h"
#include "arjdata.h"

#include <ctype.h>
#include <signal.h>
#include <time.h>

#define MSG_SIZE               32752    /* Constant msg buffer size */
#define POOL_SIZE              51200    /* Maximum size of variable-len buf */
#define POOL_R_INC              1024    /* Realloc incrementation */
#define COLUMNS                   79    /* Columns per line in I*.* */

static char msgpool[32];       /* {MSGPOOL} or {HARDERR}   */
static char msgname[40];       /* {MSG_OUT_OF_MEM} */
static char targets[128];      /* {ARJ, ARJSFXV, ARJSFXJR} */
static char systems[128];      /* {DOS, OS2, WIN32, UNIX} */
static char bindings[16];      /* {S, C, or none (means ANY} */
static char locales[32];       /* {en, ru} */
static char msgtype[8];        /* {N} or {F}, for NMSG/FMSG, respectively */
static char rdir[FILENAME_MAX];/* Resource directory */

static char M_FMSG[]="FMSG";
static char M_NMSG[]="char";

static char INCL[]="#include \"bindings.h\"\n#include \"environ.h\"\n#include \"arjtypes.h\"\n\n";

static char SKIP[]="NULL";

struct pool
{
 char name[32];
 unsigned int msgs;
 char *data;
 char st_class;
 unsigned int safesize;
 unsigned int columns;
 unsigned int indent;
 unsigned long crc32;
};

/* A Q&D emulation of the strupr() and strlwr() for those who don't have it */

#ifndef HAVE_STRLWR
static char *strlwr(char *str)
{
 char *p;

 for(p=str; *p!='\0'; p++)
  *p=tolower(*p);
 return(str);
}
#endif

#ifndef HAVE_STRUPR
static char *strupr(char *str)
{
 char *p;

 for(p=str; *p!='\0'; p++)
  *p=toupper(*p);
 return(str);
}
#endif

/* Remove given characters */

char *compress(char *i, char f)
{
 int c, d;
 for(c=d=0; i[c]!='\0'; c++)
 {
  if(i[c]!=f)
   i[d++]=i[c];
 }
 i[d]='\0';
 return(i);
}

/* Strip all leading spaces */

char *ltrim(char *i)
{
 if (i!=NULL)
 {
  unsigned int c, j;
  for (c=0; i[c]==' '||i[c]=='\x9'; c++);
  if (i[c]!=(char)0)
  {
   for (j=0; i[c]!='\0'; j++)
   {
    i[j]=i[c]; c++;
   }
   i[j]=(char)0;
  }
 }
 return i;
}

/* Strip all trailing spaces */

char *rtrim(char *i)
{
 if (i!=NULL)
 {
  unsigned int c, j;
  j=0;
  for (c=0; i[c]!='\0'; c++) if (i[c]!=' '&&i[c]!='\x9') j=c+1;
  i[j]='\0';
 }
 return i;
}

/* Transform "\n", "\r", "\a" and "\b" characters to the corresponding ASCII
   equivalents */

void patch_string(char *i)
{
 int c, j;

 if (i!=NULL)
 {
  for(c=0; i[c]!='\0'; c++)
  {
   if(i[c]=='\\')
   {
    switch(i[c+1])
    {
     case 'a':
      i[c]='\a';
      break;
     case 'b':
      i[c]='\b';
      break;
     case 'f':
      i[c]='\f';
      break;
     case 'n':
      i[c]='\n';
      break;
     case 'r':
      i[c]='\r';
      break;
     case 't':
      i[c]='\t';
      break;
     case 'v':
      i[c]='\v';
      break;
     case '\"':
      i[c]='\"';
      break;
     case '\\':
      i[c]='\\';
      break;
    }
    for(j=c+1; i[j]!='\0'; j++)
     i[j]=i[j+1];
   }
  }
 }
}

/* Get one phrase in brackets */

char *read_brackets(FILE *file, char *buf, int size, int keep)
{
 int c, offset;

 /* Until the left one has been met... */
 while((c=fgetc(file))!=(int)'{')
  if(c==-1) return(NULL);
 /* Now fill the buffer */
 if(keep)
 {
  offset=1;
  buf[0]='{';
 }
 else
  offset=0;
 while((c=fgetc(file))!=(int)'}')
 {
  if(c==-1) return(NULL);
  if(offset<size-1-keep) buf[offset++]=(char)c;
 }
 if(keep)
  buf[offset++]='}';
 buf[offset]='\0';
 return(ltrim(rtrim(buf)));
}

/* Checks if the given parameter is present in the bracketed list. Returns
   parameter number (1...32767) or 0 => the parameter was not found. */

int is_in_brackets(char *brackets, char *param)
{
 const char *delimiters="{, ;}";
 int j, firstpos=1, inspace=0, count=0;
 int invert=0;

 for(j=1; brackets[j]!='\0'; j++)
 {
  while(brackets[firstpos]=='!')
  {
   invert=!invert;
   firstpos++;
  }
  if(strchr(delimiters, brackets[j])!=NULL&&!inspace)
  {
   count++;
   inspace=1;
   if(memcmp(brackets+firstpos, param, j-firstpos)==0||brackets[firstpos]=='*')
    return(invert?0:count);
  }
  else if(strchr(delimiters, brackets[j])==NULL&&inspace)
  {
   inspace=0;
   firstpos=j;
  }
 }
 return(invert);
}

/* Fetch a quoted message from the brackets. The index given varies from 1
   to 32767. */

char *fetch_quotes(FILE *resfile, int index, char *buf, int size)
{
 int c, tc, offset, qcount=0, quoted=0;
 FILE *tstream;
 char t_name[FILENAME_MAX];
 int t_offset;

 /* Until the left one has been met... */
 while((c=fgetc(resfile))!=(int)'{')
  if(c==EOF)
   return(NULL);
 /* Now wait until we come to the closing bracket, or... */
 offset=0;
 while((c=fgetc(resfile))!=(int)'}')
 {
  if(c==EOF)
   return(NULL);
  /* Reference to external file (v 1.30+) */
  else if(c=='@'&&!quoted&&qcount%2==0)
  {
   qcount+=2;
   if(qcount==index*2)
   {
    strcpy(t_name, rdir);
    t_offset=strlen(t_name);
    while((tc=fgetc(resfile))!=EOF&&(isalnum(tc)||tc=='.'||tc=='_'||tc=='\\'||tc=='/'))
     t_name[t_offset++]=tc;
    t_name[t_offset]='\0';
    if((tstream=fopen(t_name, m_r))==NULL)
     printf("Malformed declaration: <%s>\n", t_name);
    else
    {
     buf[offset++]='\"';
     while((tc=fgetc(tstream))!=EOF)
     {
      switch(tc)
      {
       case '\n':
        buf[offset++]='\\';
        buf[offset++]='n';
        break;
       case '\a':
        buf[offset++]='\\';
        buf[offset++]='a';
        break;
       case '\b':
        buf[offset++]='\\';
        buf[offset++]='b';
        break;
       case '\"':
        buf[offset++]='\\';
        buf[offset++]='\"';
        break;
       case '\\':
        buf[offset++]='\\';
        buf[offset++]='\\';
        break;
       default:
        buf[offset++]=tc;
      }
     }
     buf[offset++]='\"';
     buf[offset]='\0';
     fclose(tstream);
     return(buf);
    }
   }
  }
  else if(c=='\"'&&!quoted)
  {
   if(++qcount==index*2)
   {
    buf[offset++]='\"';
    buf[offset]='\0';
    return(buf);
   }
  }
  quoted=c=='\\';
  if(offset<size-1&&qcount==index*2-1)
   buf[offset++]=(char)c;
 }
 return(NULL);
}

/* Fetch messages from the resource file, return NULL if EOF. */

char *get_msg(FILE *resfile, char *target, char *c_system, char binding, char *locale, char *buf, int size)
{
 int locale_offset;

 while(!feof(resfile))
 {
  if(read_brackets(resfile, msgpool, sizeof(msgpool), 0)==NULL||
     read_brackets(resfile, msgname, sizeof(msgname), 0)==NULL||
     read_brackets(resfile, targets, sizeof(targets), 1)==NULL||
     read_brackets(resfile, systems, sizeof(systems), 1)==NULL||
     read_brackets(resfile, bindings, sizeof(bindings), 0)==NULL||
     read_brackets(resfile, locales, sizeof(locales), 1)==NULL||
     read_brackets(resfile, msgtype, sizeof(msgtype), 0)==NULL)
   return(NULL);
  strlwr(targets);
  strlwr(systems);
  strlwr(bindings);
  strlwr(locales);
  strupr(msgtype);

  locale_offset=is_in_brackets(locales, locale);
  if(is_in_brackets(targets, target)&&is_in_brackets(systems, c_system)&&(bindings[0]=='\0'||strchr(bindings, binding)!=NULL)&&locale_offset)
  {
   if(fetch_quotes(resfile, locale_offset, buf, size)!=NULL)
    return(buf);
  }
  else
   read_brackets(resfile, buf, 0, 0);
 }
 return(NULL);
}

/* malloc */

void *malloc_msg(unsigned int size)
{
 void *p;
 if((p=malloc(size))==NULL)
 {
  printf("Out of memory!\r\n");
  exit(4);
 }
 return(p);
}

/* Add header to file */

void put_hdr(FILE *file, char *name, char *src)
{
 char buf[FILENAME_MAX];
 time_t cur_unixtime;
 struct tm *stm;

 cur_unixtime=time(NULL);
 stm=localtime(&cur_unixtime);
 strcpyn(buf, name, sizeof(buf));
 strupr(buf);
 fprintf(file, "/*\n"
          " * %-29s, %04u/%02u/%02u\n"
          " * ---------------------------------------------------------------------------\n"
          " * Do not modify this file. It is automatically generated by MSGBIND from\n"
          " * %s.\n"
          " * To rebuild the language resources, run MSGBIND.\n"
          " *\n"
          " */\n\n", buf, (unsigned int)stm->tm_year+1900, stm->tm_mon+1, stm->tm_mday, strupr(src));
}

/* And so we begin... */

int main(int argc, char **argv)
{
 char source[FILENAME_MAX];             /* ReSource filename */
 char target_i[FILENAME_MAX];           /* .C-file containing pointers */
 char target_n[FILENAME_MAX];           /* All NMSGs */
 char target_f[FILENAME_MAX];           /* All FMSGs */
 char target_h[FILENAME_MAX];           /* Include file - all NMSGs/FMSGs */
 char target[FILENAME_MAX], locale[15];
 char c_system[32];
 char binding;
 char *msg_buffer;                      /* Messages may be large enough... */
 struct pool pool[32];                  /* Up to 32 separate msg arrays */
 int tpool, cur_pool=0, i;
 int buf_len;
 FILE *resfile, *ifile, *nfile, *ffile, *hfile;
 char pathsep[2];

 printf("MSGBIND v 1.65  [14/12/2002]  Not a part of any binary package!\n\n");
 if(argc<6)
 {
  printf("Usage: MSGBIND <resource> <target> <OS> <binding> <locale> [target directory],\n"
         "       e.g, to build MSG_SFXV.*, type MSGBIND MSG.RES MSG_SFXV DOS en\n"
         "\n"
         "The target directory is optional. If specified (e.g., BINARIES\\ENGLISH), all\n"
         "compiled .C files will be placed there.\n");
  exit(1);
 }
 msg_buffer=(char *)malloc_msg(MSG_SIZE);
 build_crc32_table();
 pathsep[0]=PATHSEP_DEFAULT;
 pathsep[1]='\0';
 strcpyn(source, argv[1], sizeof(source)-8);
 /* Fix for GCC/EMX: convert UNIX-like representations to DOS */
#if PATHSEP_UNIX!=PATHSEP_DEFAULT
 for(i=0; source[i]!='\0'; i++)
  if(source[i]==PATHSEP_UNIX)
   source[i]=PATHSEP_DEFAULT;
#endif
 if(strrchr(source, PATHSEP_DEFAULT)==NULL)
  rdir[0]='\0';
 else
 {
  strcpy(rdir, source);
  strrchr(rdir, PATHSEP_DEFAULT)[1]='\0';
 }
 strcpyn(target, argv[2], sizeof(target)-8);
 strcpyn(c_system, argv[3], sizeof(c_system));
 binding=tolower(argv[4][0]);
 /* Beginning with v 1.21, target directory may be also specified */
 if(argc==7)
 {
  strcpyn(target_i, argv[6], sizeof(target_i)-8);
  strcpyn(target_n, argv[6], sizeof(target_n)-8);
  strcpyn(target_f, argv[6], sizeof(target_f)-8);
  strcpyn(target_h, argv[6], sizeof(target_f)-8); /* v 1.41+ */
  if(argv[6][strlen(argv[6])-1]!=PATHSEP_DEFAULT);
  {
   strcat(target_i, pathsep);
   strcat(target_n, pathsep);
   strcat(target_f, pathsep);
   strcat(target_h, pathsep);
  }
 }
 else
 {
  target_i[0]='\0';
  target_n[0]='\0';
  target_f[0]='\0';
  target_h[0]='\0';
 }
 strcat(target_i, "i");
 strcat(target_n, "n");
 strcat(target_f, "f");
 strcat(target_i, argv[2]);
 strcat(target_n, argv[2]);
 strcat(target_f, argv[2]);
 strcat(target_h, argv[2]);
 /* The source has the extension .MSG, the targets are .H and .C */
 if(strchr(source, '.')==NULL)
  strcat(source, ".msg");
 strcat(target_i, ".c");
 strcat(target_n, ".c");
 strcat(target_f, ".c");
 strcat(target_h, ".h");
 strcpyn(locale, argv[5], sizeof(locale));
 strlwr(target);
 strlwr(c_system);
 strlwr(locale);
 /* Block out all signals, since this transaction is mission-critical */
 signal(SIGINT, SIG_IGN);
 #ifndef NO_TERM_HDL
  signal(SIGTERM, SIG_IGN);
 #endif
 if((resfile=fopen(source, m_r))==NULL)
 {
  printf("Can't open source file!\n");
  exit(2);
 }
 if((ifile=fopen(target_i, m_w))==NULL)
 {
  printf("Can't open index file!\n");
  exit(3);
 }
 if((nfile=fopen(target_n, m_w))==NULL)
 {
  printf("Can't open NMSG output file!\n");
  exit(3);
 }
 if((ffile=fopen(target_f, m_w))==NULL)
 {
  printf("Can't open FMSG output file!\n");
  exit(3);
 }
 if((hfile=fopen(target_h, m_w))==NULL)
 {
  printf("Can't open .h output file!\n");
  exit(3);
 }
 put_hdr(ifile, target_i, source);
 put_hdr(nfile, target_n, source);
 put_hdr(ffile, target_f, source);
 put_hdr(hfile, target_h, source);
 fputs(INCL, ifile);
 fputs(INCL, nfile);
 fputs(INCL, ffile);
 fprintf(ifile, "#include \"");
 for(i=0; target_h[i]!='\0'; i++)
  fputc(target_h[i]=='\\'?'/':target_h[i], ifile);
 fprintf(ifile, "\"\n\n");
 /* Ack. Now process the source file line by line... */
 while(get_msg(resfile, target, c_system, binding, locale, msg_buffer, MSG_SIZE)!=NULL)
 {
  expand_tags(msg_buffer, MSG_SIZE);
  fprintf(toupper(msgtype[0])=='N'?nfile:ffile, "char %s[]=%s;\n", msgname, msg_buffer);
  fprintf(hfile, "extern %s %s[];\n", toupper(msgtype[0])=='N'?M_NMSG:M_FMSG, msgname);
  /* Check if the message belongs to a pre-defined message pool */
  if(strcmp(msgpool, SKIP))
  {
   /* Pick a message heap */
   for(tpool=0; tpool<cur_pool; tpool++)
   {
    if(!strcmp(pool[tpool].name, msgpool))
     break;
   }
   /* Allocate new heap if needed */
   if(tpool==cur_pool)
   {
    if(cur_pool>=sizeof(pool))
    {
     printf("Too many message groups!\n");
     exit(4);
    }
    strcpy(pool[tpool].name, msgpool);
    pool[tpool].msgs=0;
    pool[tpool].crc32=CRC_MASK;
    pool[tpool].safesize=POOL_R_INC;
    pool[tpool].data=(char *)malloc_msg(POOL_R_INC);
    pool[tpool].st_class=toupper(msgtype[0])=='N'?'N':'F';
    sprintf(pool[tpool].data, "%cMSGP %s []={", pool[tpool].st_class, msgpool);
    pool[tpool].columns=pool[tpool].indent=strlen(pool[tpool].data);
    cur_pool++;
   }
   pool[tpool].msgs++;
   if(strlen(pool[tpool].data)+strlen(msgname)+pool[tpool].indent+16>pool[tpool].safesize)
   {
    if((pool[tpool].safesize+=POOL_R_INC)>POOL_SIZE)
    {
     printf("Message pool for %s exceeded %u bytes, exiting\n", msgpool, POOL_SIZE);
    }
    if((pool[tpool].data=realloc(pool[tpool].data, pool[tpool].safesize))==NULL)
    {
     printf("Unexpected lack of memory!r\n");
     exit(5);
    }
   }
   if((pool[tpool].columns+=strlen(msgname))>COLUMNS)
   {
    strcat(pool[tpool].data, "\n");
    pool[tpool].columns=pool[tpool].indent;
    pool[tpool].data[strlen(pool[tpool].data)+pool[tpool].indent]='\0';
    memset(pool[tpool].data+strlen(pool[tpool].data), 32, pool[tpool].indent);
   }
   strcat(pool[tpool].data, msgname);
   strcat(pool[tpool].data, ", ");
   strcpy(msg_buffer, msg_buffer+1);
   buf_len=strlen(msg_buffer);
   msg_buffer[--buf_len]='\0';
   patch_string(msg_buffer);
   crc32term=pool[tpool].crc32;
   crc32_for_string(msg_buffer);
   pool[tpool].crc32=crc32term;
  }
 }
 fputs("\n", hfile);
 /* First, flush the message pools... */
 for(tpool=0; tpool<cur_pool; tpool++)
 {
  strcat(pool[tpool].data, "NULL};\n\n");
  fputs(pool[tpool].data, ifile);
  free(pool[tpool].data);
  /* ...by the way, flushing the CRC-32 values */
  fprintf(hfile, "#define %s_CRC32 0x%08lx\n", pool[tpool].name, pool[tpool].crc32);
  fprintf(hfile, "extern %cMSGP %s[];\n", pool[tpool].st_class, pool[tpool].name);
 }
 /* Now, put an ending LF to all files */
 fputs("\n", ifile); fputs("\n", nfile); fputs("\n", ffile); fputs("\n", hfile);
 fclose(ifile); fclose(nfile); fclose(ffile); fclose(hfile);
 free(msg_buffer);
 return(0);                            /* Report no error */
}
