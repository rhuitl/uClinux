/*
 * $Id: fardata.c,v 1.6 2004/04/17 11:39:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file contains routines dealing with far data segment and CRC.
 *
 */

#include "arj.h"
#ifdef TILED
#include <dos.h>                        /* Weird, eh? */
#endif

/* ASR fix 02/05/2003: need that regardless of COLOR_OUTPUT to support -jp
   correctly */
#if SFX_LEVEL>=ARJ
 #define CUSTOM_PRINTF
 #define CHUNK_SIZE               512    /* Size of the output block */
 #define CHUNK_THRESHOLD (CHUNK_SIZE-256) /* Safety bound */
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

#ifdef CUSTOM_PRINTF

/* Forward Declaration */

int vcprintf(int ccode, FMSG *fmt, va_list args);

#endif

#if SFX_LEVEL>=ARJ

/* Checks if the error can have an error code or not */

static int is_std_error(FMSG *errmsg)
{
 return(errmsg==M_DISK_FULL||errmsg==M_CANT_DELETE||errmsg==M_CANTOPEN||
        errmsg==M_CANTRENAME||errmsg==M_CANTREAD||errmsg==M_CANT_DELETE||
        errmsg==M_CANT_COPY_TEMP)?1:0;
}

#endif

/* Makes various cleanup depending on the error message received and quits. */

int error_proc(FMSG *errmsg, ...)
{
 char *tmp_errmsg;
 va_list marker;

 #if SFX_LEVEL>=ARJ
  /* Check if the message could have a standard error code */
  if(errno!=0&&is_std_error(errmsg))
  {
   msg_cprintf(0, lf);
   error_report();
  }
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(quiet_mode==ARJ_SILENT)
   freopen(dev_con, m_w, stdout);
 #endif
 #if SFX_LEVEL>=ARJ
  file_settype(stdout, ARJT_TEXT);
 #endif
 /* For SFX archives, don't forget to display our logo */
 #if SFX_LEVEL==ARJSFXV
  show_sfx_logo();
 #elif SFX_LEVEL==ARJSFX
  if(!logo_shown)
  {
   msg_cprintf(0, M_ARJSFX_BANNER, exe_name);
   msg_cprintf(0, M_PROCESSING_ARCHIVE, archive_name);
  }
 #endif
 #if SFX_LEVEL>=ARJ
  nputlf();
 #elif SFX_LEVEL>=ARJSFXV
  fputc(LF, new_stdout);
 #else
  fputc(LF, stdout);
 #endif
 /* Format and print the error message */
 va_start(marker, errmsg);
 #ifdef CUSTOM_PRINTF
  vcprintf(H_ERR, errmsg, marker);
 #else
  tmp_errmsg=malloc_fmsg(errmsg);
  #if SFX_LEVEL>=ARJSFXV
   vfprintf(new_stdout, (FMSG *)tmp_errmsg, marker);
  #else
   vprintf(tmp_errmsg, marker);
  #endif
  free_fmsg(tmp_errmsg);
 #endif
 va_end(marker);
 #if SFX_LEVEL>=ARJ
  nputlf();
 #elif SFX_LEVEL>=ARJSFXV
  fputc(LF, new_stdout);
 #else
  fputc(LF, stdout);
 #endif
 /* Terminate the execution with a specific errorlevel */
 #if SFX_LEVEL>=ARJSFXV
  /* If there's no errorlevel yet, select errorlevel by message class */
  if(errorlevel==0)
   errorlevel=subclass_errors(errmsg);
  /* If the error was the lack of memory, display final memory statistics to
     find memory leaks */
  #if SFX_LEVEL>=ARJ
   if(errorlevel==ARJ_ERL_NO_MEMORY)
    mem_stats();
  #endif
  error_occured=1;
  exit(errorlevel);
 #elif defined(REARJ)
  exit(REARJ_ERL_WARNING);
 #elif defined(REGISTER)
  exit(REGISTER_ERL_ERROR);
 #elif SFX_LEVEL>=ARJSFX
  exit(ARJSFX_ERL_ERROR);
 #else
  exit(1);
 #endif
 return(0);
}

#ifdef FMSG_ST

/* A printf() function for far strings */

int msg_printf(FMSG *fmt, ...)
{
 va_list marker;
 char *storage;
 int result;

 storage=malloc_far_str(fmt);
 va_start(marker, fmt);
 result=vfprintf(new_stdout, (FMSG *)storage, marker);
 va_end(marker);
 free(storage);
 return(result);
}

/* A fprintf() function for far strings */

int msg_fprintf(FILE *stream, FMSG *fmt, ...)
{
 va_list marker;
 char *storage;
 int result;

 storage=malloc_far_str(fmt);
 va_start(marker, fmt);
 result=vfprintf(stream, storage, marker);
 va_end(marker);
 free(storage);
 return(result);
}

/* A sprintf() function for far strings */

int msg_sprintf(char *str, FMSG *fmt, ...)
{
 va_list marker;
 char *storage;
 int result;

 storage=malloc_far_str(fmt);
 va_start(marker, fmt);
 result=vsprintf(str, storage, marker);
 va_end(marker);
 free(storage);
 return(result);
}

#endif

#ifdef CUSTOM_PRINTF

/*
 * A Q&D custom printf() implementation. Derived from:
 *
 * vsprintf.c -- Lars Wirzenius & Linus Torvalds.
 * Wirzenius wrote this portably, Torvalds f*cked it up :-)
 *
 */

/* Length-limited strlen() */

static int strnlen(const char FAR *s, int count)
{
 const char FAR *sc;

 for(sc=s; *sc!='\0'&&count--; ++sc)
  ;
 return(sc-s);
}

/* Hex representation of digits */

static char adigit(unsigned long n, int is_uc)
{
 if(n<10)
  return('0'+n);
 n-=10;
 return((is_uc?'A':'a')+n);
}

/* Q'n'D strtoul() implementation */

unsigned long simple_strtoul(const FMSG *cp, FMSG **endp, unsigned int base)
{
 unsigned long result=0, value;

 if(!base)
 {
  base=10;
  if(*cp=='0')
  {
   base=8;
   cp++;
   if((*cp=='x')&&isxdigit(cp[1]))
   {
    cp++;
    base=16;
   }
  }
 }
 while(isxdigit(*cp)&&(value=isdigit(*cp)?
                       *cp-'0':
                       (islower(*cp)?toupper(*cp):*cp)-'A'+10)<base)
 {
  result=result*base+value;
  cp++;
 }
 if(endp)
  *endp=(FMSG *)cp;
 return(result);
}

/* Convert digits and skip over them */

static int skip_atoi(FMSG **s)
{
 int i=0;

 while(isdigit(**s))
  i=i*10+*((*s)++)-'0';
 return(i);
}

#define ZEROPAD                    1    /* pad with zero */
#define SIGN                       2    /* unsigned/signed long */
#define PLUS                       4    /* show plus */
#define SPACE                      8    /* space if plus */
#define LEFT                      16    /* left justified */
#define SPECIAL                   32    /* 0x */
#define LARGE                     64    /* use 'ABCDEF' instead of 'abcdef' */
#define FAR_STR                  128    /* Far strings (Fs) */

/* Number representation routine */

static int number(char *istr, long num, int base, int size, int precision, int type)
{
 char c, sign, tmp[66];
 int i;
 int ucase_dig=0;
 char *str;

 str=istr;
 if(type&LARGE)
  ucase_dig=1;
 if(type&LEFT)
  type&=~ZEROPAD;
 if(base<2||base>36)
  return(0);
 c=(type&ZEROPAD)?'0':' ';
 sign=0;
 if(type&SIGN)
 {
  if(num<0)
  {
   sign='-';
   num=-num;
   size--;
  }
  else if(type&PLUS)
  {
   sign='+';
   size--;
  }
  else if(type&SPACE)
  {
   sign=' ';
   size--;
  }
 }
 if(type&SPECIAL)
 {
  if(base==16)
   size-=2;
  else if(base==8)
   size--;
 }
 i=0;
 if(num==0)
  tmp[i++]='0';
 else while (num!=0)
 {
  unsigned long __res;

  __res=((unsigned long)num)%(unsigned long)base;
  num=((unsigned long)num)/(unsigned long)base;
  tmp[i++]=adigit(__res, ucase_dig);
 }
 if(i>precision)
  precision=i;
 size-=precision;
 if(!(type&(ZEROPAD+LEFT)))
 {
  while(size-->0)
   *str++=' ';
 }
 if(sign)
  *str++=sign;
 if(type&SPECIAL)
 {
  if(base==8)
   *str++='0';
  else if(base==16)
  {
   *str++='0';
   *str++=ucase_dig?'X':'x';
  }
 }
 if(!(type&LEFT))
 {
  while(size-->0)
   *str++=c;
 }
 while(i<precision--)
  *str++='0';
 while(i-->0)
  *str++=tmp[i];
 while(size-->0)
  *str++=' ';
 return(str-istr);
}

/* Flushes the output buffer downstream. The buffer gets clobbered. */

static void flush_cbuf(int ccode, char *text)
{
 char *n_text, *t_text;
 int need_pause, rc;
 char c;

 if(quiet_mode==ARJ_SILENT||(quiet_mode==ARJ_QUIET&&!(ccode&H_FORCE)))
  return;
 CLOBBER_SENTRY();
 need_pause=(prompt_for_more&&!yes_on_all_queries&&!print_with_more);
 n_text=t_text=text;
#ifdef COLOR_OUTPUT
 if(!redirected&&!no_colors)
  textcolor(color_table[ccode&H_COLORMASK].color);
#endif
 while((c=*t_text)!='\0')
 {
  if(c==LF)
  {
   *t_text='\0';
   #ifdef COLOR_OUTPUT
    if(redirected)
    {
     #if SFX_LEVEL>=ARJSFXV
      fprintf(new_stdout, strform, n_text);
      fprintf(new_stdout, lf);
     #else
      printf(strform, n_text);
      printf(lf);
     #endif
    }
    else
    {
     scr_out(n_text);
     if(!no_colors)
      textcolor(7);
     #ifdef NEED_CRLF
      scr_out("\r");
     #endif
     scr_out(lf);
    }
    if(!no_colors)
     textcolor(color_table[ccode&H_COLORMASK].color);
   #else
    printf(strform, n_text);
    printf(lf);
   #endif
   n_text=t_text+1;
   #if SFX_LEVEL>=ARJ
    lines_scrolled++;
    if(lines_scrolled>=lines_per_page-1)
    {
     lines_scrolled=0;
     if(need_pause)
     {
      rc=pause();
      #ifdef COLOR_OUTPUT
       /* Restore the color after implicit recursion to msg_cprintf() */
       if(!no_colors)
        textcolor(color_table[ccode&H_COLORMASK].color);
      #endif
      if(!rc&&(ccode&H_WEAK))
       longjmp(main_proc, 1);
     }
    }
   #endif
  }
  t_text++;
 }
#ifdef COLOR_OUTPUT
 if(redirected)
  #if SFX_LEVEL>=ARJSFXV
   fprintf(new_stdout, strform, n_text);
  #else
   printf(strform, n_text);
  #endif
 else
  scr_out(n_text);
#else
 printf(strform, n_text);
#endif
}

/* vcprintf() implementation */

int vcprintf(int ccode, FMSG *fmt, va_list args)
{
 int len;
 unsigned long num;
 int i, base;
 char FAR *s;
 int flags;                             /* flags to number() */
 int field_width;                       /* width of output field */
 int precision;                         /* min. # of digits for integers; max
                                           number of chars for from string */
 int qualifier;                         /* 'h', 'l', or 'L' for integer
                                           fields */
 int far_str;                           /* Far string qualifier */
 char buf[CHUNK_SIZE];                  /* Output buffer */
 int p_buf;
 int rc=0;
 int ocode;                             /* Output color code for formatted
                                           fields (that's what the whole
                                           routine is about!) */
 long *ipl;
 int *ipi;
 int last_fmt=0;

 ocode=(ccode&H_NFMT)?H_STD:ccode;
 for(p_buf=0; *fmt; ++fmt)
 {
  if(last_fmt&&ccode&H_NFMT)
  {
   last_fmt=0;
   buf[p_buf]='\0';
   rc+=p_buf;
   p_buf=0;
   flush_cbuf(ocode, buf);
  }
  if(*fmt!='%'||*(fmt+1)=='%')
  {
   if(p_buf>=CHUNK_SIZE-1)
   {
    buf[p_buf]='\0';
    rc+=p_buf;
    p_buf=0;
    flush_cbuf(ccode, buf);
   }
   buf[p_buf++]=*fmt;
   if(*fmt=='%')
    ++fmt;                              /* Skip over the 2nd percent - we've handled
                                           it here */
   continue;
  }
  /* A format symbol is found - flush the buffer if:
     1. It's H_NFMT, so we need to change the brush, OR
     2. CHUNK_THRESHOLD has been exceeded (for numeric) */
  if(ccode&H_NFMT||p_buf>=CHUNK_THRESHOLD)
  {
   buf[p_buf]='\0';
   rc+=p_buf;
   p_buf=0;
   flush_cbuf(ccode, buf);
  }
  last_fmt=1;
  /* Process flags */
  flags=0;
  repeat:
  ++fmt;                                /* This also skips first '%' */
  switch(*fmt)
  {
   case '-': flags|=LEFT; goto repeat;
   case '+': flags|=PLUS; goto repeat;
   case ' ': flags|=SPACE; goto repeat;
   case '#': flags|=SPECIAL; goto repeat;
   case '0': flags|=ZEROPAD; goto repeat;
   case 'F': flags|=FAR_STR; goto repeat;
  }
  /* Get field width */
  field_width=-1;
  if(isdigit(*fmt))
   field_width=skip_atoi((FMSG **)&fmt);
  else if(*fmt=='*')
  {
   ++fmt;
   /* It's the next argument */
   field_width=va_arg(args, int);
   if(field_width<0)
   {
    field_width=-field_width;
    flags|=LEFT;
   }
  }
  /* Get the precision */
  precision=-1;
  if(*fmt=='.')
  {
   ++fmt; 
   if(isdigit(*fmt))
    precision=skip_atoi((FMSG **)&fmt);
   else if(*fmt=='*')
   {
    ++fmt;
    /* It's the next argument */
    precision=va_arg(args, int);
   }
   if(precision<0)
    precision=0;
  }
  /* Get the conversion qualifier */
  qualifier=-1;
  if(*fmt=='h'||*fmt=='l'||*fmt=='L')
  {
   qualifier=*fmt;
   ++fmt;
  }
  /* Default base */
  base=10;
  switch(*fmt)
  {
   case 'c':
    if(!(flags&LEFT))
     while(--field_width>0)
      buf[p_buf++]=' ';
    buf[p_buf++]=(unsigned char)va_arg(args, int);
    while(--field_width>0)
     buf[p_buf++]=' ';
    continue;
   case 's':
    if(!(flags&FAR_STR))
     s=(char FAR *)va_arg(args, char NEAR *);
    else
     s=va_arg(args, char FAR *);
#ifdef DEBUG
    if(!s)
     s="(null)";
#endif
    len=strnlen(s, precision);
    if(!(flags&LEFT))
    {
     while(len<field_width--)
     {
      if(p_buf>=CHUNK_SIZE-1)
      {
       buf[p_buf]='\0';
       rc+=p_buf;
       p_buf=0;
       flush_cbuf(ocode, buf);
      }
      buf[p_buf++]=' ';
     }
    }
    for(i=0; i<len; ++i)
    {
     if(p_buf>=CHUNK_SIZE-1)
     {
      buf[p_buf]='\0';
      rc+=p_buf;
      p_buf=0;
      flush_cbuf(ocode, buf);
     }
     buf[p_buf++]=*s++;
    }
    while(len<field_width--)
    {
     if(p_buf>=CHUNK_SIZE-1)
     {
      buf[p_buf]='\0';
      rc+=p_buf;
      p_buf=0;
      flush_cbuf(ocode, buf);
     }
     buf[p_buf++]=' ';
    }
    continue;
   case 'p':
    if(field_width==-1)
    {
     field_width=2*sizeof(void *);
     flags|=ZEROPAD;
    }
    p_buf+=number(buf+p_buf, (unsigned long)va_arg(args, void *), 16,
                  field_width, precision, flags);
    continue;
   case 'n':
    if(qualifier=='l')
    {
     ipl=va_arg(args, long *);
     *ipl=p_buf;
    }
    else
    {
     ipi=va_arg(args, int *);
     *ipi=p_buf;
    }
    continue;
   /* Integer number formats - set up the flags and "break" */
   case 'o':
    base=8;
    break;
   case 'X':
    flags|=LARGE;
   case 'x':
    base=16;
    break;
   case 'd':
   case 'i':
    flags|=SIGN;
   case 'u':
    break;
   default:
    if(*fmt!='%')
     buf[p_buf++]='%';
    if(*fmt)
     buf[p_buf++]=*fmt;
    else
     --fmt;
    continue;
   }
   if(qualifier=='l')
    num=va_arg(args, unsigned long);
   else if(qualifier=='h')
   {
#ifdef __linux__
    if (flags&SIGN)
     num=va_arg(args, int);             /* num=va_arg(args, short);      */
    else
     num=va_arg(args, int);             /* num=va_arg(args, unsigned short);*/
#else
    if(flags&SIGN)
     num=va_arg(args, short);
    else
     num=va_arg(args, unsigned short);
#endif
   }
   else if(flags&SIGN)
    num=va_arg(args, int);
   else
    num=va_arg(args, unsigned int);
   p_buf+=number(buf+p_buf, num, base, field_width, precision, flags);
 }
 if(p_buf>0)
 {
  buf[p_buf]='\0';
  rc+=p_buf;
  flush_cbuf(last_fmt?ocode:ccode, buf);
 }
 return(rc);
}

#endif /* CUSTOM_PRINTF */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)

/* Helper routine for scrprintf() */

int msg_cprintf(int ccode, FMSG *fmt, ...)
{
 #ifndef CUSTOM_PRINTF
  char *storage;
 #endif
 va_list marker;
 int result;

 #ifndef CUSTOM_PRINTF
  #ifdef FMSG_ST
   storage=malloc_far_str(fmt);
  #else
   storage=fmt;
  #endif
 #endif
 va_start(marker, fmt);
 #if defined(CUSTOM_PRINTF)
  result=vcprintf(ccode, fmt, marker);
 #elif SFX_LEVEL>=ARJSFXV
  result=vfprintf(new_stdout, (FMSG *)storage, marker);
 #else
  result=vprintf(storage, marker);
 #endif
 va_end(marker);
 #if defined(FMSG_ST)&&!defined(CUSTOM_PRINTF)
  free(storage);
 #endif
 return(result);
}

#endif

#if SFX_LEVEL>=ARJSFX&&defined(TILED)

/* A model-independent movedata() function (it must go to ENVIRON.C) */

void far_memmove(char FAR *dest, char FAR *src, int length)
{
 movedata(FP_SEG(src), FP_OFF(src), FP_SEG(dest), FP_OFF(dest), length);
}

#endif

#if SFX_LEVEL>=ARJ

/* Initializes CRC32 subsystem (only used by main()) */

void init_crc()
{
 build_crc32_table();
}

/* Returns CRC32 for the given block */

void crc_for_block(char *block, unsigned int length)
{
 crc32_for_block(block, length);
}

/* Returns CRC32 for the given string */

void crc_for_string(char *str)
{
 crc32_for_string(str);
}

#endif

#ifdef COLOR_OUTPUT

/* Parse the color table */

int parse_colors(char *opt)
{
 int i, c;
 char *p;
 int rc=0;

 if(*opt=='\0')
 {
  no_colors=1;
  textcolor(7);                         /* HACK */
  return(0);
 }
 while(*opt!='\0')
 {
  for(p=opt; !isdigit(*p); p++)
  {
   if(*p=='\0')
   {
    opt=p;
    goto next_opt;
   }
  }
  c=atoi(p);
  if(c>=32)
   rc++;
  else
  {
   for(i=0; color_table[i].arg!='\0'||!(++rc); i++)
   {
    if(color_table[i].arg==tolower(*opt))
    {
     color_table[i].color=(char)c;
     break;
    }
   }
  }
  next_opt:
  while(*opt!='\0'&&!isdigit(*opt))
   opt++;
  while(*opt!='\0'&&(isdigit(*opt)||!isalpha(*opt)))
   opt++;
 }
 return(rc);
}

#endif
