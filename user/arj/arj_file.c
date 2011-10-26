/*
 * $Id: arj_file.c,v 1.9 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Various archive-management functions (mostly, file-related ones) are stored
 * here.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Character used in counters */
#if TARGET!=UNIX
 #define COUNTER_CHAR           0xB2
#else
 #define COUNTER_CHAR            '#'
#endif
#define UNDISP_CHAR              '?'    /* Replaces nonprintable characters */

/* Local variables */

static char reply_help[]="?";           /* Request for help */
#if SFX_LEVEL>=ARJ
static char ext_digits[]=".%03d";       /* Pattern used to serialize
                                           extensions */
#endif

/* Counter formatting sequences */

#if SFX_LEVEL>=ARJSFXV
static char del_single[]="\b\b\b\b\b";
static char del_double[]="\b\b\b\b\b\b\b\b\b\b";
static char sfmt_single[]="     %s";
static char sfmt_double[]="          %s";
static char sfmt_bytes[]="%10ld%s";
static char sfmt_start_graph[]="   0%%%s";
static char sfmt_numeric[]="%4d%%%s";
#if SFX_LEVEL>=ARJ
static char sfmt_start_num[]="   %d%%";
#if TARGET!=UNIX
static char sfmt_graph[]="þþþþþþþþþþ%s";
static char sfmt_mid_graph[]="þþþþþ%s";
#else
static char sfmt_graph[]="..........%s";
static char sfmt_mid_graph[]=".....%s";
#endif
static char sfmt_short_numeric[]="%4d%%";
#endif
#else
static char sfmt_sfx[]="%4d%%\b\b\b\b\b";
#endif

/* Local forward-referenced functions */

static int display_block(char *str, int len);
static int block_op(int action, char *block, int len);

#if SFX_LEVEL>=ARJSFXV

/* Closes the file given */

int file_close(FILE *stream)
{
 if(stream!=NULL)
  return(fclose(stream));
 else
  return(-1);
}

/* Opens a file, possibly clearing its FA_ARCH attribute (read-only modes are
   not affected) */

FILE *file_open_noarch(char *name, char *mode)
{
 FILE *stream;

#if TARGET!=UNIX
 if(clear_archive_bit&&(mode[0]=='w'||mode[0]=='a'||mode[1]=='+'||mode[2]=='+'))
  dos_chmod(name, STD_FATTR_NOARCH);
#endif
 if((stream=file_open(name, mode))==NULL)
  error(M_CANTOPEN, name);
 return(stream);
}

#endif

#if SFX_LEVEL>=ARJ

/* Overwrites a file, querying user if it exists */

FILE *file_create(char *name, char *mode)
{
 if(file_exists(name))
 {
  if(!yes_on_all_queries&&!overwrite_existing)
  {
   msg_cprintf(0, M_EXISTS, name);
   if(!query_action(REPLY_YES, QUERY_OVERWRITE, M_QUERY_OVERWRITE))
    error(M_CANTOPEN, name);
  }
#if TARGET!=UNIX
  if(clear_archive_bit&&(mode[0]=='w'||mode[0]=='a'||mode[1]=='+'||mode[2]=='+'))
   dos_chmod(name, STD_FATTR_NOARCH);
#endif
 }
 return(file_open(name, mode));
}

#endif

#ifndef REARJ

/* Reads a byte from the file */

int fget_byte(FILE *stream)
{
 int buffer;

 buffer=fgetc(stream);
 if(buffer==EOF)
 {
  if(ignore_archive_errors)
  {
   #if SFX_LEVEL>=ARJSFXV
    msg_cprintf(H_ERR, M_CANTREAD);
   #else
    msg_cprintf(H_ERR, M_CANTREAD);
   #endif
   return(0);
  }
  else
   error(M_CANTREAD);
 }
 return(buffer&0xFF);
}

/* Reads two bytes from the file */

unsigned int fget_word(FILE *stream)
{
 unsigned int b0, b1;

 b0=fget_byte(stream);
 b1=fget_byte(stream);
 return((b1<<8)|b0);
}

/* Reads four bytes from the file */

unsigned long fget_longword(FILE *stream)
{
 unsigned int w0, w1;

 w0=fget_word(stream);
 w1=fget_word(stream);
 return(((unsigned long)w1<<16)|(unsigned long)w0);
}

/* Reads a block from the file, updating CRC */

int fread_crc(char *buffer, int count, FILE *stream)
{
 int n;

 n=fread(buffer, 1, count, stream);
 if(n>0)
 {
  origsize+=(unsigned long)n;
  crc_for_block((char *)buffer, n);
 }
 return(n);
}

#endif

#if SFX_LEVEL>=ARJ

/* Writes a block, updating the CRC term */

void fwrite_crc(char *buffer, int count, FILE *stream)
{
 crc_for_block(buffer, count);
 if(stream!=NULL)
  file_write(buffer, 1, count, stream);
}

#endif

#ifndef REARJ

/* Processes the given block upon extraction. Returns a nonzero value if the
   extraction is to be terminated. */

int extraction_stub(char *block, int block_len, int action)
{
 char c;
 char *block_ptr;
 int cn;

 #if SFX_LEVEL>=ARJ
  if(!debug_enabled||strchr(debug_opt, 'c')==NULL)
   crc_for_block(block, block_len);
 #else
  crc32_for_block(block, block_len);
 #endif
 if(!file_packing)                      /* Not applicable for memory data */
 {
  if(encmem_limit<block_len)            /* Check for overrun */
   error(M_BAD_HEADER);
  encmem_limit-=block_len;
  far_memmove(encblock_ptr, (char FAR *)block, block_len);
  encblock_ptr+=block_len;
  encmem_remain+=block_len;
  return(0);
 }
 /* Postprocessing */
 #if SFX_LEVEL>=ARJ
  if(action==BOP_LIST||action==BOP_SEARCH||action==BOP_COMPARE||action==BOP_DISPLAY)
   return(block_op(action, block, block_len));
 #endif
 if(atstream==NULL)
  return(0);
 /* Strip high bit from files created by different OS */
 if(file_type==ARJT_TEXT&&host_os!=OS
 #if SFX_LEVEL>=ARJ
  &&type_override!=FT_BINARY
 #endif
 )
 {
  block_ptr=block;
  while(block_len-->0)
  {
   c=*(block_ptr++);
   c&=0x7F;
   if(fputc((int)c, atstream)==EOF)
    error(M_DISK_FULL);
  }
 }
 else
 {
  /* HACK for IBM LIBC implementations under 32-bit OS/2 */
  #if SFX_LEVEL>=ARJSFXV&&TARGET==OS2&&(COMPILER==ICC||defined(LIBC))
   int fn=fileno(atstream);

   if(fn<6)
   {
    _setmode(fn, file_type?0x4000:0x8000); /* O_TEXT:O_BINARY */
    cn=write(fn, block, block_len);
   }
   else
    cn=fwrite(block, 1, block_len, atstream);
  #else
   cn=fwrite(block, 1, block_len, atstream);
  #endif
  #if SFX_LEVEL>=ARJSFXV
   if(is_tty(atstream))
    cn=block_len;
  #endif
  if(cn!=block_len)
   error(M_DISK_FULL);
 }
 return(0);
}

/* Executed when decoding is initialized */

void decode_start_stub()
{
 #if SFX_LEVEL>=ARJ
  subbitbuf=0;
 #endif
 bitbuf=0;
 byte_buf=0;
 bitcount=0;
 fillbuf(CHAR_BIT*2);
 #if SFX_LEVEL>=ARJSFXV
  mem_stats();
 #endif
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Executed when the decoding memory variables are released */

void decode_end_stub()
{
 /* Currently empty, may contain debugging checks if needed. */
}

#endif

#if SFX_LEVEL>=ARJ

/* Finds an non-existent filename that matches the given format string. The
   format string must contain "%d" somewhere because the names are numbered. */

char *find_tmp_filename(char *name_format)
{
 char tmp_name[CCHMAXPATH];
 int i;

 for(i=0; i<=99; i++)
 {
  sprintf(tmp_name, name_format, i);
  if(!file_exists(tmp_name))
   return(strcpy(name_format, tmp_name));
 }
 error(M_CANTOPEN, name_format);
 return(0); /* not reached, avoid warning */
}

/* Creates an numeric extension to the name, returns -1 if failed */

int find_num_ext(char *name, int mode)
{
 char tmp_name[CCHMAXPATHCOMP];
 char tmp_ext[CCHMAXPATHCOMP];
 int name_offset;
 char *ext_offset;
 int ext_num;

 strcpy(tmp_name, name);
 name_offset=split_name(tmp_name, NULL, NULL);
 if((ext_offset=strchr(&tmp_name[name_offset], '.'))==NULL)
  strcat(tmp_name, ext_digits);
 else
 {
  strcpy(tmp_ext, ext_offset);          /* Remember the original extension */
  strcpy(ext_offset, ext_digits);       /* Substitute extension */
  if(mode==EXT_INSERT)
   strcat(tmp_name, tmp_ext);           /* Complete with original extension */
 }
 for(ext_num=0; ext_num<999; ext_num++)
 {
  sprintf(name, tmp_name, ext_num);
  if(!file_exists(name))
   return(0);
 }
 msg_cprintf(0, M_EXISTS, name);
 return(-1);
}

/* Treats filename as an ARCmail packet and finds a suitable name for it */

int find_arcmail_name(char *name)
{
 unsigned long counter;
 char *nptr;
 char c;

 for(counter=0L; counter<100000000L; counter++)
 {
  if((nptr=strchr(name+1, '.'))==NULL)
   nptr=name+strlen(name);
  nptr--;
  do
  {
   c=*nptr;
   if(!isdigit(c))
    c='0';
   else
    c++;
   if(c>'9')
   {
    *nptr='0';
    if(nptr==name)
    {
     msg_cprintf(0, M_RANGE_EXCEEDED, name);
     return(-1);
    }
    nptr--;
   }
   else
    *nptr=c;
  } while(c>'9');
  if(!file_exists(name))
   return(0);
 }
 msg_cprintf(0, M_EXISTS, name);
 return(-1);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Puts the given character to the console */

static int nputc(int c)
{
 msg_cprintf(0, (FMSG *)"%c", c);
 return(c);
}

#endif

#if SFX_LEVEL>=ARJ

/* Reads a command for execution from the stdin */

void query_cmd()
{
 char cmd[CMDLINE_LENGTH];

 msg_cprintf(0, M_COMMAND);
 read_line(cmd, sizeof(cmd));
 alltrim(cmd);
 if(cmd[0]!='\0')
  exec_cmd(cmd);
}

#endif

/* Compares the first n characters of two MSG-strings (used exclusively by
   query_action_proc()) */

#if SFX_LEVEL>=ARJ

static int cmp_far_str(char FAR *str1, char FAR *str2, int length)
{
 int result;
 char *nstr1, *nstr2;

 nstr1=malloc_far_str(str1);
 nstr2=malloc_far_str(str2);
 result=strncmp(nstr1, nstr2, length);
 free(nstr1);
 free(nstr2);
 return(result);
}

#define msg_strncmp(str1, str2, length) cmp_far_str((char FAR *)str1, (char FAR *)str2, length)

#else
 #define msg_strncmp strncmp
#endif

/* Query routine - used exclusively by query_action() */

#if SFX_LEVEL>=ARJSFXV

static int query_action_proc(int def, int qtype, char *query)
{
 char reply_text[INPUT_LENGTH];
 int sel, key, ukey;
 char *sel_ptr, *rt_ptr;
 int rt_len;

 if(query!=NULL)
  msg_cprintf(H_PROMPT, (FMSG *)strform, query);
 #if SFX_LEVEL>=ARJ
  if(qtype!=QUERY_CRITICAL&&queries_assume_no[qtype])
  {
   msg_cprintf(H_OPER, M_NO);
   msg_cprintf(0, (FMSG *)lf);
   return(0);
  }
  if(qtype!=QUERY_CRITICAL&&queries_assume_yes[qtype])
  {
   msg_cprintf(H_OPER, M_YES);
   msg_cprintf(0, (FMSG *)lf);
   return(1);
  }
 #endif
 if(kbd_cleanup_on_input)
  fetch_keystrokes();
 #if SFX_LEVEL>=ARJ
  if(accept_shortcut_keys)
  {
   while(1)
   {
    do
    {
     while(1)
     {
      key=uni_getch();
      /* If possible default action selected */
      if(def!=0&&key==LF)
      {
       msg_cprintf(0, (FMSG *)lf);
       if(def==1)
        return(1);
       if(def==2)
        return(0);
      }
      ukey=toupper(key);
      far_strcpy(strcpy_buf, M_REPLIES);
      sel_ptr=strchr(strcpy_buf, ukey);
      sel=sel_ptr-strcpy_buf;
      if(ukey!=0&&sel_ptr!=NULL&&(qtype!=QUERY_CRITICAL||sel<=REPLY_QUIT))
       break;
      fetch_keystrokes();
      nputc(BEL);
     }
     nputc(key);
     msg_cprintf(0, (FMSG *)lf);
    } while(sel>MAX_REPLY);
    switch(sel)
    {
     case REPLY_YES:
      return(1);
     case REPLY_NO:
      return(0);
     case REPLY_QUIT:
      exit(ARJ_ERL_WARNING);
     case REPLY_ALL:
      if(qtype!=QUERY_CRITICAL)
       queries_assume_yes[qtype]=1;
      return(1);
     case REPLY_SKIP:
      if(qtype!=QUERY_CRITICAL)
       queries_assume_no[qtype]=1;
      return(0);
     case REPLY_GLOBAL:
      yes_on_all_queries=1;
      return(1);
     case REPLY_COMMAND:
      query_cmd();
      if(query!=NULL)
       msg_cprintf(H_PROMPT, (FMSG *)strform, query);
    }
   }
   /* There is no way down here */
  }
 #endif
 /* Use an editable field */
 while(1)
 {
  read_line(reply_text, INPUT_LENGTH);
  for(rt_ptr=reply_text; rt_ptr[0]==' '; rt_ptr++);
  if((rt_len=strlen(rt_ptr))>0)
  {
   strupper(rt_ptr);
   if(!msg_strncmp(rt_ptr, reply_help, rt_len))
   {
    far_strcpy(strcpy_buf, (qtype==QUERY_CRITICAL)?M_REPLIES_HELP:M_ALL_REPLIES_HELP);
    msg_cprintf(0, (FMSG *)strcpy_buf);
    continue;
   }
   else if(!msg_strncmp(rt_ptr, M_NO, rt_len))
    return(0);
   else if(!msg_strncmp(rt_ptr, M_YES, rt_len))
    return(1);
   else if(!msg_strncmp(rt_ptr, M_QUIT, rt_len))
    exit(1);
   else if(qtype!=QUERY_CRITICAL)
   {
    #if SFX_LEVEL>=ARJ
     if(!msg_strncmp(rt_ptr, M_ALWAYS, rt_len))
     {
      if(qtype!=QUERY_CRITICAL)
       queries_assume_yes[qtype]=1;
      return(1);
     }
     if(!msg_strncmp(rt_ptr, M_SKIP, rt_len))
     {
      if(qtype!=QUERY_CRITICAL)
       queries_assume_no[qtype]=1;
      return(0);
     }
    #endif
    if(!msg_strncmp(rt_ptr, M_GLOBAL, rt_len))
    {
     yes_on_all_queries=1;
     return(1);
    }
    #if SFX_LEVEL>=ARJ
     if(!msg_strncmp(rt_ptr, M_COMMAND, rt_len))
     {
      query_cmd();
      if(query!=NULL)
       msg_cprintf(H_PROMPT, (FMSG *)strform, query);
      continue;
     }
    #endif
   }
  }
  else
  {
   if(def==1)
    return(1);
   if(def==2)
    return(0);
  }
  fetch_keystrokes();
  nputc(BEL);
  msg_cprintf(0, M_REPLIES_HELP);
 }
}

#else

int query_action()
{
 #ifndef REARJ
  char buf[40];
 #else
  char buf[80];
 #endif
 char *buf_ptr;
 int sl, rc;
 char *fmsg_ptr;

 while(1)
 {
  read_line(buf, sizeof(buf));
  buf_ptr=buf;
  while(*buf_ptr==' ')
   buf_ptr++;
  if((sl=strlen(buf_ptr))!=0)
  {
   strupper(buf_ptr);
   fmsg_ptr=malloc_fmsg(M_NO);
   rc=strncmp(buf_ptr, fmsg_ptr, sl);
   free_fmsg(fmsg_ptr);
   if(!rc)
    return(0);
   fmsg_ptr=malloc_fmsg(M_YES);
   rc=strncmp(buf_ptr, fmsg_ptr, sl);
   free_fmsg(fmsg_ptr);
   if(!rc)
    return(1);
   #ifndef REARJ
    fmsg_ptr=malloc_fmsg(M_QUIT);
    rc=strncmp(buf_ptr, fmsg_ptr, sl);
    free_fmsg(fmsg_ptr);
    if(!rc)
     exit(ARJSFX_ERL_ERROR);
   #endif
  }
  msg_cprintf(0, M_REPLIES_HELP);
 }
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Standard procedure that queries user. Accepts the following parameters:
   - def=0 if no default action, or number of reply to be selected w/ENTER.
   - qtype is the standard query number to allow pre-selections.
   - query is the query text. */

int query_action(int def, int qtype, FMSG *query)
{
 #if SFX_LEVEL>=ARJ
  char *nquery;
  int result;
  FILE *tmp_stdout;

  if((tmp_stdout=new_stdout)==new_stderr)
   new_stdout=stderr;
  result=query_action_proc(def, qtype, nquery=malloc_fmsg(query));
  free(nquery);
  new_stdout=tmp_stdout;
  return(result);
 #else
  return(query_action_proc(def, qtype, query));
 #endif
}

/* Prompts the user to press ENTER */

int pause()
{
 char *tmp_query;
 FILE *tmp_stdout;
 int rc;

 if((tmp_stdout=new_stdout)==new_stderr)
  new_stdout=stderr;
 tmp_query=malloc_fmsg(M_PRESS_ENTER);
 rc=query_action_proc(1, QUERY_PRESS_ENTER, tmp_query);
 new_stdout=tmp_stdout;
 free(tmp_query);
 return(rc);
}

/* Puts a LF character to the stdout */

void nputlf()
{
 msg_cprintf(0, (FMSG *)lf);
}

#endif

#if SFX_LEVEL>=ARJ

/* Deletes files specified by the given wildcard. Returns 1 if no files were
   found to delete. */

int delete_files(char *name)
{
 char tmp_name[CCHMAXPATHCOMP];
 struct flist_root root;
 FILE_COUNT curfile;

 flist_init(&root, FCLIM_DELETION, FL_STANDARD);
 if(flist_add_files(&root, NULL, name, 1, 0, FETCH_FILES, NULL))
  return(1);
 for(curfile=0; curfile<root.files; curfile++)
 {
  flist_retrieve(tmp_name, NULL, &root, curfile);
  msg_cprintf(0, M_DELETING, tmp_name);
  if(is_directory(tmp_name)?file_rmdir(tmp_name):file_unlink(tmp_name))
   msg_cprintf(H_ERR, M_CANT_DELETE, tmp_name);
 }
 flist_cleanup(&root);
 return(0);
}

#endif

#ifndef REARJ

/* Displays the given comment string */

#if SFX_LEVEL>=ARJSFXV
void display_comment(char FAR *cmt)
#else
void display_comment(char *cmt)
#endif
{
 unsigned char c;
 #if SFX_LEVEL>=ARJSFXV
  int is_ansi=0;
 #endif
 #if TARGET==OS2
  USHORT af;
 #endif

 #if SFX_LEVEL>=ARJ
  if(new_stderr==new_stdout)
   return;
 #endif
 #if TARGET==OS2
  fflush(stdout);
  VioGetAnsi(&af, 0);
  VioSetAnsi(ANSI_ON, 0);
 #endif
 while((c=*(cmt++))!='\0')
 {
  #if SFX_LEVEL>=ARJSFXV
   if(c==ANSI_ESC)
    is_ansi=1;
  #endif
 #if SFX_LEVEL>=ARJSFXV&&!defined(DIRECT_TO_ANSI)
  if(is_ansi)
  {
   display_ansi(c);
   if(c==LF)
    display_ansi(CR);
  }
  else
  {
 #endif
   /* Substitute non-printable control characters with "?"'s */
   #ifndef DIRECT_TO_ANSI
    if(c<' '&&c!=TAB&&c!=LF&&c!=CR)
     c=UNDISP_CHAR;
   #endif
   #if SFX_LEVEL>=ARJSFXV
    nputc((int)c);
   #else
    fputc((int)c, stdout);
   #endif
   #if SFX_LEVEL>=ARJ
    if(c==LF)
    {
     lines_scrolled++;
     if(lines_scrolled>=lines_per_page-1)
     {
      lines_scrolled=0;
      if(!yes_on_all_queries&&prompt_for_more&&is_tty(stdout))
      {
       if(!pause())
        return;
      }
     }
    }
   #endif
 #if SFX_LEVEL>=ARJSFXV&&!defined(DIRECT_TO_ANSI)
  }
 #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  if(is_ansi)
  {
   #ifdef DIRECT_TO_ANSI
    printf("\x1B[0m\n");
   #else
    display_ansi(LF);
   #endif
  }
 #endif
 #if TARGET==OS2
  VioSetAnsi(af, 0);
 #endif
}

#if SFX_LEVEL>=ARJ

/* Puts repeatable character to stdout */

static char *nputnc(char *dest, int c, int count)
{
 while(count-->0)
  *(dest++)=c;
 return(dest);
}

#endif

/* Displays progress indicator */

void display_indicator(long bytes)
{
 int pct;
 char ind[64];
 char *p;
 /* Indicator width */
 static unsigned char ind_sizes[]={5, 0, 11, 5, 8, 11, 11};
 #if SFX_LEVEL>=ARJ
  static int prev_pct=0;
 #endif

 if(!file_packing)
  return;
 p=ind;
 if(arjdisp_enabled)
  arjdisp_scrn((unsigned long)bytes);
 /* Different conditions for ARJ and ARJSFX! */
 #if SFX_LEVEL>=ARJ
 else if(indicator_style!=IND_NONE)
 {
  check_wrap(ind_sizes[indicator_style]);
  if(uncompsize<0L)
  {
   if(bytes==0L)
    p+=sprintf(p, sfmt_double, del_double);
   p+=sprintf(p, sfmt_bytes, bytes, del_double);
  }
  else
  {
   if(indicator_style==IND_NORMAL||indicator_style==IND_TOTAL_PCT)
   {
    if(bytes==0L)
    {
     p+=sprintf(p, sfmt_single, del_single);
     p+=sprintf(p, sfmt_start_graph, del_single);
    }
    else
    {
     if(total_size!=0&&display_totals&&indicator_style==IND_TOTAL_PCT)
      pct=calc_percentage(total_written+bytes, total_size);
     else
      pct=calc_percentage(bytes, uncompsize);
     if(pct==prev_pct&&CHECK_SENTRY())
      return;
     p+=sprintf(p, sfmt_numeric, pct/10, del_single);
    }
   }
   else if(indicator_style==IND_GRAPH||indicator_style==IND_TOTAL_GRAPH)
   {
    if(bytes==0L)
    {
     p+=sprintf(p, sfmt_double, del_double);
     p+=sprintf(p, sfmt_graph, del_double);
     *p='\0'; p=ind;
     msg_cprintf(H_HL, (FMSG *)strform, ind);
    }
    else
    {
     if(total_size!=0&&display_totals&&indicator_style==IND_TOTAL_GRAPH)
      pct=calc_percentage(total_written+bytes, total_size);
     else
      pct=calc_percentage(bytes, uncompsize);
     if(pct==prev_pct&&CHECK_SENTRY())
      return;
     p=nputnc(p, COUNTER_CHAR, pct/100);
     p=nputnc(p, '\b', pct/100);
     *p='\0'; p=ind;
     msg_cprintf(H_OPER, (FMSG *)strform, ind);
    }
   }
   else if(indicator_style==IND_PCT_GRAPH||indicator_style==IND_TOTAL_PCT_GRAPH||indicator_style==IND_TOTAL_PCT_LGRAPH)
   {
    if(total_size!=0&&display_totals&&(indicator_style==IND_TOTAL_PCT_GRAPH||indicator_style==IND_TOTAL_PCT_LGRAPH))
     pct=calc_percentage(total_written+bytes, total_size);
    else
     pct=calc_percentage(bytes, uncompsize);
    if(bytes==0L)
    {
     p+=sprintf(p, sfmt_double, del_double);
     p+=sprintf(p, sfmt_start_num, pct/10);
     *p='\0'; p=ind;
     if(pct==prev_pct&&CHECK_SENTRY())
      return;
     msg_cprintf(H_OPER, (FMSG *)strform, ind);
     msg_cprintf(H_HL, sfmt_mid_graph, del_double);
    }
    else
    {
     p+=sprintf(p, sfmt_short_numeric, pct/10);
     if(total_size!=0&&indicator_style==IND_TOTAL_PCT_GRAPH)
      pct=calc_percentage(total_written+bytes, total_size);
     else
      pct=calc_percentage(bytes, uncompsize);
     if(pct==prev_pct&&CHECK_SENTRY())
      return;
     p=nputnc(p, COUNTER_CHAR, pct/200);
     p=nputnc(p, '\b', pct/200+5);
    }
   }
  }
 }
 *p='\0';
 msg_cprintf(H_OPER, (FMSG *)strform, ind);
 prev_pct=pct;
 SET_SENTRY();
 #elif SFX_LEVEL==ARJSFXV
 else if(indicator_style==IND_NORMAL||indicator_style==IND_GRAPH)
 {
  if(uncompsize<0L)
  {
   if(bytes==0L)
    p+=sprintf(p, sfmt_double, del_double);
   p+=sprintf(p, sfmt_bytes, bytes, del_double);
  }
  if(indicator_style==IND_NORMAL)
  {
   if(bytes==0L)
   {
    p+=sprintf(p, sfmt_single, del_single);
    p+=sprintf(p, sfmt_start_graph, del_single);
   }
   else
   {
    pct=calc_percentage(bytes, uncompsize);
    p+=sprintf(p, sfmt_numeric, pct/10, del_single);
   }
  }
 }
 *p='\0';
 msg_cprintf(0, (FMSG *)strform, ind);
 #else
 else if(indicator_style==IND_NORMAL)
 {
  pct=calc_percentage(bytes, uncompsize);
  printf(sfmt_sfx, pct/10);
 }
 #endif
}

#endif

#if SFX_LEVEL>=ARJ

/* Puts a character to the output stream. The cursor position given is only for
   checking purposes. Returns the new cursor position. */

static int arj_putc(unsigned char c, int p)
{
 unsigned char t[8];
 unsigned char *q;
 int rc=p;

 q=t;
 if(c==LF)
 {
  #if COMPILER==MSC
   *q++=CR;
  #endif
  *q++=c;
  rc=1;
 }
 else if(c==TAB)
 {
  do
  {
   if(p<CONSOLE_LINE_LENGTH)
    *q++=' ';
   p++;
  } while(p%TAB_POS!=1);
  rc=p;
 }
 else if(c==CR)
 {
  *q++=' ';
  rc++;
 }
 else
 {
  *q++=(c>=' ')?c:UNDISP_CHAR;
  rc++;
 }
 *q='\0';
 msg_cprintf(0, (FMSG *)strform, t);
 return(rc);
}

/* Prints the given text to stdout, querying for "more?" when needed. Returns
   1 if the output was cancelled by the user in response to the "--More--?"
   prompt. */

static int list_with_more(char *str, unsigned int len)
{
 char i_field[CONSOLE_LINE_LENGTH+1];   /* Input field */
 char *sptr;
 unsigned int i;
 int cur_pos;
 int cur_line;
 unsigned char c;
 int sf;

 #if COMPILER==MSC
  if(help_issued)
   fputc(CR, stdout);
 #endif
 sptr=str;
 far_strcpy((char FAR *)i_field, prompt_for_more?M_QUERY_MORE:M_QUERY_SCANNED_ENOUGH);
 nputlf();
 cur_line=2;
 cur_pos=1;
 i=1;
 while(i<=len)
 {
  c=*(sptr++);
  if(verbose_display==VERBOSE_NONE&&!help_issued)
   c&=0x7F;                             /* Strip high bit from nonlocal text */
  i++;
  if(i>len)
   c=LF;
  cur_pos=arj_putc(c, cur_pos);
  if(c==LF)
  {
   cur_line++;
   if(cur_line>=lines_per_page-2)
   {
    cur_line=0;
    sf=(yes_on_all_queries|skip_scanned_query);
    if(!sf)
    {
     sf=query_action(REPLY_NO, QUERY_SCANNED_ENOUGH, i_field);
     if(prompt_for_more)
      sf^=1;
    }
    if(sf)
     return(1);
   }
  }
 }
 if(help_issued)
  return(0);
 sf=(yes_on_all_queries|skip_scanned_query);
 if(!sf)
 {
  sf=query_action(REPLY_NO, QUERY_SCANNED_ENOUGH, i_field);
  if(prompt_for_more)
   sf^=1;
 }
 return(sf);
}

/* Compares the contents of the block with the input file. */

static int compare_fblock(char *block, int len)
{
 int bytes_read;
 char FAR *tmp_block;

 if(identical_filedata)
 {
  tmp_block=farmalloc_msg((unsigned long)len);
  far_memmove(tmp_block, (char FAR *)block, len);
  if((bytes_read=fread(block, 1, len, tstream))!=len)
   identical_filedata=0;
  else
  {
   if(bytes_read>0)
   {
    if(far_memcmp((char FAR *)block, tmp_block, bytes_read))
     identical_filedata=0;
   }
  }
  far_memmove((char FAR *)block, tmp_block, len);
  farfree(tmp_block);
 }
 return(0);
}

/* Displays the text found in a block. Returns the number of bytes displayed. */

static int display_found_text(unsigned char FAR *block, int offset, int block_len)
{
 int remain;
 int d_offset;
 int column;
 unsigned int c;
 int i;

 d_offset=offset;
 remain=min(fdisp_lines*TXTD_LENGTH, block_len);
 if(remain>TXTD_LENGTH)
 {
  msg_cprintf(0, M_MARK_LLINE);
  d_offset=(remain/2>offset)?0:offset-remain/2;
 }
 block+=d_offset;
 column=0;
 i=0;
 while(i<remain&&d_offset<block_len)
 {
  if(column>=TXTD_LENGTH)
  {
   msg_cprintf(0, lf);
   column=0;
  }
  c=*(block++);
  if(verbose_display)
  {
   if(c<CON_LBOUND)
    c=UNDISP_CHAR;
  }
  else
   if(c<CON_LBOUND||c>CON_UBOUND)
    c=UNDISP_CHAR;
  fputc(c, new_stdout);
  i++;
  d_offset++;
  column++;
 }
 msg_cprintf(0, lf);
 return(i-(offset-d_offset));
}

/* Performs a search for the given pattern in memory block */

static int t_search_stub(char *pattern, char *cmpblock, char FAR *block, int skip, int block_len)
{
 int len;
 int matches;
 int search_offset;
 int limit;
 char c;
 int t_offset;
 char *p;

 len=strlen(pattern);
 matches=0;
 search_offset=0;
 c=*pattern;
 limit=(len>=block_len)?0:block_len-len;
 t_offset=skip;
 p=&cmpblock[skip];
 while(t_offset<limit)
 {
  if(*p==c)
  {
   if(!memcmp(pattern, p, len))
   {
    if(!pattern_found&&search_mode!=SEARCH_DEFAULT)
    {
     if(search_mode==SEARCH_SHOW_NAMES)
      msg_cprintf(0, strform, misc_buf);
     if(search_mode!=SEARCH_DEFAULT)
      msg_cprintf(0, strform, lf);
    }
    pattern_found=1;
    matches++;
    if(fdisp_lines!=0&&t_offset>search_offset)
     search_offset=t_offset+display_found_text(block, t_offset, block_len)-len;
    if(extm_mode!=EXTM_NONE)
     break;
   }
  }
  t_offset++;
  p++;
 }
 return(matches);
}

/* Performs a search in the block of continuous data. */

static int search_in_block(char *block, int block_len)
{
 int tmp_len, tail_len;
 char *sstr_ptr;
 char FAR *block_ptr;
 char FAR *reserve_ptr;
 int i;

 block_ptr=(char FAR *)block;
 reserve_ptr=(char FAR *)search_reserve;
 if(ignore_pcase)
 {
  block_ptr=farmalloc_msg((unsigned long)block_len);
  far_memmove(block_ptr, (char FAR *)block, block_len);
  toupper_loc(block, block_len);
  if(reserve_size!=0)
  {
   reserve_ptr=farmalloc_msg(160L);
   far_memmove(reserve_ptr, (char FAR *)search_reserve, reserve_size);
   toupper_loc(search_reserve, reserve_size);
  }
 }
 for(i=0; i<SEARCH_STR_MAX&&search_str[i]!=NULL; i++)
 {
  sstr_ptr=search_str[i];
  if(reserve_size!=0)
  {
   tmp_len=(block_len>INPUT_LENGTH)?INPUT_LENGTH:block_len;
   memcpy(search_reserve+reserve_size, block, tmp_len);
   if(ignore_pcase)
    far_memmove(&reserve_ptr[reserve_size], block_ptr, tmp_len);
   tail_len=reserve_size-strlen(sstr_ptr)+1;
   search_occurences[i]+=(long)t_search_stub(sstr_ptr, search_reserve, reserve_ptr, tail_len, reserve_size+tmp_len);
   if(pattern_found&&extm_mode!=EXTM_NONE)
    break;
  }
  search_occurences[i]+=(long)t_search_stub(sstr_ptr, block, block_ptr, 0, block_len);
  if(pattern_found&&extm_mode!=EXTM_NONE)
   break;
 }
 if(ignore_pcase)
 {
  far_memmove((char FAR *)block, block_ptr, block_len);
  farfree(block_ptr);
  if(reserve_size!=0)
   farfree(reserve_ptr);
 }
 reserve_size=(block_len>INPUT_LENGTH)?INPUT_LENGTH:block_len;
 memcpy(search_reserve, block+(block_len-reserve_size), reserve_size);
 return(0);
}

/* Displays a block of text using ANSI comment display routine. */

static int display_block(char *str, int len)
{
 if(new_stdout!=new_stderr)
 {
  while((len--)>0)
  {
   #ifndef DIRECT_TO_ANSI
    display_ansi(*(str++));
   #else
    putchar(*(str++));
   #endif
  }
 }
 return(0);
}

/* Performs various actions involving the given block. */

static int block_op(int action, char *block, int len)
{
 if(action==BOP_LIST)
  return(list_with_more(block, len));
 else if(action==BOP_DISPLAY)
  return(display_block(block, len));
 else if(action==BOP_SEARCH)
  return(search_in_block(block, len));
 else if(action==BOP_COMPARE)
  return(compare_fblock(block, len));
 else
  return(0);
}

#endif

#if SFX_LEVEL>=ARJ||defined(REARJ)

/* Renames file and ensures that it has been successfully renamed */

#ifdef REARJ

int rename_with_check(char *oldname, char *newname)
{
 if(!no_file_activity)
 {
  if(file_rename(oldname, newname))
   return(-1);
  if(file_exists(oldname)||!file_exists(newname))
   return(-1);
 }
 return(0);
}

#else

void rename_with_check(char *oldname, char *newname)
{
 if(!file_test_access(oldname))
 {
  if(!file_rename(oldname, newname))
  {
   if(!file_exists(oldname)&&file_exists(newname))
    return;
  }
 }
 error(M_CANTRENAME, oldname, newname);
}

#endif
#endif  /* SFX_LEVEL>=ARJ||defined(REARJ) */

#if SFX_LEVEL>=ARJ

/* Returns number of <c> occurences in the given string */

static int count_chars(char *str, char c)
{
 int occurs=0;
 char *tmp_ptr;

 for(tmp_ptr=str; *tmp_ptr!='\0'; tmp_ptr++)
  if(*tmp_ptr==c)
   occurs++;
 return(occurs);
}

/* Deletes the processed files */

int delete_processed_files(struct flist_root *root)
{
 char name[FILENAME_MAX];
 unsigned int count;
 int depth, max_depth;
 FILE_COUNT i;
 FILE *t;

 /* If break is requested, cancel the deletion */
 if(ctrlc_processing)
  return(0);
 max_depth=0;
 count=0;
 for(i=0; i<root->files; i++)
 {
  if(cfa_get(i)==FLFLAG_PROCESSED)
   count++;
 }
 if(delete_processed==DP_STD&&!yes_on_all_queries&&!query_delete)
 {
  msg_sprintf(misc_buf, M_QUERY_DELETE_N_FILES, count);
  if(!query_action(REPLY_YES, QUERY_DELETE_N_FILES, (char FAR *)misc_buf))
   return(0);
 }
 msg_cprintf(0, M_DELETE_COUNT, count);
 for(i=0; i<root->files; i++)
 {
  if(cfa_get(i)==FLFLAG_PROCESSED)
  {
   flist_retrieve(name, NULL, root, i);
   depth=count_chars(name, PATHSEP_DEFAULT);
   if(depth>max_depth)
    max_depth=depth;
   if(!is_directory(name))
   {
    /* ASR fix for 2.78-TCO */
    if(delete_processed!=DP_ADD_TRUNC)
    {
     if(file_unlink(name))
     {
      msg_cprintf(H_ERR, M_CANT_DELETE, name);
      nputlf();
     }
    }
    else
    {
     if((t=file_open(name, m_rbp))==NULL)
     {
      msg_cprintf(H_ERR, M_CANT_TRUNCATE, name);
      nputlf();
     }
     file_chsize(t, 0);
     fclose(t);
    }
    cfa_store(i, FLFLAG_DELETED);
   }
  }
 }
 for(depth=max_depth; depth>=0; depth--)
 {
  for(i=0; i<root->files; i++)
  {
   if(cfa_get(i)==FLFLAG_PROCESSED)
   {
    flist_retrieve(name, NULL, root, i);
    if(count_chars(name, PATHSEP_DEFAULT)>=depth&&is_directory(name))
    {
     if(file_rmdir(name))
     {
      msg_cprintf(H_ERR, M_CANT_DELETE, name);
      nputlf();
     }
     cfa_store(i, FLFLAG_DELETED);
    }
   }
  }
 }
 return(0);
}

/* Writes a byte to the file */

void fput_byte(int b, FILE *stream)
{
 if(!no_file_activity)
 {
  if(fputc(b, stream)==EOF)
   error(M_DISK_FULL);
 }
}

/* Writes two bytes to the file */

void fput_word(unsigned int w, FILE *stream)
{
 fput_byte(w&0xFF, stream);
 fput_byte(w>>8,   stream);
}

/* Writes four bytes to the file */

void fput_dword(unsigned long l, FILE *stream)
{
#ifdef WORDS_BIGENDIAN
fput_word((unsigned int)(l&0xFFFF), stream);
fput_word((unsigned int)(l>>16), stream);
#else
if(!no_file_activity)
  {
   if(!fwrite(&l,4,1,stream))
    error(M_DISK_FULL);
  }
#endif
}

/* Writes the compressed data */

void flush_compdata()
{
 if(out_bytes>0)
 {
  compsize+=(unsigned long)out_bytes;
  if(compsize>origsize&&(!garble_enabled||!file_packing))
   unpackable=1;
  else
  {
   if(!no_file_activity)
   {
    if(garble_enabled)
     garble_encode_stub(out_buffer, out_bytes);
    if(file_packing)
    {
     file_write(out_buffer, 1, out_bytes, aostream);
    }
    else
    {
     far_memmove(packblock_ptr, (char FAR *)out_buffer, out_bytes);
     packblock_ptr+=out_bytes;
    }
    out_avail=PUTBIT_SIZE;
   }
  }
  out_bytes=0;
 }
}

/* Initializes compressed data output */

void init_putbits()
{
 unsigned long fp;

 bitcount=0;
 byte_buf=0;
 bitbuf=0;
 out_bytes=0;
 if(!file_packing||no_file_activity)
  fp=0L;
 else
 {
  fp=ftell(aostream);
  if(fp>MAX_FILE_SIZE)
   error(M_FILE_IS_TOO_LARGE);
 }
 out_buffer=malloc_msg(PUTBIT_SIZE);
 out_avail=PUTBIT_SIZE-(fp%PUTBIT_SIZE);
 if(out_avail>PUTBIT_SIZE)
  error(M_PUTBIT_SIZE_ERROR);
 mem_stats();
}

/* Ends the bitwise output */

void shutdown_putbits()
{
 if(!unpackable)
 {
  putbits(CHAR_BIT-1, 0);
  if(out_bytes!=0)
   flush_compdata();
 }
 free(out_buffer);
 out_bytes=0;
}

/* Clears the archive attribute for a set of files */

int group_clear_arch(struct flist_root *root)
{
 char name[FILENAME_MAX];
 FILE_COUNT i;

 if(ctrlc_processing)
  return(0);
 for(i=0; i<root->files; i++)
 {
  if(cfa_get(i)==FLFLAG_PROCESSED)
  {
   flist_retrieve(name, NULL, root, i);
   if(dos_clear_arch_attr(name))
    msg_cprintf(H_ERR, M_CANT_RESET, name);
   cfa_store(i, FLFLAG_DELETED);
  }
 }
 return(0);
}

#endif
