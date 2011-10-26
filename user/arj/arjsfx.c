/*
 * $Id: arjsfx.c,v 1.6 2004/04/14 20:54:21 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * All SFX modules except ARJSFXJR result from this file.
 *
 */

#include <stdio.h>
#include <signal.h>

#include "arj.h"
#include "arjsfx.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Local variables */

static char cmd_args[SFX_COMMAND_SIZE+1];
#if SFX_LEVEL>=ARJSFXV
 static unsigned long ticks;
#endif
static unsigned int limit;

#if SFX_LEVEL>=ARJSFXV

/* Checks if all the files given to ARJ were successfully processed. */

static void file_arg_cleanup()
{
 int cur_arg;
 unsigned int cur_file;
 char *tmp_name;

 for(cur_arg=0; cur_arg<file_args; cur_arg++)
 {
  if(order[cur_arg]==0&&strcmp_os(f_arg_array[cur_arg], nonexist_name))
  {
   msg_cprintf(H_ERR, M_CANT_FIND, f_arg_array[cur_arg]);
   if(errorlevel==ARJ_ERL_SUCCESS)
    errorlevel=ARJ_ERL_WARNING;
   errors++;
  }
 }
}

#endif

/* Parses a command line token */

static void parse_cmdline(char *token)
{
 int name_len;
 char fn_end;

 #if SFX_LEVEL>=ARJSFXV
 if(is_switch(token))
  analyze_arg(token);
 #else
 if(!skip_switch_processing&&switch_char==0&&strchr(switch_chars, token[0])!=NULL)
 {
  switch_char=(int)token[0];
  analyze_arg(token);
 }
 else if(!skip_switch_processing&&switch_char!=0&&(int)token[0]==switch_char)
  analyze_arg(token);
 #endif
 else
 {
  name_len=strlen(token);
  fn_end=token[name_len-1];
  if(file_args==0&&target_dir[0]=='\0'&&strchr(path_separators, fn_end)!=NULL)
   target_dir=token;
  else
  {
   if(file_args>=params_max)
    error(M_ARGTABLE_OVERFLOW);
   f_arg_array[file_args++]=token;
  }
 }
}

/* Issues predefined switch processing, if any */

#if SFX_LEVEL>=ARJSFXV
char FAR *preprocess_comment(char FAR *comment)
#else
char *preprocess_comment(char *comment)
#endif
{
 char ctr;
 char *aptr, *endptr;
 int quoted=0, slashed;
 char c;

 if(comment[0]==')'&&comment[1]==')')
 {
  comment+=2;
  aptr=cmd_args;
  for(ctr=1; ctr<sizeof(cmd_args)&&*comment!='\0'&&*comment!='\n'; ctr++)
  {
   c=*comment;
   slashed=0;
   if(c=='\\')
   {
    c=*++comment;
    if(c!='"'&&c!='\\')
     *aptr++='\\';
    else
     slashed=1;
   }
   *aptr=c=*comment;
   if(c=='"'&&!slashed)
    quoted=!quoted;
   else if(c==' '&&!quoted)
    *aptr++='\0';
   else
    *aptr++=c;
   comment++;
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
    parse_cmdline(aptr);
    while(*aptr!='\0'&&(endptr-aptr)>0)
     aptr++;
   }
  }
  if(*comment=='\n')
   comment++;
 }
 return(comment);
}

/* Ctrl+C handler */

static void ctrlc_handler(SIGHDLPARAMS)
{
 #if SFX_LEVEL>=ARJSFXV
  ctrlc_processing=1;
 #endif
 /* Check if we are able to honor the request. If we aren't, raise the
    signal again and make a speedy getaway. */
#if SFX_LEVEL>=ARJSFXV
 if(!ctrlc_not_busy)
  raise(SIGINT);
 else
 {
  error_occured=1;                      /* ARJSFX needs termination */
#endif
  signal(SIGINT, NULL);                 /* Restore default Ctrl+C handler */
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, M_BREAK_SIGNALED);
   exit(ARJ_ERL_BREAK);
  #else
   msg_cprintf(0, M_BREAK_SIGNALED);
   exit(ARJSFX_ERL_ERROR);
  #endif
#if SFX_LEVEL>=ARJSFXV
 }
#endif
}

/* Termination handler */

#ifndef NO_TERM_HDL
static void term_handler(SIGHDLPARAMS)
{
 /* Check if we are able to honor the request. If we aren't, raise the
    signal again and make a speedy getaway. */
#if SFX_LEVEL>=ARJSFXV
 error_occured=1;                      /* ARJSFX needs termination */
#endif
 signal(SIGTERM, NULL);                /* Restore default SIGTERM handler */
 #if SFX_LEVEL>=ARJSFXV
  msg_cprintf(0, M_SIGTERM);
  exit(ARJ_ERL_BREAK);
 #else
  msg_cprintf(0, M_SIGTERM);
  exit(ARJSFX_ERL_ERROR);
 #endif
}
#endif

/* atexit routine - closes all files and frees memory */

static void final_cleanup(void)
{
 #if SFX_LEVEL>=ARJSFXV
  file_close(aistream);
  aistream=NULL;
  file_close(atstream);
  atstream=NULL;
 #else
  if(atstream!=NULL)
   fclose(atstream);
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(tmp_tmp_filename!=NULL&&!keep_tmp_file&&tmp_tmp_filename[0]!='\0')
   file_unlink(tmp_tmp_filename);
 #else
  if(tmp_tmp_filename[0]!='\0')
   file_unlink(tmp_tmp_filename);
 #endif
 #if SFX_LEVEL>=ARJSFXV&&(TARGET!=UNIX||defined(HAVE_FCLOSEALL))
  fcloseall();
 #endif
 if(quiet_mode)
  freopen(dev_con, m_w, stdout);
 #if SFX_LEVEL>=ARJSFXV
  if(ferror(stdout))
   msg_fprintf(stderr, M_DISK_FULL);
  if(debug_enabled&&strchr(debug_opt, 't')!=NULL)
  {
   ticks=get_ticks()-ticks;
   msg_cprintf(0, M_FINAL_TIMING, ticks);
  }
 #endif
}

#if SFX_LEVEL>=ARJSFXV

/* Waits and then prints an error message */

static void wait_error(FMSG *errmsg)
{
 arj_delay(5);
 error(errmsg);
}

/* Displays the ARJSFX logo */

void show_sfx_logo()
{
 char *tptr, *nptr;

 if(!logo_shown)
 {
  for(nptr=tptr=archive_name; *tptr!='\0'; tptr++)
   if(strchr(path_separators, *tptr)!=NULL)
    nptr=tptr+1;
  msg_cprintf(0, M_ARJSFX_BANNER, M_VERSION, nptr, build_date);
  msg_cprintf(0, lf);
  logo_shown=1;
 }
}

#endif

/* Checks if the SFX has been tampered with (currently stub) */

static void arj_exec_validation()
{
 limit=0;
}

/* Executes a command */

static void exec_command(char *cmd)
{
 #if SFX_LEVEL>=ARJSFXV
  char *cur_dir;
 #else
  char cur_dir[FILENAME_MAX];
 #endif

 if(target_dir[0]=='\0')
  system_cmd(cmd);
 else
 {
  #if SFX_LEVEL>=ARJSFXV
   cur_dir=(char *)malloc_msg(FILENAME_MAX);
  #endif
  file_getcwd(cur_dir, FILENAME_MAX);
  file_chdir(target_dir);
  system_cmd(cmd);
  file_chdir(cur_dir);
  #if SFX_LEVEL>=ARJSFXV
   free(cur_dir);
  #endif
 }
}

/* Main routine */

int main(int argc, char *argv[])
{
 int cur_arg;
 #if SFX_LEVEL>=ARJSFXV
  int cmd;
  int is_add_cmd;
  unsigned long start_time, proc_time;
  FILE_COUNT i;
  FILE *stream;
  char *tmp_ptr, *tptr;
  int got_str;
  char *name;
  int flist_type;
  FILE_COUNT numfiles;
  int expand_wildcards;
  int entry;
  int sort_f;
  FILE_COUNT count;
  FILE_COUNT cur_file;
  int tmp_reg;
 #else
  char *tmp_ptr;
 #endif

#ifdef COLOR_OUTPUT
 no_colors=redirected=!is_tty(stdout);
#endif
 #if SFX_LEVEL>=ARJSFXV
  errorlevel=0;
  ignore_errors=0;
  new_stdout=stdout;
  lfn_supported=LFN_NOT_SUPPORTED;
  ticks=get_ticks();
  detect_lfns();
  detect_eas();
  #ifndef NO_FATAL_ERROR_HDL
   install_smart_handler();
  #endif
  build_crc32_table();
 #else
  build_crc32_table();
  detect_lfns();
  file_packing=1;
 #endif
 #ifdef TZ_VAR
  tzset();
 #endif
 #ifdef STDOUT_SETBUF_FIX               /* ASR fix for IBM C Set / GLIBC */
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
 #endif
 #if SFX_LEVEL>=ARJSFXV
  start_time=get_ticks();
  flist_init(&flist_main, FCLIM_ARCHIVE, FL_STANDARD);
  ctrlc_processing=0;
  header=(char *)malloc_msg(HEADERSIZE_MAX);
  archive_name=(char *)malloc_msg(FILENAME_MAX);
  /* Original ARJSFX reserves 200 bytes for misc_buf but, taking into account
     that LFNs can be large enough, more space is to be reserved. */
  misc_buf=(char *)malloc_msg(FILENAME_MAX+INPUT_LENGTH);
  tmp_tmp_filename=(char *)malloc_msg(FILENAME_MAX);
  limit=20;
  init();
  if(signal(SIGINT, ctrlc_handler)==SIG_ERR)
   error(M_SIGNAL_FAILED);
  #ifndef NO_TERM_HDL
   if(signal(SIGTERM, term_handler)==SIG_ERR)
    error(M_SIGNAL_FAILED);
  #endif
  atexit(final_cleanup);
 #else
  tmp_tmp_filename[0]='\0';
  target_dir=nullstr;
  garble_password=nullstr;
  extr_cmd_text=nullstr;
 #endif
 #ifndef SKIP_GET_EXE_NAME
  get_exe_name(archive_name);
 #else
  strcpy(archive_name, argv[0]);
 #endif
 exe_name=archive_name;
 #if SFX_LEVEL<=ARJSFX
  for(tmp_ptr=exe_name; *tmp_ptr!='\0'; tmp_ptr++)
   if(*tmp_ptr==PATHSEP_DEFAULT)
    exe_name=tmp_ptr+1;
  atexit(final_cleanup);
  signal(SIGINT, ctrlc_handler);
  #ifndef NO_TERM_HDL
   signal(SIGTERM, term_handler);
  #endif
 #endif
 check_fmsg(CHKMSG_SKIP);
 #if SFX_LEVEL>=ARJSFXV
  skip_switch_processing=0;
 #else
  switch_char=0;
 #endif
 for(cur_arg=1; cur_arg<argc; cur_arg++)
  parse_cmdline(argv[cur_arg]);
 #if SFX_LEVEL>=ARJSFXV
  if(install_errhdl)
   ignore_errors=1;
  if(quiet_mode)
   freopen(dev_null, m_w, stdout);
 #endif
 if(argc>1)
  skip_preset_options=1;
 arj_exec_validation();
 if(help_issued)
 {
  #if SFX_LEVEL>=ARJSFXV
   show_sfx_logo();
  #else
   msg_cprintf(0, M_ARJSFX_BANNER, exe_name);
  #endif
  check_fmsg(CHKMSG_SFX_HELP);
  #if SFX_LEVEL>=ARJSFXV
   exit(ARJ_ERL_SUCCESS);
  #else
   exit(ARJSFX_ERL_SUCCESS);
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  if(limit!=0)
   wait_error(M_CRC_ERROR);
  limit=20;
  arj_exec_validation();
  proc_time=get_ticks();
  check_fmsg(CHKMSG_SKIP);
  perform_cmd();
 #else
  process_archive();
 #endif
 /* Cleanup for ARJSFXV */
 #if SFX_LEVEL>=ARJSFXV
  file_arg_cleanup();
 #endif
 if(errors>0)
  error(M_FOUND_N_ERRORS, errors);
 #if SFX_LEVEL>=ARJSFXV
  if(errorlevel!=ARJ_ERL_SUCCESS)
   exit(errorlevel);
 #endif
#if SFX_LEVEL>=ARJSFXV
 if(extr_cmd_text[0]!='\0')
#else
 if(execute_extr_cmd&&extr_cmd_text[0]!='\0')
#endif
 {
  if(licensed_sfx)
  {
   msg_cprintf(0, M_EXECUTING_CMD, extr_cmd_text);
   arj_delay(2);
   exec_command(extr_cmd_text);
  }
  else
  {
   #if SFX_LEVEL>=ARJSFXV
    msg_sprintf(misc_buf, M_EXTR_CMD_QUERY, extr_cmd_text);
    if(query_action(REPLY_YES, QUERY_CRITICAL, (FMSG *)misc_buf))
     exec_command(extr_cmd_text);
   #else
    msg_cprintf(0, M_EXTR_CMD_QUERY, extr_cmd_text);
    if(query_action())
     exec_command(extr_cmd_text);
   #endif
  }
 }
 #if SFX_LEVEL>=ARJSFXV
  return(ARJ_ERL_SUCCESS);
 #else
  return(ARJSFX_ERL_SUCCESS);
 #endif
}

#if SFX_LEVEL>=ARJSFXV

/* Converts a filename entered from command-line to standard form */

static void cnv_cmdline_fnm(char *name)
{
 strip_lf(name);
 alltrim(name);
}

/* General SFX setup */

void sfx_setup()
{
 int expand_wildcards;
 char *name;
 int i;
 char *tptr, *tmp_ptr;
 FILE *stream;
 FILE_COUNT count;

 if(quiet_mode)
  freopen(dev_null, m_w, stdout);
 if(file_args>=0)
  case_path(archive_name);
 case_path(target_dir);
 case_path(extraction_filename);
 if(extract_to_file&&extraction_filename[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-w");
 if(garble_enabled&&garble_password[0]=='\0')
  error(M_NO_PWD_OPTION);
 if(file_args==0)
  f_arg_array[file_args++]=all_wildcard;
 if(ignore_crc_errors)
  keep_tmp_file=1;
 if(handle_labels&&label_drive=='\0'&&target_dir[0]!='\0'&&target_dir[1]==':')
  label_drive=target_dir[0];
 if(extract_expath)
 {
  cmd_verb=ARJ_CMD_EXTRACT;
  subdir_extraction=1;
 }
 else if(extract_cmd)
 {
  cmd_verb=ARJ_CMD_EXTRACT;
  extract_expath=1;
 }
 else if(list_sfx_cmd)
  cmd_verb=ARJ_CMD_LIST;
 else if(test_sfx_cmd)
  cmd_verb=ARJ_CMD_TEST;
 else if(verbose_list)
 {
  cmd_verb=ARJ_CMD_LIST;
  std_list_cmd=1;
 }
 else
  cmd_verb=ARJ_CMD_EXTRACT;
 expand_wildcards=0;
 name=malloc_msg(FILENAME_MAX);
 for(i=0; i<file_args; i++)
 {
  tptr=f_arg_array[i];
  if(listchars_allowed&&tptr[0]==listchar)
  {
   if(*++tptr=='\0')
    error(M_MISSING_FILENAME_ARG, f_arg_array[i]);
   stream=file_open_noarch(tptr, m_r);
   tmp_ptr=header;
   order[i]=1;
   while(fgets(tmp_ptr, FILENAME_MAX, stream)!=NULL)
   {
    cnv_cmdline_fnm(tmp_ptr);
    if(tmp_ptr[0]!='\0')
    {
     strcpy(name, tmp_ptr);
     count=0;
     if(flist_add_files(&flist_main, &flist_exclusion, name, expand_wildcards, recurse_subdirs, allow_any_attrs, &count))
     {
      i=file_args;
      break;
     }
    }
   }
   fclose(stream);
  }
  else
  {
   strcpy(name, f_arg_array[i]);
   count=0;
   if(flist_add_files(&flist_main, &flist_exclusion, name, expand_wildcards, recurse_subdirs, allow_any_attrs, &count))
    break;
   order[i]=count;
  }
 }
 free(name);
 cfa_init(flist_main.files);
}

#endif
