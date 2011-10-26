/*
 * $Id: arj.c,v 1.12 2004/05/01 15:29:02 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This is  the main file of the  ARJ project. The  routines in this file have
 * a wide variety of purposes, however, all archive-related procedures are NOT
 * put into ARJ.C.
 *
 */

#include <stdio.h>
#include <signal.h>

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Expiry date/time */

#define EXPIRABLE                  0    /* 1 -> allow expiry as such */

#define EXPIRY_YR               1980
#define EXPIRY_MO                  1
#define EXPIRY_DY                  1
#define EXPIRY_H                   0
#define EXPIRY_M                   0
#define EXPIRY_S                   0

/* Local variables */

static char fixed_arjtemp[]="ARJTEMP.$$$";
static char arjtemp_wildcard[]="ARJTEMP.$??";
static char wildcard_pattern[]="?*[]^";
static int tmp_archive_exists;
static int tmp_archive_removed;
static unsigned long ticks;
static unsigned int limit;
static char brief_help[]="arjs.txt";
static char full_help[]="arjl.txt";
static char sort_filename[]="arjsort.$$$";
static char *arj_env_str=NULL;
static char single_spc[]=" ";

/* Forward references */

static void finish_archive_name(char *name);
static void final_cleanup(void);

/* Checks if all the files given to ARJ were successfully processed. */

static void file_arg_cleanup(struct flist_root *flist)
{
 int cur_arg;
 FILE_COUNT cur_file;
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
 if(flist->files>0)
 {
  tmp_name=malloc_msg(FILENAME_MAX);
  for(cur_file=0; cur_file<flist->files; cur_file++)
  {
   flist_retrieve(tmp_name, NULL, flist, cur_file);
   msg_cprintf(H_ERR, M_CANT_FIND, tmp_name);
   if(listfile_err_opt)
   {
    if(errorlevel==ARJ_ERL_SUCCESS)
     errorlevel=ARJ_ERL_WARNING;
    errors++;
   }
  }
  free(tmp_name);
 }
}

/* Depending on the command given, issues some special setup */

static void cmd_setup(int *cmd, int *is_add_cmd)
{
 int cnv_cmd;
 int add_cmd;
 char *tmp_swptr;
 char *vptr;
 unsigned long vol_size;

 cnv_cmd=*cmd;
 switch(*cmd)
 {
  case ARJ_CMD_MOVE:
   cnv_cmd=ARJ_CMD_ADD;
   delete_processed=DP_ADD;
  case ARJ_CMD_ADD:
   if(freshen_criteria)
    cnv_cmd=ARJ_CMD_FRESHEN;
   if(update_criteria)
    cnv_cmd=ARJ_CMD_UPDATE;
   break;
  case ARJ_CMD_REM_BAK:
   current_chapter=RESERVED_CHAPTER;
   break;
  case ARJ_CMD_FRESHEN:
   if(freshen_criteria==FC_NONE)
    freshen_criteria=FC_EXISTING;
   break;
  case ARJ_CMD_UPDATE:
   if(update_criteria==FC_NONE)
    update_criteria=FC_EXISTING;
   break;
  case ARJ_CMD_SECURE:
   sign_with_arjsec=1;
   break;
  case ARJ_CMD_ADDC:
   cnv_cmd=ARJ_CMD_UPDATE;
   update_criteria=UC_NEW_OR_DIFFERENT;
   chapter_mode=CHAP_USE;
   break;
  case ARJ_CMD_CNVC:
   cnv_cmd=ARJ_CMD_COPY;
   chapter_mode=CHAP_USE;
   break;
  case ARJ_CMD_DELC:
   cnv_cmd=ARJ_CMD_DELETE;
   chapter_mode=CHAP_USE;
   break;
  case ARJ_CMD_EXEC:
   cnv_cmd=ARJ_CMD_EXTR_NP;
   execute_cmd=1;
   if(extraction_filename[0]=='\0')
   {
    extraction_filename=fixed_arjtemp;
    extract_to_file=1;
   }
   break;
  case ARJ_CMD_SAMPLE:
   cnv_cmd=ARJ_CMD_PRINT;
   print_with_more=1;
   break;
  case ARJ_CMD_PRINT:
   if(!prompt_for_more)
    break;
   print_with_more=1;
   break;
  case ARJ_CMD_V_LIST:
   cnv_cmd=ARJ_CMD_LIST;
   std_list_cmd=1;
   break;
  case ARJ_CMD_EXTRACT:
   cnv_cmd=ARJ_CMD_EXTR_NP;
   subdir_extraction=1;
   break;
 }
 if(cnv_cmd==ARJ_CMD_EXTR_NP&&delete_processed&&!execute_cmd)
 {
  cnv_cmd=ARJ_CMD_DELETE;
  delete_processed=DP_EXTRACT;
 }
 add_cmd=msg_strchr(M_ADD_COMMANDS, (char)cnv_cmd)!=NULL;
 if(file_args<0)
 {
  if(!append_curtime)
   error(M_NO_FILE_GIVEN);
  else
  {
   archive_name[0]='\0';
   file_args++;
   finish_archive_name(archive_name);
  }
 }
 if(cnv_cmd==ARJ_CMD_DELETE&&file_args==0&&delete_processed!=DP_EXTRACT)
  error(M_NO_DELETE_ARG);
 if(cnv_cmd!=ARJ_CMD_COMMENT&&msg_strchr(M_MODIFY_COMMANDS, (char)cnv_cmd)!=NULL&&current_chapter!=0&&current_chapter<=CHAPTERS_MAX)
  error(M_BAD_SYNTAX);
 if(add_cmd&&multivolume_option)
 {
  if(volume_limit<MIN_VOLUME_SIZE)
   error(M_INVALID_VOL_SIZE);
  /* ASR fix. This was dropped in original ARJ but stays here, with a fix to
     treat -va adequately. */
  if(protfile_option)
  {
   vol_size=(unsigned long)calc_protdata_size(volume_limit, protfile_option)+MIN_VOLUME_SIZE;
   if(volume_limit<vol_size&&multivolume_option!=MV_AVAIL)
    error(M_PROTFILE_EXCEEDS, vol_size);
  }
 }
 if(add_command&&strpbrk(archive_name, wildcard_pattern)!=NULL)
  error(M_CANTOPEN, archive_name);
 if(cnv_cmd==ARJ_CMD_COPY&&file_args>0)
  error(M_BAD_SYNTAX);
 if(win32_platform&&lfn_mode==LFN_DUAL)
  error(M_BAD_SYNTAX);
 if(chapter_mode==CHAP_REMOVE&&cnv_cmd!=ARJ_CMD_COPY)
  error(M_BAD_SYNTAX);
 if(test_archive_crc>=TC_CRC_AND_CONTENTS&&exclude_paths)
  error(M_JT_UNUSABLE, "-e/-e1");
 if(test_archive_crc>=TC_CRC_AND_CONTENTS&&fix_longnames)
  error(M_JT_UNUSABLE, "-2l");
 if(arcmail_sw&&serialize_exts)
  error(M_JO_UNUSABLE, "-2a");
 #if TARGET==DOS
  if(priority.class!=0)
   error(M_OS_DEPENDENT, "-2p");
 #endif
 if(ea_supported&&restart_at_filename)
  error(M_CANT_RESTART_W_EAS);
 if(assign_work_directory&&work_directory[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-w");
 if(extract_to_file&&extraction_filename[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-jw");
 if(create_list_file&&list_file[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-l");
 if(create_index&&index_name[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-ji");
 if(restart_at_filename&&filename_to_restart[0]=='\0'&&index_name[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-jn");
 if((cnv_cmd==ARJ_CMD_EXTR_NP||cnv_cmd==ARJ_CMD_EXTRACT)&&use_comment&&archive_cmt_name[0]=='\0')
  error(M_MISSING_FILENAME_ARG, "-z");
 if(chk_arj_version)
 {
  tmp_swptr=swptr_hv;
  if(tmp_swptr[0]=='\0'||tmp_swptr[0]=='R'||tmp_swptr[0]=='r')
  {
   if(!is_registered)
    exit(ARJ_ERL_WARNING);
   else if(tmp_swptr[0]!='\0')
    tmp_swptr++;
  }
  if(tmp_swptr[0]!='\0')
  {
   msg_strcpy(strcpy_buf, M_VERSION);
   vptr=strcpy_buf;
   if(vptr[0]<tmp_swptr[0])
    exit(ARJ_ERL_WARNING);
   if(vptr[0]==tmp_swptr[0])
   {
    vptr+=2;
    tmp_swptr+=2;                       /* Skip over "." */
    if(vptr[0]<tmp_swptr[0])
     exit(ARJ_ERL_WARNING);
    if(vptr[0]==tmp_swptr[0])
    {
     vptr++;
     tmp_swptr++;
     if(vptr[0]<tmp_swptr[0])
      exit(ARJ_ERL_WARNING);
     if(vptr[0]==tmp_swptr[0])
     {
      vptr++;
      tmp_swptr++;
      if(vptr[0]<tmp_swptr[0])
       exit(ARJ_ERL_WARNING);
     }
    }
   }
  }
 }
 if(file_args==0)
  f_arg_array[file_args++]=all_wildcard;
 method_specifier=(custom_method==0)?1:custom_method-1;
 if(create_sfx)
 {
  if(method_specifier==4)
   error(M_INVALID_METHOD_SFX);
  if(chapter_mode)
   error(M_CHAPTER_SFX_CREATION);
  if(create_sfx==SFXCRT_SFXJR&&type_override&&primary_file_type==ARJT_TEXT)
   error(M_TEXTMODE_LFN_SFXJR);
  #if TARGET==DOS
   if(create_sfx==SFXCRT_SFXJR&&lfn_supported!=LFN_NOT_SUPPORTED)
    error(M_TEXTMODE_LFN_SFXJR);
  #endif
  #if defined(HAVE_EAS)
   if(create_sfx==SFXCRT_SFXJR&&ea_supported)
    error(M_TEXTMODE_LFN_SFXJR);
  #endif
  #if TARGET==UNIX
   if(create_sfx==SFXCRT_SFXJR&&dos_host)
    error(M_DOS_MODE_SFXJR);
  #endif
  if(create_sfx==SFXCRT_SFXJR&&garble_enabled)
   error(M_NO_GARBLE_IN_SFXJR);
  if(msg_strchr(M_MODIFY_COMMANDS, (char)cnv_cmd)==NULL)
   error(M_INVALID_SFX_SW_USE);
  if(create_sfx==SFXCRT_SFXJR&&multivolume_option)
   error(M_MULTIVOLUME_SFXJR);
 }
 if(debug_enabled&&strchr(debug_opt, 'n')!=NULL)
  no_file_activity=1;
 if(ignore_crc_errors)
  keep_tmp_file=1;
 if(exit_after_count&&exit_count==0)
  exit_count=file_args;
 if(handle_labels&&label_drive=='\0'&&target_dir[0]!='\0'&&target_dir[1]==':')
  label_drive=target_dir[0];
 if(filelist_storage==BST_NONE&&!win32_platform)
 {
  filelist_storage=BST_DISK;
  max_filenames=3000;
 }
 *cmd=cnv_cmd;
 *is_add_cmd=add_cmd;
}

/* Gets the command for execution */

static void get_exec_cmd()
{
 if(set_string_parameter&&string_parameter[0]!='\0')
  cmd_to_exec=string_parameter;
 else
 {
  while(header[0]=='\0')
  {
   msg_cprintf(0, M_ENTER_CMD);
   read_line(header, HEADERSIZE_MAX);
  }
  cmd_to_exec=malloc_str(header);
 }
}

/* Picks an extension from the -hx extension list */

static int fetch_extension(int offset, char *dest)
{
 int c_offset;

 if(strlen(archive_ext_list)<offset)
  return(0);
 while(archive_ext_list[offset]!='\0'&&archive_ext_list[offset]!='.') offset++;
 if(archive_ext_list[offset]=='\0')
  return(0);
 c_offset=offset;
 do
  offset++;
 while(c_offset+6>offset&&archive_ext_list[offset]!='\0'&&archive_ext_list[offset]!='.');
 while(c_offset<offset)
  *(dest++)=archive_ext_list[c_offset++];
 *dest='\0';
 return(offset);
}

/* Adds ARJ extension to the archive name */

static void finish_archive_name(char *name)
{
 int n_len;
 char last_char;
 int offset;
 char ext_pad[EXTENSION_MAX+2];         /* +2 means space for '.' and '\0' */
 int entry;

 if(name[0]=='\0')
  msg_strcpy(name, M_EXT_ARJ);
 n_len=strlen(name);
 entry=split_name(name, NULL, NULL);
 last_char=name[n_len-1];
 if(last_char=='.')
  name[n_len-1]='\0';
 else if(strchr(name+entry, '.')==NULL)
 {
  /* create_sfx is an ASR fix for 2.77 (empty extension on UNIX) */
  if(!override_archive_exts)
  {
   #ifdef NULL_EXE_EXTENSION
    if(!create_sfx)
     msg_strcpy(name+n_len, M_EXT_ARJ);
    else
     name[n_len]='\0';
   #else
    msg_strcpy(name+n_len, M_EXT_ARJ);
   #endif
   if(lfn_supported==LFN_NOT_SUPPORTED)
    strupper(name+n_len);
  }
  else
  {
   offset=0;
   while((offset=fetch_extension(offset, ext_pad))!=0)
   {
    strcpy(name+n_len, ext_pad);
    if(file_exists(name))
     break;
   }
   if(offset==0)
   {
    fetch_extension(0, ext_pad);
    strcpy(name+n_len, ext_pad);
   }
  }
 }
}

/* Converts a filename entered from command-line to standard form */

static void cnv_cmdline_fnm(char *name)
{
 strip_lf(name);
 alltrim(name);
 if(translate_unix_paths)
  unix_path_to_dos(name);
}

/* Creates an exclusion list */

void create_excl_list(char *names)
{
 char tmp_name[FILENAME_MAX];
 FILE *stream;

 if(listchars_allowed&&names[0]==listchar)
 {
  if(*++names=='\0')
   error(M_MISSING_FILENAME_ARG, "-x");
  unix_path_to_dos(names);
  stream=file_open_noarch(names, m_r);
  while(fgets(tmp_name, sizeof(tmp_name), stream)!=NULL)
  {
   cnv_cmdline_fnm(tmp_name);
   if(tmp_name[0]!='\0')
    flist_add_files(&flist_exclusion, NULL, tmp_name, 0, 0, 0, NULL);
  }
  fclose(stream);
 }
 else
  flist_add_files(&flist_exclusion, NULL, names, 0, 0, 0, NULL);
}

/* Parses the command line, taking filename argument. Returns the command
   code. */

static int parse_cmdline(char *token, int cmd)
{
 int name_len;
 char *endptr;
 char end_sym;

 if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
  msg_cprintf(H_HL|H_NFMT, M_TOKEN, token);
 if(is_switch(token))
  analyze_arg(token);
 else
 {
  if(cmd==0)
  {
   cmd=toupper(token[0]);
   /* Use fake 1-byte commands for 2-byte commands */
   if(!stricmp(token, cmd_ac))
    return(cmd=ARJ_CMD_ADDC);
   if(!stricmp(token, cmd_cc))
    return(cmd=ARJ_CMD_CNVC);
   if(!stricmp(token, cmd_dc))
    return(cmd=ARJ_CMD_DELC);
   if(msg_strchr(M_CMD_TABLE, (char)cmd)==NULL||strlen(token)!=1)
   {
    msg_cprintf(H_HL|H_NFMT, M_INVALID_COMMAND, token);
    exit(ARJ_ERL_USER_ERROR);
   }
  }
  else
  {
   if(file_args<0)
   {
    far_strcpyn((char FAR *)archive_name, (char FAR *)token, FILENAME_MAX);
    unix_path_to_dos(archive_name);
    alltrim(archive_name);
    if(archive_name[0]=='\0')
    {
     if(!append_curtime)
      error(M_NO_FILE_GIVEN);
     finish_archive_name(archive_name);
    }
    file_args++;
   }
   else
   {
    unix_path_to_dos(token);
    name_len=strlen(token);
    endptr=&token[name_len-1];
    end_sym=*endptr;
    while(*endptr==' ')
     endptr--;
    if(file_args<0||strcmp_os(token, nonexist_name))
    {
     if(file_args==0&&!set_target_directory&&target_dir[0]=='\0'&&
        strchr(path_separators, *endptr)!=NULL)
     {
      target_dir=token;
      if(end_sym!=' ')
       return(cmd);
     }
     if(file_args==0&&!set_target_directory&&target_dir[0]=='\0'&&
        msg_strchr(M_DIR_COMMANDS, (char)cmd)!=NULL&&strpbrk(token, wildcard_pattern)==NULL&&
        is_directory(token))
     {
      target_dir=malloc_msg(name_len+2);
      strcpy(target_dir, token);
      target_dir[name_len]=PATHSEP_DEFAULT;
      target_dir[name_len+1]='\0';
     }
     else
     {
      if(file_args>=params_max)
       error(M_ARGTABLE_OVERFLOW);
      f_arg_array[file_args++]=token;
     }
    }
    else
     f_arg_array[file_args++]=token;
   }
  }
 }
 return(cmd);
}

/* Ctrl+C handler */

static void ctrlc_handler(SIGHDLPARAMS)
{
 ctrlc_processing=1;
 /* Check if we are able to honor the request. If we aren't, raise the
    signal again and make a speedy getaway. */
 if(!ctrlc_not_busy)
  raise(SIGINT);
 else
 {
  error_occured=1;                      /* ARJ needs termination */
  signal(SIGINT, NULL);                 /* Restore default Ctrl+C handler */
  msg_cprintf(H_SIG, M_BREAK_SIGNALED);
  exit(ARJ_ERL_BREAK);
 }
}

/* Termination handler */

#ifndef NO_TERM_HDL
static void term_handler(SIGHDLPARAMS)
{
 error_occured=1;                       /* ARJ needs termination */
 signal(SIGTERM, NULL);
 msg_cprintf(H_SIG, M_SIGTERM);
 exit(ARJ_ERL_BREAK);
}
#endif

/* Executes an OS command with checking for break */

void exec_cmd(char *cmd)
{
 flush_kbd();
 ctrlc_not_busy=0;                      /* Say that we are busy */
 system_cmd(cmd);
 ctrlc_not_busy=1;
 if(ctrlc_processing)                   /* If processing was delayed... */
 #if COMPILER==BCC
  ctrlc_handler();
 #else
  ctrlc_handler(0);
 #endif
}

/* atexit routine - closes all files and frees memory */

static void final_cleanup(void)
{
 short pad;
 static int double_shutdown=0;

 file_close(idxstream);
 file_close(aistream);
 file_close(atstream);
 idxstream=NULL;
 aistream=NULL;
 atstream=NULL;
 if(aostream!=NULL)
 {
  if(last_hdr_offset>0L)
  {
   fseek(aostream, last_hdr_offset+2L, SEEK_SET);
   pad=0;
   fwrite(&pad, 1, 2, aostream);
  }
  file_close(aostream);
  aostream=NULL;
 }
 #if TARGET!=UNIX||defined(HAVE_FCLOSEALL)
  fcloseall();
 #endif
 if(tmp_archive_name!=NULL)
 {
  if(tmp_archive_removed)
  {
   rename_with_check(tmp_archive_name, archive_name);
   tmp_archive_name[0]='\0';
  }
  if(!keep_tmp_archive&&tmp_archive_name[0]!='\0'&&(!tmp_archive_used||!tmp_archive_exists))
   file_unlink(tmp_archive_name);
  if(tmp_archive_used==1)
   file_unlink(archive_name);
  free(tmp_archive_name);
  tmp_archive_name=NULL;
 }
 if(tmp_tmp_filename!=NULL)
 {
  if(!keep_tmp_file&&tmp_tmp_filename[0]!='\0')
   file_unlink(tmp_tmp_filename);
  free(tmp_tmp_filename);
  tmp_tmp_filename=NULL;
 }
 if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
 {
  msg_cprintf(0, M_EXITING_PROGRAM);
  if(double_shutdown)
   msg_cprintf(0, M_HERE_TWICE);
  if(verify_heap())
   msg_cprintf(H_ERR, M_BAD_HEAP);
 }
 if(double_shutdown)
  return;
 double_shutdown=1;
 flist_cleanup(&flist_main);
 flist_cleanup(&flist_order);
 flist_cleanup(&flist_exclusion);
 flist_cleanup(&flist_archive);
 #if defined(HAVE_EAS)
  flist_cleanup(&flist_ea);
  flist_cleanup(&flist_xea);
 #endif
 #if TARGET==UNIX
  if(l_entries.list!=NULL)
   farfree(l_entries.list);
 #endif
 if(quiet_mode)
  freopen(dev_con, m_w, stdout);
 if(ferror(stdout))
  msg_fprintf(stderr, M_DISK_FULL);
 if(debug_enabled&&strchr(debug_opt, 't')!=NULL)
 {
  ticks=get_ticks()-ticks;
  msg_cprintf(H_HL|H_NFMT, M_FINAL_TIMING, ticks);
 }
 if(!store_by_suffix)
  free(archive_suffixes);
 cfa_shutdown();
 if(arj_env_str!=NULL)
  free_env_str(arj_env_str);
 if(eh!=NULL)
 {
  eh_release(eh);
  eh=NULL;
 }
 if(ntext!=NULL)                        /* ASR fix for 2.76.05 */
  free(ntext);
 free_fmsg(arj_env_name);
 free(header);
 free(archive_name);
 free(misc_buf);
 free(strcpy_buf);
 free(exe_name);
 farfree(order);
 free(f_arg_array);
#ifdef COLOR_OUTPUT
 scrn_reset();
#endif
}

/* Waits and then prints an error message */

static void wait_error(FMSG *errmsg)
{
 arj_delay(5);
 error(errmsg);
}

/* Checks if the ARJ beta has expired */

static void arj_exec_validation()
{
 #if !defined(COMMERCIAL)&&EXPIRABLE==1
  struct timestamp cur_time, expiry_time;
 #endif

 limit=0;
 #if !defined(COMMERCIAL)&&EXPIRABLE==1
  /* See top of this module for definitions */
  cur_time_stamp(&cur_time);
  make_timestamp(&expiry_time, EXPIRY_YR, EXPIRY_MO, EXPIRY_DY, EXPIRY_H, EXPIRY_M, EXPIRY_S);
  if(ts_cmp(&cur_time, &expiry_time)>=0)
   limit=100;
 #endif
 /* The EXE validation must occur here. Skipped for speed-up */
}

/* This is not an optimization -- ASR fix for High C -- 05/04/2001 */

#if COMPILER==HIGHC&&!defined(DEBUG)
 #pragma on(Optimize_for_space)
#endif

/* Main routine */

int main(int argc, char *argv[])
{
 int cmd;
 int is_add_cmd;
 unsigned long start_time, proc_time;
 FILE_COUNT i;
 int j;
 int cur_arg;
 FILE *stream;
 char *tmp_ptr, *tptr, *endptr;
 int got_str=0;
 char *name;
 int flist_type;
 FILE_COUNT numfiles;
 int expand_wildcards;
 int entry;
 int sort_f;
 FILE_COUNT count;
 FILE_COUNT cur_file;
 int ansi_cpf;
 FILE *tmp_stdout;
 FILE_COUNT default_capacity=EXT_FILELIST_CAPACITY;

#if TARGET==WIN32
 win32_platform=1;
#else
 win32_platform=0;
#endif
#ifdef COLOR_OUTPUT
 no_colors=redirected=!is_tty(stdout);
#endif
 errorlevel=0;
 ignore_errors=0;
 ansi_cpf=0;
 in_key=1;
 params_max=argc+PARAMS_MAX;
 order=NULL;
 f_arg_array=NULL;
 #ifdef TZ_VAR
  tzset();
 #endif
 ticks=get_ticks();
 detect_lfns();
 detect_eas();
 ticks=get_ticks();
 cmd=preprocess_cmdline(argc, argv);
 set_file_apis(use_ansi_cp);            /* ARJ32 only (from v 2.72) */
 #ifndef NO_FATAL_ERROR_HDL
  install_smart_handler();
 #endif
 /* Perform STDOUT setup -- ASR fix for IBM C Set++, VisualAge C++ and
    GLIBC builds */
 #ifdef STDOUT_SETBUF_FIX
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
 #endif
 new_stderr=NULL;
 if(quiet_mode)
  new_stderr=fopen(dev_null, m_w);
 if(quiet_mode==ARJ_QUIET||quiet_mode==ARJ_SILENT)
  new_stdout=new_stderr;
 /* Test for low-memory DOS situtations */
 #if TARGET==DOS
  free(malloc_msg(10000));
  farfree(farmalloc_msg(9000));
 #endif
 /* Locate the executables. On UNIX systems, before assuming /usr/bin/arj, we
    try to guess if ARGV contains a somewhat qualified filename. This is a
    special hack for PACKAGER. */
 exe_name=(char *)malloc_msg(CCHMAXPATH);
 #ifndef SKIP_GET_EXE_NAME
  get_exe_name(exe_name);
 #else
  get_exe_name(exe_name, argv[0]);
 #endif
 case_path(arj_env_name);
 init_crc();
 start_time=get_ticks();
 ctrlc_processing=0;
 tmp_archive_removed=0;
 tmp_archive_exists=0;
 is_registered=1;
 #ifdef COMMERCIAL
  is_commercial=1;
 #else
  is_commercial=0;
 #endif
 archive_suffixes=NULL;
 header=(char *)malloc_msg(HEADERSIZE_MAX);
 archive_name=(char *)malloc_msg(FILENAME_MAX);
 archive_name[0]='\0';                  /* ASR fix for ARJ -i in ARJ 2.73 */
 misc_buf=(char *)malloc_msg(FILENAME_MAX+INPUT_LENGTH);
 tmp_tmp_filename=(char *)malloc_msg(FILENAME_MAX);
 strcpy_buf=(char *)malloc_msg(200);
 order=(FILE_COUNT FAR *)farmalloc_msg(params_max*sizeof(FILE_COUNT));
 f_arg_array=(char **)malloc_msg(params_max*sizeof(char *));
 limit=20;
 parse_reg_key();
 arj_exec_validation();
 set_file_apis(use_ansi_cp);
 init();
 flist_init(&flist_main, 0, FL_STANDARD);
 flist_init(&flist_exclusion, 0, FL_STANDARD);
 flist_init(&flist_order, 0, FL_STANDARD);
 flist_init(&flist_archive, 0, FL_STANDARD);
 #if defined(HAVE_EAS)
  flist_init(&flist_ea, 0, FL_STANDARD);
  flist_init(&flist_xea, 0, FL_STANDARD);
 #endif
 if(signal(SIGINT, ctrlc_handler)==SIG_ERR)
  error(M_SIGNAL_FAILED);
 #ifndef NO_TERM_HDL
  if(signal(SIGTERM, term_handler)==SIG_ERR)
   error(M_SIGNAL_FAILED);
 #endif
 #ifdef HAVE_BREAK_HANDLER
  if(signal(SIGBREAK, term_handler)==SIG_ERR)
   error(M_SIGNAL_FAILED);
 #endif
 atexit(final_cleanup);
 for(i=0; i<10; i++)
  is_registered=reg_validation(regdata+REG_KEY1_SHIFT, regdata+REG_KEY2_SHIFT, regdata+REG_NAME_SHIFT, regdata+REG_HDR_SHIFT);
 check_fmsg(CHKMSG_SKIP);
 if((tmp_stdout=new_stdout)==new_stderr&&!is_registered)
  new_stdout=stderr;
 msg_strcpy(strcpy_buf, M_VERSION);
 msg_cprintf(0, M_ARJ_BANNER, M_ARJ_BINDING, strcpy_buf, build_date);
 if(!is_registered&&!msg_strcmp((FMSG *)(regdata+REG_KEY2_SHIFT), M_REG_TYPE))
  msg_cprintf(0, M_REGISTERED_TO, regdata+REG_NAME_SHIFT);
 else
  msg_cprintf(0, (FMSG *)lf);
 new_stdout=tmp_stdout;
 proc_time=get_ticks();
 flist_init(&flist_exclusion, FCLIM_EXCLUSION, FL_STANDARD);
 #if defined(HAVE_EAS)
  flist_init(&flist_ea, FCLIM_EA, FL_STANDARD);
  flist_init(&flist_xea, FCLIM_EA, FL_STANDARD);
 #endif
 switch_char='\0';
 if(!disable_arj_sw)
 {
  if((arj_env_str=malloc_env_str(arj_env_name))!=NULL)
   parse_arj_sw(cmd, arj_env_str, header);
  else
  {
   #ifndef SKIP_GET_EXE_NAME
    split_name(exe_name, archive_name, NULL);
    msg_strcat(archive_name, M_ARJ_CFG);
    if(file_exists(archive_name))
     parse_arj_sw(cmd, archive_name, header);
   #else
    msg_strcpy(misc_buf, M_ARJ_CFG);
    sprintf(archive_name, "%s/.%s", getenv("HOME"), misc_buf);
    if(!file_exists(archive_name))
     sprintf(archive_name, "/etc/%s", misc_buf);
    if(file_exists(archive_name))
     parse_arj_sw(cmd, archive_name, header);
   #endif
   archive_name[0]='\0';                /* ASR fix */
  }
 }
 if(install_errhdl)
  ignore_errors=1;
 if(force_lfn)
  lfn_supported=LFN_SUPPORTED;
 if(use_ansi_cp==ANSICP_CONVERT)
  ansi_cpf=1;
 set_file_apis(use_ansi_cp);
 #ifndef NO_FATAL_ERROR_HDL
  if(win32_platform)
   install_smart_handler();
 #endif
 if(lfn_mode==LFN_NONE||lfn_mode==LFN_IGNORE)
  lfn_supported=LFN_NOT_SUPPORTED;
 if(lfn_supported!=LFN_NOT_SUPPORTED&&lfn_mode==LFN_DUAL)
  lfn_supported=LFN_COMP;
 is_registered=!is_registered;
 if(!is_registered&&regdata[REG_NAME_SHIFT]!='\0')
  wait_error(M_CRC_ERROR);
 cmd=0;
 if(rsp_name[0]=='\0')
 {
  for(cur_arg=1; cur_arg<argc; cur_arg++)
   cmd=parse_cmdline(argv[cur_arg], cmd);
 }
 else
 {
  stream=file_open_noarch(rsp_name, m_r);
  while(fgets(header, FILENAME_MAX, stream)!=NULL)
  {
   tmp_ptr=malloc_str(header);
   got_str=1;
   for(tptr=tmp_ptr; *tptr!='\0'; tptr++)
   {
    if(rsp_per_line)
    {
     if(*tptr==LF)
      *tptr='\0';
    }
    else if(*tptr==LF||*tptr==' ')
     *tptr='\0';
   }
   endptr=tptr;
   tptr=tmp_ptr;
   while((endptr-tptr)>0)
   {
    /* ASR fix: check for overrun -- 25/08/2001 */
    while(*tptr=='\0'&&((endptr-tptr)>0))
     tptr++;
    if((endptr-tptr)>0)
    {
     cmd=parse_cmdline(tptr, cmd);
     while(*tptr!='\0'&&((endptr-tptr)>0))
      tptr++;
    }
   }
  }
  fclose(stream);
  if(!got_str)
   error(M_CANTREAD);
 }
 if(install_errhdl)
  ignore_errors=1;
 if(force_lfn)
  lfn_supported=LFN_SUPPORTED;
 set_file_apis(use_ansi_cp);
 #ifndef NO_FATAL_ERROR_HDL
  if(win32_platform)
   install_smart_handler();
 #endif
 if(file_args>=0)
 {
  case_path(archive_name);
  finish_archive_name(archive_name);
 }
 for(j=0; j<file_args; j++)
 {
  tptr=f_arg_array[j];
  if(strcmp_os(tptr, nonexist_name))
  {
   if(is_directory(tptr))
    tptr=malloc_subdir_wc(tptr);
   f_arg_array[j]=tptr;
  }
 }
 if(lfn_mode==LFN_NONE||lfn_mode==LFN_IGNORE)
  lfn_supported=LFN_NOT_SUPPORTED;
 if(lfn_supported!=LFN_NOT_SUPPORTED&&lfn_mode==LFN_DUAL)
  lfn_supported=LFN_COMP;
 if(limit!=0)
  wait_error(M_CRC_ERROR);
 if(cmd==ARJ_CMD_CHK_INT)
 {
  if(archive_name[0]=='\0')
  {
   far_strcpyn((char FAR *)archive_name, (char FAR *)exe_name, FILENAME_MAX);
   if(!ansi_cpf)
    fix_ansi_name(archive_name);
  }
  set_file_apis(use_ansi_cp);
  if(check_integrity(archive_name))
   msg_cprintf(0, M_OK);
  else
  {
   arj_delay(BAD_CRC_DELAY);
   error(M_CRC_ERROR);
  }
  exit(ARJ_ERL_SUCCESS);
 }
 if(cmd==ARJ_CMD_RECOVER)
 {
  if(archive_name[0]=='\0')
   far_strcpyn((char FAR *)archive_name, (char FAR *)exe_name, FILENAME_MAX);
  set_file_apis(use_ansi_cp);
  name=(char *)malloc_msg(FILENAME_MAX);
  msg_strcpy(name, M_ARJFIXED_NAME);
  stream=file_create(name, m_wb);
  if(stream!=NULL)
   fclose(stream);
  free(name);
  msg_strcpy(tmp_tmp_filename, M_ARJFIXED_NAME);
  name=form_prot_name();
  if(!protfile_option)
   name[0]='\0';
  if(recover_file(archive_name, name, tmp_tmp_filename, 0, 0L))
  {
   tmp_tmp_filename[0]='\0';
   error(M_CANT_FIND_DAMAGE, archive_name);
  }
  msg_cprintf(H_HL|H_NFMT, M_REPAIRED_FILE, tmp_tmp_filename);
  tmp_tmp_filename[0]='\0';
  free(name);
  exit(ARJ_ERL_SUCCESS);
 }
 if(argc<2||help_issued||limit!=0)
 {
  check_fmsg(CHKMSG_NOSKIP);
  help_issued=1;
  #if TARGET==UNIX
   allow_any_attrs=FETCH_FILES;
  #endif
  set_file_apis(use_ansi_cp);
  strcpy(archive_name, exe_name);
  if(is_tty(stdout))
   prompt_for_more=!prompt_for_more;
  else
   prompt_for_more=0;
  indicator_style=IND_NONE;
  cmd=ARJ_CMD_PRINT;
  file_args=1;
  f_arg_array[0]=(argc<2)?brief_help:full_help;
 }
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   msg_cprintf(H_HL, M_LFN_ENABLED);
 #endif
 #if defined(HAVE_EAS)
  if(ea_supported)
   msg_cprintf(H_HL, M_EA_ENABLED);
 #endif
 case_path(archive_suffixes);
 case_path(swptr_t);
 case_path(archive_ext_list);
 case_path(target_dir);
 case_path(index_name);
 case_path(arjsec_env_name);
 case_path(list_file);
 case_path(swptr_hm);
 case_path(nonexist_name);
 case_path(arjcrypt_name);
 case_path(arjdisp_ptr);
 case_path(filename_to_restart);
 case_path(work_directory);
 case_path(extraction_filename);
 case_path(archive_cmt_name);
 case_path(comment_file);
 unix_path_to_dos(target_dir);
 unix_path_to_dos(index_name);
 unix_path_to_dos(arjsec_env_name);
 unix_path_to_dos(list_file);
 unix_path_to_dos(swptr_hm);
 unix_path_to_dos(nonexist_name);
 unix_path_to_dos(arjcrypt_name);
 unix_path_to_dos(arjdisp_ptr);
 unix_path_to_dos(filename_to_restart);
 unix_path_to_dos(work_directory);
 unix_path_to_dos(extraction_filename);
 unix_path_to_dos(archive_cmt_name);
 unix_path_to_dos(comment_file);
 cmd_setup(&cmd, &is_add_cmd);
 /* ASR fix: in the open-source release, there is no longer any distinction
    between commercial and shareware versions. Therefore, the code which
    checks for M_EXT_LIC has been removed. */
 #if TARGET!=DOS
  if(priority.class>0)
   set_priority(&priority);
 #endif
 if(run_cmd_at_start&&start_cmd[0]!='\0')
  exec_cmd(start_cmd);
 if(!exclude_files)
 {
  flist_cleanup(&flist_exclusion);
  flist_init(&flist_exclusion, FCLIM_EXCLUSION, FL_STANDARD);
 }
 flist_add_files(&flist_exclusion, NULL, arjtemp_wildcard, 0, 0, 0, NULL);
 if(filter_same_or_newer||filter_older)
  convert_time_limits();
 if(cmd==ARJ_CMD_WHERE||extm_mode)
  search_setup();
 else if(execute_cmd)
  get_exec_cmd();
 if(garble_enabled)
 {
  if(!strcmp(garble_password, "?"))
  {
   tptr=(char *)malloc_msg(INPUT_LENGTH+1);
   msg_cprintf(0, M_ENTER_PWD);
   read_line_noecho(tptr, INPUT_LENGTH);
   garble_password=malloc_str(tptr);
   if(is_add_cmd||cmd=='G')
   {
    msg_cprintf(0, M_VERIFY_PWD);
    read_line_noecho(tptr, INPUT_LENGTH);
    if(strcmp(tptr, garble_password))
     error(M_PWD_MISMATCH);
   }
   free(tptr);
  }
 }
 if(garble_password[0]=='\0'&&(cmd==ARJ_CMD_GARBLE||garble_enabled))
  error(M_NO_PWD_OPTION);
 limit=20;
 if(append_curtime)
  append_curtime_proc();
 if(is_add_cmd&&file_exists(archive_name))
 {
  tmp_archive_exists=1;
  if(tmp_archive_name==NULL)
  {
   tmp_archive_used=-1;
   tmp_archive_name=malloc_msg(FILENAME_MAX);
   tmp_archive_name[0]='\0';
   tmp_archive_used=0;
  }
  split_name(archive_name, tmp_archive_name, NULL);
  strcat(tmp_archive_name, arjtemp_spec);
  find_tmp_filename(tmp_archive_name);
  if(!stricmp(archive_name, tmp_archive_name))
   error(M_CANTRENAME, archive_name, tmp_archive_name);
  file_unlink(tmp_archive_name);
  tmp_archive_removed=1;
  rename_with_check(archive_name, tmp_archive_name);
 }
 set_file_apis(1);
 arj_exec_validation();
 set_file_apis(use_ansi_cp);
 #if TARGET!=UNIX
  if(cmd!=ARJ_CMD_ORDER)
   flist_type=find_dupl_drivespecs(f_arg_array, file_args)?FL_HASH:FL_STANDARD;
  else
   flist_type=FL_STANDARD;
 #else
  flist_type=FL_STANDARD;
 #endif
 numfiles=default_capacity;
 if((tptr=strchr(debug_opt, 'i'))!=NULL)
 {
  tptr++;
  numfiles=(FILE_COUNT)strtol(tptr, &tptr, 10);
 }
 if(strchr(debug_opt, 'q')!=NULL)
  flist_type=FL_STANDARD;
 flist_init(&flist_main, numfiles, (char)flist_type);
 flist_init(&flist_order, FILELIST_CAPACITY, (char)FL_STANDARD);
 if(is_add_cmd)
 {
  arch_wildcard_allowed=1;
  expand_wildcards=1;
 }
 else
  expand_wildcards=0;
 name=malloc_msg(FILENAME_MAX);
 for(j=limit; j<file_args; j++)
 {
  tptr=f_arg_array[j];
  if(listchars_allowed&&tptr[0]==listchar)
  {
   if(*++tptr=='\0')
    error(M_MISSING_FILENAME_ARG, f_arg_array[j]);
   sort_f=0;
   entry=split_name(tptr, NULL, NULL);
   if(cmd==ARJ_CMD_ORDER&&!stricmp(tptr+entry, sort_filename))
    sort_f=1;
   stream=file_open_noarch(tptr, m_r);
   tmp_ptr=header;
   order[j]=1;
   while(fgets(tmp_ptr, FILENAME_MAX, stream)!=NULL)
   {
    if(sort_f)
    {
     if(strlen(tmp_ptr)<=121)
      tmp_ptr[0]='\0';
     else if(tmp_ptr[120]==' ')
      strcpy(tmp_ptr, tmp_ptr+121);
    }
    if(cmd==ARJ_CMD_ORDER&&strpbrk(tmp_ptr, wildcard_pattern)!=NULL)
     error(M_ORDER_WILDCARD);
    cnv_cmdline_fnm(tmp_ptr);
    if(tmp_ptr[0]!='\0')
    {
     name[0]='\0';
     if(is_add_cmd)
      strcat(name, target_dir);
     strcat(name, tmp_ptr);
     count=0;
     if(flist_add_files(&flist_main, &flist_exclusion, name, expand_wildcards, recurse_subdirs, allow_any_attrs, &count))
     {
      j=file_args;
      break;
     }
     if(listfile_err_opt&&count!=0)
     {
      if(flist_add(&flist_order, NULL, name, NULL, NULL))
      {
       j=file_args;
       break;
      }
     }
    }
   }
   fclose(stream);
  }
  else
  {
   if(cmd==ARJ_CMD_ORDER&&strpbrk(f_arg_array[j], wildcard_pattern))
    error(M_ORDER_WILDCARD);
   name[0]='\0';
   if(is_add_cmd)
    strcat(name, target_dir);
   strcat(name, f_arg_array[j]);
   count=0;
   if(flist_add_files(&flist_main, &flist_exclusion, name, expand_wildcards, recurse_subdirs, allow_any_attrs, &count))
   {
    if(strchr(debug_opt, 'i')!=NULL)
     order[j]=count;
    break;
   }
   order[j]=count;
  }
 }
 if(tmp_archive_removed)
 {
  rename_with_check(tmp_archive_name, archive_name);
  tmp_archive_name[0]='\0';
  tmp_archive_removed=0;
 }
 if(create_list_file)
 {
  stream=file_create(list_file, m_w);
  for(cur_file=0; cur_file<flist_main.files; cur_file++)
  {
   flist_retrieve(name, NULL, &flist_main, cur_file);
   strcat(name, lf);
   if(fputs(name, stream)==EOF)
    error(M_DISK_FULL);
  }
  fclose(stream);
 }
 cfa_init(flist_main.files+1);
 if(restart_at_filename)
  restart_proc(tmp_ptr=header);
 free(name);
 if(create_index)
 {
  idxstream=file_open(index_name, m_a);
  if(msg_fprintf(idxstream, M_INDEX_HDR)<0)
   error(M_DISK_FULL);
 }
 if(cmd==ARJ_CMD_ORDER)
 {
  fnm_matching=FMM_FULL_PATH;
  arch_hdr_index=farmalloc_msg(((unsigned long)flist_main.files+1L)*sizeof(unsigned long));
  for(cur_file=0; cur_file<flist_main.files; cur_file++)
   arch_hdr_index[cur_file]=0L;
 }
 if(!reg_validation(single_spc, single_spc, single_spc, regdata+REG_HDR_SHIFT))
  limit=20;
 flist_init(&flist_archive, FCLIM_ARCHIVE, FL_STANDARD);
 flist_add_files(&flist_archive, NULL, archive_name, !is_add_cmd, is_add_cmd?0:recurse_subdirs, allow_any_attrs, NULL);
 if(flist_archive.files==0)
 {
  msg_cprintf(H_ERR, M_CANT_FIND, archive_name);
  errorlevel=ARJ_ERL_CANTOPEN;
  errors++;
 }
 if(debug_enabled&&strchr(debug_opt, 't')!=NULL)
  msg_cprintf(H_HL|H_NFMT, M_N_TICKS, get_ticks()-ticks);
 check_fmsg(CHKMSG_SKIP);
 if(quiet_mode==ARJ_QUIET2)
  new_stdout=new_stderr;
 /* The main processing loop */
 for(cur_file=limit; cur_file<flist_archive.files; cur_file++)
 {
  if(quiet_mode==ARJ_QUIET2)
   new_stdout=new_stderr;
  flist_retrieve(archive_name, NULL, &flist_archive, cur_file);
  perform_cmd(cmd);
  if(cur_file+1<flist_archive.files)
   nputlf();
 }
 file_arg_cleanup(&flist_order);
 errno=0;
 if(errors>0)
  error(M_FOUND_N_ERRORS, errors);
 return(errorlevel);
}
