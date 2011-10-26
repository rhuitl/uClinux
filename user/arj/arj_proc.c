/*
 * $Id: arj_proc.c,v 1.15 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file  contains many  of the functions  that  are called by various ARJ
 * modules. Everything is OS-independent, all OS-dependent  procedures must be
 * moved to ENVIRON.C.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Other defines */

#define FNAME_FLEN                27	/* Length of formatted filename */

/* String table (may need some localization in the future...) */

#if SFX_LEVEL>=ARJ||defined(REARJ)
static char strtime_filler[]="00000000000000";
#endif
#if SFX_LEVEL>=ARJ
static char time_tail_pattern[]="%04d%02d%02d%03d%02d%02d%02d";
static char date_digit_format[]="%04d%02d%02d";
static char allowed_attrs[]=TAG_LIST;
static char vol_st_id[]=" - ";          /* A substring of M_NEXT_VOL_STATS */
#endif
#if SFX_LEVEL>=ARJSFXV
static char nonexistent_name[]="...";
#endif

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)

/* The first byte in integrity_pattern[] is changed to avoid confusion with the
   pattern to search */

static unsigned char integrity_pattern[]={0xB1, 0x03, 0xB0, 0x02, 0xB0, 0x03, 0xB0,
                                          0x04, 0xB0, 0x05, 0};

#endif

#if SFX_LEVEL>=ARJ
static int hswitch;                     /* Indicates that we have a "-h..." */
static int jswitch;                     /* Indicates that we have a "-j..." */
static int os2switch;                   /* ARJ/2 switches (-h2, -2) */
static int noswitch;
#endif

#if SFX_LEVEL>=ARJ
static
int *sw_index[]={&jswitch, &hswitch, &allow_any_attrs, &filter_fa_arch,
                 &skip_ts_check, &delete_processed, &exclude_paths,
                 &freshen_criteria, &garble_enabled, &indicator_style,
                 &keep_bak, &create_list_file, &custom_method, &new_files_only,
                 &filter_same_or_newer, &fnm_matching, &query_for_each_file,
                 &recurse_subdirs, &timestamp_override, &type_override,
                 &update_criteria, &multivolume_option, &assign_work_directory,
                 &exclude_files, &yes_on_all_queries, &use_comment,
                 &help_issued, &listchars_allowed, &handle_labels, &disable_arj_sw,
                 &select_by_number, &install_errhdl, &quiet_mode,
                 &rsp_per_line, &noswitch, &lowercase_names, NULL};
static
int *jsw_index[]={&jswitch, &comment_display, &chapter_mode, &exit_after_count,
                  &chk_free_space, &create_sfx, &validate_style, &select_backup_files,
                  &jh_enabled, &create_index, &keep_tmp_archive, &show_filenames_only,
                  &max_compression, &restart_at_filename, &serialize_exts,
                  &prompt_for_more, &set_string_parameter, &ignore_crc_errors,
                  &store_by_suffix, &test_archive_crc, &translate_unix_paths,
                  &verbose_display, &extract_to_file, &start_at_ext_pos,
                  &assume_yes, &supply_comment_file, &hollow_mode, &skip_time_attrs,
                  NULL};
static
int *hsw_index[]={&hswitch, &clear_archive_bit, &filter_attrs, &run_cmd_at_start,
                  &debug_enabled, &arjsec_opt, &lfn_mode, &gost_cipher,
                  &detailed_index, &protfile_option, &listfile_err_opt,
                  &filelist_storage, &nonexist_filespec, &extm_mode,
                  &arjdisp_enabled, &ignore_open_errors, &ignore_archive_errors,
                  &disable_sharing, &set_target_directory, &allow_mv_update,
                  &chk_arj_version, &search_mode, &override_archive_exts,
                  &use_ansi_cp, &sign_with_arjsec, &append_curtime,
                  &marksym_expansion, &force_lfn, &noswitch, NULL};
static
int *os2sw_index[]={&os2switch, &arcmail_sw, &noswitch, &crit_eas, &dos_host,
                    &include_eas, &disable_comment_series, &suppress_hardlinks,
                    &start_with_seek, &skip_century, &fix_longnames, &do_chown,
                    &priority.class, &recursion_order, &symlink_accuracy, &noswitch,
                    &exclude_eas, NULL};

static
int *jysw_index[]={&skip_append_query, &prompt_for_mkdir, &query_delete,
                   &skip_space_query, &skip_rename_prompt, &overwrite_existing,
                   &kbd_cleanup_on_input, &skip_scanned_query,
                   &skip_next_vol_query, &accept_shortcut_keys, NULL};
#elif SFX_LEVEL==ARJSFXV
static
int *sw_index[]={&skip_integrity_test, &prompt_for_directory, &skip_ts_check,
                 &chk_free_space, &extract_expath, &freshen_criteria,
                 &garble_enabled, &help_issued, &indicator_style,
                 &process_lfn_archive, &skip_preset_options, &list_sfx_cmd,
                 &overwrite_ro, &new_files_only, &gost_cipher, &fnm_matching,
                 &ignore_crc_errors, &disable_sharing, &test_sfx_cmd,
                 &update_criteria, &verbose_list, &extract_to_file,
                 &extract_cmd, &yes_on_all_queries, &assume_yes, &help_issued,
                 &skip_volumes, &debug_enabled, &quiet_mode, &handle_labels,
                 &arjdisp_enabled, &execute_extr_cmd, &lowercase_names, NULL};
static
int *jysw_index[]={&skip_append_query, &prompt_for_mkdir, &skip_space_query,
                   &skip_extract_query, &skip_rename_prompt, &overwrite_existing,
                   &kbd_cleanup_on_input, &skip_next_vol_query, NULL};
#elif SFX_LEVEL==ARJSFX
static
int *sw_index[]={&extract_expath, &list_sfx_cmd, &test_sfx_cmd, &verbose_list,
                 &extract_cmd, &show_ansi_comments, &prompt_for_directory,
                 &skip_ts_check, &arjdisp_enabled, &freshen_criteria,
                 &garble_enabled, &indicator_style, &process_lfn_archive,
                 &verbose_display, &make_directories, &new_files_only,
                 &overwrite_existing, &fnm_matching, &skip_integrity_test,
                 &update_criteria, &skip_extract_query, &yes_on_all_queries,
                 &quiet_mode, &help_issued, &help_issued, &execute_extr_cmd};
#endif

/* Local functions */

#if SFX_LEVEL>=ARJ
 static int compare_exts(char *name, char *pad);
#endif

#if SFX_LEVEL>=ARJ

/* Encodes a block of data */

void garble_encode_stub(char *data, int len)
{
 garble_encode(data, len);
}

/* Decodes a block of data */

void garble_decode_stub(char *data, int len)
{
 garble_decode(data, len);
}

#endif

#if SFX_LEVEL>=ARJ

/* Returns day of year */

static int day_of_year(struct tm *tms)
{
 int m, y, rc;

 rc=0;
 for(m=tms->tm_mon; m>0; m--)
 {
  switch(m)
  {
   case 1: rc+=31; break;
   case 2:
    rc+=28;
    y=tms->tm_year+1900;
    if((y%4==0)&&(y%100!=0||y%400==0))
     rc++;
    break;
   case 3: rc+=31; break;
   case 4: rc+=30; break;
   case 5: rc+=31; break;
   case 6: rc+=30; break;
   case 7: rc+=31; break;
   case 8: rc+=31; break;
   case 9: rc+=30; break;
   case 10: rc+=31; break;
   case 11: rc+=30; break;
  }
 }
 return(rc+tms->tm_mday);
}

/* Appends current date/time to the archive filename in accordance with the
   "-h#" option */

void append_curtime_proc()
{
 time_t curtime;
 struct tm *tms;
 char time_pad[19];
 char ext[32];
 char *ext_pos;
 char *aptr, *tptr;
 char *dptr=time_pad;                   /* ASR fix for High C -- 29/03/2001 */
 int l, lim;
 int doy;                               /* Day of year */

 curtime=time(NULL);
 tms=localtime(&curtime);
 doy=day_of_year(tms);
 sprintf(time_pad, time_tail_pattern, tms->tm_year+1900, tms->tm_mon+1,
         tms->tm_mday, doy, tms->tm_hour, tms->tm_min, tms->tm_sec);
 if((ext_pos=strchr(archive_name+split_name(archive_name, NULL, NULL), '.'))!=NULL)
 {
  strncpy(ext, ext_pos, sizeof(ext));
  *ext_pos='\0';
 }
 else
  ext[0]='\0';
 if(time_str[0]=='\0')
 {
  if(append_curtime==ATS_DUAL)
   strcat(archive_name, time_pad+7);
  else if(append_curtime==ATS_TIME)
   strcat(archive_name, time_pad+8);
  else if(append_curtime==ATS_DATE)
  {
   time_pad[8]='\0';
   strcat(archive_name, time_pad+2);
  }
 }
 else                                   /* Custom format */
 {
  l=strlen(time_str);
  aptr=archive_name+strlen(archive_name)+l;
  *aptr='\0';
  lim=0;
  for(tptr=time_str+l-1; (tptr-time_str)>=0; tptr--)
  {
   if(*tptr==*(tptr+1))
    *(--aptr)=(lim>0)?dptr[--lim]:*tptr;
   else
   {
    switch(*tptr)
    {
     case 'Y':
      dptr=time_pad;
      lim=4;
      *(--aptr)=dptr[--lim];
      break;
     case 'M':
      dptr=time_pad+4;
      lim=2;
      *(--aptr)=dptr[--lim];
      break;
     case 'D':
      dptr=time_pad+6;
      lim=2;
      *(--aptr)=dptr[--lim];
      break;
     case 'N':
      dptr=time_pad+8;
      lim=3;
      *(--aptr)=dptr[--lim];
      break;
     case 'h':
      dptr=time_pad+11;
      lim=2;
      *(--aptr)=dptr[--lim];
      break;
     case 'm':
      dptr=time_pad+13;
      lim=2;
      *(--aptr)=dptr[--lim];
      break;
     case 's':
      dptr=time_pad+15;
      lim=2;
      *(--aptr)=dptr[--lim];
      break;
     default:
      *(--aptr)=*tptr;
    }
   }
  }
 }
 strcat(archive_name, ext);
}

/* Adds an ending backslash to the given pathname if it doesn't contain one */

void add_pathsep(char *path)
{
 int len;

 if((len=strlen(path))==0)              /* Maybe current path? */
  return;
 if(strchr(path_separators, path[len-1])==NULL)
 {
  path[len]=PATHSEP_DEFAULT;
  path[len+1]='\0';
 }
}

/* Converts the timestamps given by the user to the internal storage format */

void convert_time_limits()
{
 char *cptr;
 time_t tmp_ts;
 time_t ts;
 struct tm *tms;
 struct timestamp arj_ts;               /* ARJ-format timestamp storage */

 if(filter_same_or_newer==TCHECK_NDAYS)
 {
  tmp_ts=strtoul(timestr_newer, &cptr, 10)*(-86400L);
  ts=sum_time(tmp_ts, time(NULL));
  tms=localtime(&ts);
  if(tms==NULL)                         /* ASR fix 21/02/2001 -- IBM LIBC */
   error(M_INVALID_DATE);
  sprintf(misc_buf, date_digit_format, tms->tm_year+1900, tms->tm_mon+1, tms->tm_mday);
  timestr_newer=malloc_str(misc_buf);   /* MEMORY LEAK! (Never freed) */
 }
 if(filter_older==TCHECK_NDAYS)
 {
  tmp_ts=strtoul(timestr_older, &cptr, 10)*(-86400L);
  ts=sum_time(tmp_ts, time(NULL));
  tms=localtime(&ts);
  if(tms==NULL)                         /* ASR fix 21/02/2001 -- IBM LIBC */
   error(M_INVALID_DATE);
  sprintf(misc_buf, date_digit_format, tms->tm_year+1900, tms->tm_mon+1, tms->tm_mday);
  timestr_older=malloc_str(misc_buf);   /* MEMORY LEAK! (Never freed) */
 }
 if(timestr_older[0]!='\0')
  convert_strtime(&tested_ftime_older, timestr_older);
 if(timestr_newer[0]!='\0')
  convert_strtime(&tested_ftime_newer, timestr_newer);
 if(timestr_older[0]=='\0'&&timestr_newer[0]=='\0')
 {
  ts=time(NULL);
  tms=localtime(&ts);
  make_timestamp(&arj_ts, tms->tm_year, tms->tm_mon+1, tms->tm_mday, 0, 0, 0);
  if(timestr_newer[0]=='\0')
   tested_ftime_newer=arj_ts;
  if(timestr_older[0]=='\0')
   tested_ftime_older=arj_ts;
 }
}

/* Analyzes ARJ_SW settings */

void parse_arj_sw(int cmd, char *arj_sw, char *dest)
{
 int use_file;                          /* 1 if ARJ_SW represents a file */
 char *buf;
 char *dptr, *varname;
 char *sptr;
 FILE *stream;
 char *sw, *sw_p;

 use_file=0;
 while(arj_sw[0]==' ')
  arj_sw++;
 if(strchr(switch_chars, arj_sw[0])==NULL)
 {
  buf=dest;
  dptr=dest+FILENAME_MAX+1;
  sptr=dest+FILENAME_MAX*2+2;
  sptr[0]='\0';
  dptr[0]='\0';
  stream=file_open_noarch(arj_sw, m_r);
  while(fgets(buf, FILENAME_MAX, stream)!=NULL)
  {
   strip_lf(buf);
   if(buf[0]=='#')
    continue;
   else if(!use_file&&buf[0]=='+'&&buf[1]==' ')
   {
    strcpy(sptr, buf+1);
    use_file=1;
   }
   else if(!use_file&&buf[0]=='-'&&buf[1]==' ')
   {
    strcat(dptr, buf+2);
    strcat(dptr, " ");
    use_file=1;
   }
   else if((cmd==ARJ_CMD_ADDC&&!strnicmp(buf, "AC ", 3))||
           (cmd==ARJ_CMD_CNVC&&!strnicmp(buf, "CC ", 3))||
           (cmd==ARJ_CMD_DELC&&!strnicmp(buf, "DC ", 3)))
   {
    strcpy(dptr, buf+3);
    use_file=1;
    break;
   }
   else
   {
    if(toupper((int)buf[0])==cmd&&buf[1]==' ')
    {
     strcpy(dptr, buf+2);
     use_file=1;
     break;
    }
   }
  }
  fclose(stream);
  strcat(dptr, sptr);
  sw=malloc_str(dptr);
 }
 else
  sw=malloc_str(arj_sw);
 varname=use_file?arj_sw:arj_env_name;
 sw_p=malloc_str(sw);
 /* Tokenize switch */
 for(dptr=sw; *dptr!='\0'; dptr++)
  if(*dptr==' ')
   *dptr='\0';
 sptr=dptr;
 dptr=sw;
 while((dptr-sptr)<0)
 {
  while(*dptr=='\0')
   dptr++;
  if((dptr-sptr)<0)
  {
   if(is_switch(dptr))
    analyze_arg(dptr);
   while(*dptr!='\0'&&(dptr-sptr)<0)
    dptr++;
  }
 }
 if(!translate_unix_paths)
  switch_char=0;
 msg_cprintf(H_HL|H_NFMT, M_USING_ENV_VAR, varname, sw_p);
 free(sw_p);
}

/* Copies a part of archive */

void copy_bytes(unsigned long nbytes)
{
 char *buf;
 unsigned int fetch_size;

 buf=malloc_msg(PROC_BLOCK_SIZE);
 fseek(aistream, 0L, SEEK_SET);
 while(nbytes>0L)
 {
  fetch_size=(unsigned int)min(PROC_BLOCK_SIZE, nbytes);
  if(fread(buf, 1, fetch_size, aistream)!=fetch_size)
   error(M_CANTREAD);
  if(fwrite(buf, 1, fetch_size, aostream)!=fetch_size)
   error(M_DISK_FULL);
  nbytes-=(unsigned long)fetch_size;
 }
 free(buf);
}

/* Returns 1 if the given filename did not contain any UNIX-style ('/') path
   separators, and all native path separators have been converted to UNIX-style
   ones ('/'). 0 is returned if the filename initially contained a UNIX-style
   separator. When it returns 1, the PATHSYM_FLAG in arj_flags is set by parent
   procedure. */

int translate_path(char *name)
{
 int i;

 if(strchr(name, PATHSEP_UNIX)!=NULL)
  return(0);
 for(i=0; name[i]!=0; i++)
  if(name[i]==PATHSEP_DEFAULT)
   name[i]=PATHSEP_UNIX;
 return(1);
}

/* Restarts archive processing from the specified file */

void restart_proc(char *dest)
{
 char *r_name, *c_name;
 char *dptr;
 char vol_stats[40];
 char *vs_ptr;
 int i;
 int vs_match;
 int vn=0, vc=0;                        /* ASR fix for High C -- 29/03/2001 */
 unsigned long vs=0;                    /* ASR fix for High C -- 29/03/2001 */
 FILE_COUNT cur_file;
 int nd;

 dptr=dest;
 r_name=malloc_msg(FILENAME_MAX);
 c_name=malloc_msg(FILENAME_MAX);
 strcpy(r_name, filename_to_restart);
 msg_strcpy(vol_stats, M_NEXT_VOLUME_STATS);
 vs_ptr=vol_stats;
 i=0;
 while(*vs_ptr!='\0')
 {
  if(!strncmp(vs_ptr, vol_st_id, sizeof(vol_st_id)-1))
   break;
  i++;
  vs_ptr++;
 }
 i+=sizeof(vol_st_id)-1;
 if(filename_to_restart[0]=='\0'&&index_name[0]!='\0')
 {
  vs_match=0;
  r_name[0]='\0';
  idxstream=file_open_noarch(index_name, m_r);
  while(fgets(dptr, FILENAME_MAX, idxstream)!=NULL)
  {
   strip_lf(dptr);
   if(!memcmp(dptr, vol_stats, i))
   {
    vs_match=1;
    vn=atoi(dptr+i);
    vc=atoi(dptr+i+4);
    vs=atoi(dptr+i+6);
    strcpy(r_name, dptr+i+17);
   }
  }
  fclose(idxstream);
  if(vs_match==0)
   error(M_RESTART_INFO_NF);
  else
  {
   resume_volume_num=vn;
   if(vc==1)
   {
    start_at_ext_pos=1;
    ext_pos=vs;
   }
   else if(vc==2)
    error(M_NOTHING_TO_DO);
  }
 }
 for(cur_file=0L; cur_file<flist_main.files; cur_file++)
 {
  flist_retrieve(c_name, NULL, &flist_main, cur_file);
  if(!strcmp_os(c_name, r_name))
   break;
  cfa_store(cur_file, FLFLAG_DELETED);
 }
 if(cur_file>=flist_main.files)
  error(M_CANT_FIND_RST_FILE, r_name);
 free(c_name);
 free(r_name);
 if(create_sfx)
 {
  nd=split_name(archive_name, NULL, NULL);
  vs_ptr=strchr(archive_name+nd, '.');
  if(vs_ptr==NULL)
   msg_strcat(archive_name, M_EXE_EXT);
  else
   msg_strcpy(vs_ptr, M_EXE_EXT);
 }
}

/* Looks for an extension of the given filename in the extension list */

int search_for_extension(char *name, char *ext_list)
{
 int match;
 char *endptr;
 char ext_pad[EXTENSION_MAX+1];
 char *t_ptr;
 int i;

 match=0;
 endptr=&ext_list[strlen(ext_list)];
 t_ptr=ext_list;
 while(t_ptr!=endptr)
 {
  if(*t_ptr=='.')
   t_ptr++;
  ext_pad[0]='.';
  for(i=0; i<EXTENSION_MAX&&t_ptr[i]!='\0'&&t_ptr[i]!='.'; i++)
   ext_pad[i+1]=t_ptr[i];
  ext_pad[i+1]='\0';
  if(compare_exts(name, ext_pad))
  {
   match=1;
   break;
  }
  else
  {
   while(*t_ptr!='\0'&&*t_ptr!='.')
    t_ptr++;
  }
 }
 return(match);
}

/* Returns the exact amount of data that could be safely written to the
   destination volume */

unsigned long get_volfree(unsigned int increment)
{
 unsigned long pvol;
 unsigned int arjsec_overhead;
 long remain;

 if(increment==0||volume_flag_set)
 {
  volume_flag_set=1;
  return(0);
 }
 pvol=0L;
 if(arjprot_tail)
  pvol=calc_protdata_size(volume_limit, prot_blocks);
 else if(protfile_option)
  pvol=calc_protdata_size(volume_limit, protfile_option);
 arjsec_overhead=sign_with_arjsec?ARJSEC_SIG_MAXLEN+1:0;
 remain=volume_limit-ftell(aostream)-pvol-(long)arjsec_overhead-
        (long)out_bytes-(long)cpos-(long)ext_voldata-
        MULTIVOLUME_RESERVE-t_volume_offset;
 return((unsigned long)min(remain, (unsigned long)increment));
}

/* Performs various checks when multivolume data is packed to predict an
   overrun. Returns number of bytes that could be successfully written. */

unsigned int check_multivolume(unsigned int increment)
{
 unsigned long pvol;
 unsigned int arjsec_overhead;
 long remain;
 unsigned int inc, rc;

 if(!file_packing)
  return(increment);
 if(increment==0||volume_flag_set)
 {
  volume_flag_set=1;
  return(0);
 }
 pvol=0L;
 if(protfile_option)
  pvol=calc_protdata_size(volume_limit, protfile_option);
 arjsec_overhead=sign_with_arjsec?ARJSEC_SIG_MAXLEN+1:0;
 /* Split this expression to work around High C bugs -- ASR 14/08/2001 */
 remain=volume_limit-ftell(aostream)-pvol-(long)arjsec_overhead;
 stop_optimizer();
 remain-=(long)out_bytes+(long)cpos+(long)ext_voldata;
 stop_optimizer();
 remain-=(long)MULTIVOLUME_RESERVE+(long)t_volume_offset;
 /* Now decrement the buffer size until we fit the remainder */
 while((long)bufsiz*2L>remain&&bufsiz>MIN_CRITICAL_BUFSIZ)
  bufsiz>>=1;
 if(bufsiz<MIN_CRITICAL_BUFSIZ)
  bufsiz=MIN_CRITICAL_BUFSIZ;
 if((long)increment+1000L<remain&&(long)increment*2L<remain)
  return(increment);
 inc=0;
 if((long)increment<remain)
  inc=increment;
 else if(remain>0)
  inc=remain;
 if(inc<=0)
 {
  volume_flag_set=1;
  return(0);
 }
 if((long)increment*2L>remain)
 {
  if(inc>1000)
   rc=(inc-inc%500)>>1;
  else if(inc>2000)
   rc=inc-1000;
  else
   rc=(inc>512)?inc>>1:inc;
 }
 /* Mistrust the return value. That would help to get around certain compiler
    optimization bugs (as with OpenWatcom v 1.1RC) - at least the wrong value
    won't be passed to fread() causing buffer overrun. */
 return(min(rc, increment));
}

/* Compares the extension from pad with the file's extension. Returns 1 if
   there was a match. */

static int compare_exts(char *name, char *pad)
{
 int k;

 /* si = name, di = pad */
 if(strlen(pad)==1&&strchr(name, '.')==NULL)
  return(1);
 k=strlen(name)-strlen(pad);
 if(k<0)
  return(0);
 else
  return(strcmp_os(name+k, pad)==0);
}

/* "Stores" a file by simply copying it */

void store()
{
 int fetch_size;
 unsigned int mem_size;
 char *fetch;
 int to_read;

 fetch=(char *)malloc_msg(PROC_BLOCK_SIZE);
 mem_stats();
 origsize=0L;
 cpos=0;
 ext_voldata=0;
 display_indicator(0L);
 crc32term=CRC_MASK;
 to_read=PROC_BLOCK_SIZE;
 if(multivolume_option&&file_packing)
  to_read=check_multivolume(to_read);
 if(file_packing)
 {
  while((fetch_size=fread_crc(fetch, to_read, encstream))>0)
  {
   if(garble_enabled)
    garble_encode_stub(fetch, fetch_size);
   if(!no_file_activity)
   {
    file_write(fetch, 1, fetch_size, aostream);
   }
   display_indicator(origsize);
   if(multivolume_option)
    to_read=check_multivolume(to_read);
  }
 }
 else
 {
  while(encmem_remain!=0)
  {
   mem_size=min((unsigned int)PROC_BLOCK_SIZE, encmem_remain);
   far_memmove((char FAR *)fetch, encblock_ptr, mem_size);
   crc32_for_block(fetch, mem_size);
   if(garble_enabled)
    garble_encode_stub(fetch, mem_size);
   far_memmove(packblock_ptr, (char FAR *)fetch, mem_size);
   encblock_ptr+=mem_size;
   packblock_ptr+=mem_size;
   origsize+=mem_size;
   encmem_remain-=mem_size;             /* Changed this order. This is an ASR
                                           fix for High C beta -- 05/04/2001 */
  }
 }
 free(fetch);
 compsize=origsize;
}

/* Performs a "hollow" file processing (just calculates the CRC) */

void hollow_encode()
{
 int fetch_size;
 char *fetch;

 fetch=(char *)malloc_msg(PROC_BLOCK_SIZE);
 mem_stats();
 origsize=0L;
 out_bytes=0;
 cpos=0;
 ext_voldata=0;
 display_indicator(0L);
 crc32term=CRC_MASK;
 fetch_size=PROC_BLOCK_SIZE;
 while(fread_crc(fetch, fetch_size, encstream)!=0)
  display_indicator(origsize);
 free(fetch);
 compsize=0L;
}

#endif

#if SFX_LEVEL>=ARJ||defined(REARJ)

/* Retrieves a pair of decimal digits from the given pointer */

static int get_dec_pair(char *str)
{
 if(str[0]=='\0')
  return(0);
 if(str[1]=='\0')
  return((int)str[0]-'0');
 return((int)(str[0]-'0')*10+(int)(str[1]-'0'));
}

/* Converts the given time string ("yyyymmddhhmmss") to the internal timestamp
   format */

void convert_strtime(struct timestamp *dest, char *str)
{
 char tmp_strtime[30];
 int y, m, d, hh, mm, ss;               /* Timestamp components */

 strncpy(tmp_strtime, str, 14);
 tmp_strtime[14]='\0';
 strcat(tmp_strtime, strtime_filler);
 y=get_dec_pair(tmp_strtime);
 if(y>=19&&y<80)
 {
  y=y*100+get_dec_pair(tmp_strtime+2);
  m=get_dec_pair(tmp_strtime+4);
  d=get_dec_pair(tmp_strtime+6);
  hh=get_dec_pair(tmp_strtime+8);
  mm=get_dec_pair(tmp_strtime+10);
  ss=get_dec_pair(tmp_strtime+12);
 }
 else
 {
  m=get_dec_pair(tmp_strtime+2);
  d=get_dec_pair(tmp_strtime+4);
  hh=get_dec_pair(tmp_strtime+6);
  mm=get_dec_pair(tmp_strtime+8);
  ss=get_dec_pair(tmp_strtime+10);
  y+=(y>=80)?1900:2000;
 }
 if(m<1||m>12||d<1||d>31||hh>23||mm>59||ss>59)
  error(M_INVALID_DATE_STRING, str);
 make_timestamp(dest, y, m, d, hh, mm, ss);
}

#endif

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)

/* Checks integrity of the executable file */

int check_integrity(char *name)
{
 #if SFX_LEVEL>=ARJ
  char *buf;
  int f_len=PROC_BLOCK_SIZE;
 #else
  char buf[CACHE_SIZE];
  int f_len=CACHE_SIZE;
 #endif
 FILE *stream;
 int p_len;
 int fetch, i;
 int c;
 char *bptr;
 unsigned long wr_pos;
 unsigned long fsize, cur_pos;
 char pattern[20];
 unsigned long st_crc, st_fsize;        /* Stored parameters */

 #if SFX_LEVEL>=ARJ
  buf=(char *)malloc_msg(f_len);
 #endif
 stream=file_open(name, m_rb);
 if(stream==NULL)
 {
  msg_cprintf(H_ERR, M_CANTOPEN, name);
  #if SFX_LEVEL>=ARJ
   nputlf();
   return(0);
  #else
   return(1);
  #endif
 }
 strcpy(pattern, (char *)integrity_pattern);
 pattern[0]--;
 p_len=strlen(pattern);
 fseek(stream, 0L, SEEK_END);
 fsize=ftell(stream);
 fseek(stream, 0L, SEEK_SET);
 crc32term=CRC_MASK;
 cur_pos=0L;
 while(1)
 {
  fseek(stream, cur_pos, SEEK_SET);
  fetch=fread(buf, 1, f_len, stream);
  if(fetch==0)
   #if SFX_LEVEL>=ARJSFXV
    error(M_CANTREAD);
   #else
    pause_error(M_NO_INTEGRITY_PATTERN);
   #endif
  fetch-=p_len;
  bptr=buf;
  for(i=0; i<fetch; i++)
  {
   if(!memcmp(bptr, pattern, p_len))
    break;
   bptr++;
  }
  if(i<fetch)
   break;
  cur_pos+=f_len/2;                     /* Dirty hack */
 }
 wr_pos=(long)i+cur_pos+p_len;
 fseek(stream, wr_pos, SEEK_SET);
 if(fread(&st_crc, 1, 4, stream)!=4)
  #if SFX_LEVEL>=ARJSFXV
   error(M_CANTREAD);
  #else
   pause_error(M_NO_INTEGRITY_PATTERN);
  #endif
 if(fread(&st_fsize, 1, 4, stream)!=4)
  #if SFX_LEVEL>=ARJSFXV
   error(M_CANTREAD);
  #else
   pause_error(M_NO_INTEGRITY_PATTERN);
  #endif
 #ifdef WORDS_BIGENDIAN   /* Another dirty hack */
 st_crc   = mget_dword((char*) &st_crc);
 st_fsize = mget_dword((char*) &st_fsize);
 #endif 
 crc32term=CRC_MASK;
 fseek(stream, 0L, SEEK_SET);
 for(cur_pos=0L; cur_pos<wr_pos; cur_pos++)
 {
  if((c=fgetc(stream))==-1)
   #if SFX_LEVEL>=ARJSFXV
    error(M_CANTREAD);
   #else
    pause_error(M_NO_INTEGRITY_PATTERN);
   #endif
  crc32term=crc32_for_char(crc32term, (unsigned char)c);
 }
 cur_pos+=8L;
 fseek(stream, cur_pos, SEEK_SET);
 while(cur_pos<fsize)
 {
  if((c=fgetc(stream))==-1)
   #if SFX_LEVEL>=ARJSFXV
    error(M_CANTREAD);
   #else
    pause_error(M_NO_INTEGRITY_PATTERN);
   #endif
  crc32term=crc32_for_char(crc32term, (unsigned char)c);
  cur_pos++;
 }
 fsize+=2L;
 #if SFX_LEVEL>=ARJ
  free(buf);
 #endif
 fclose(stream);
 #if SFX_LEVEL>=ARJSFXV
  return(crc32term==st_crc&&fsize==st_fsize);
 #else
  if(crc32term==st_crc&&fsize==st_fsize)
   msg_cprintf(0, M_INTEGRITY_OK);
  else
   pause_error(M_INTEGRITY_VIOLATED);
  return(0);
 #endif
}

#endif

/* Converts a filename to the format used in current OS (simply substitutes
   the UNIX separators with DOS ones) */

void name_to_hdr(char *name)
{
 int i;

 for(i=0; name[i]!='\0'; i++)
 {
  if(name[i]==PATHSEP_UNIX)
   name[i]=PATHSEP_DEFAULT;
 }
}

#if SFX_LEVEL>=ARJSFXV

/* Formats the given filename to look properly in the "Adding..." and other
   messages. */

char *format_filename(char *name)
{
 int f_pos, tf_pos;
 char *result;
 int ctr;                               /* Path delimiter counter */
 int len;
 static char name_holder[FNAME_FLEN+1];
 int i;

 if(show_filenames_only)
  f_pos=split_name(name, NULL, NULL);
 else
  f_pos=0;
 tf_pos=f_pos;
 ctr=1;
 while(name[tf_pos]!='\0')
 {
  if(tf_pos>0&&name[tf_pos]==PATHSEP_DEFAULT)
   ctr++;
  tf_pos++;
 }
 len=ctr*CCHMAXPATH+ctr;
 if(len>FNAME_FLEN-1)
  len=FNAME_FLEN-1;
 result=&name[f_pos];
 if(strlen(result)<len)
 {
  strcpy(name_holder, result);
  for(i=strlen(name_holder); i<len; i++)
   strcat(name_holder, " ");
  result=name_holder;
 }
 return(result);
}

#endif

#if SFX_LEVEL>=ARJ

/* Parses the given argument to a file attribute bitmap */

static void parse_attrs(char *str)
{
 char *sptr, *attrptr;
 char *g_attr;
 char c;
 int attrno;

 file_attr_mask=TAG_FILES;
 if(*str=='\0')
  file_attr_mask=TAG_RDONLY|TAG_SYSTEM|TAG_HIDDEN|TAG_DIREC|TAG_LABEL|
                 TAG_CHAPTER|TAG_NORMAL|TAG_WINLFN;
 else
 {
  sptr=str;
  attrptr=allowed_attrs;
  while((c=*sptr++)!='\0')
  {
   c=toupper(c);
   if((g_attr=strchr(attrptr, c))==NULL)
    error(M_INVALID_SWITCH, str);
   attrno=g_attr-attrptr-1;
   if(attrno>=0)
    file_attr_mask|=1<<attrno;
   else if(attrno==-1)
    file_attr_mask=TAG_RDONLY|TAG_SYSTEM|TAG_HIDDEN|TAG_DIREC|TAG_NORMAL;
  }
  if((file_attr_mask|(TAG_ARCH|TAG_NOT_ARCH))==(TAG_ARCH|TAG_NOT_ARCH))
   file_attr_mask|=TAG_RDONLY|TAG_SYSTEM|TAG_HIDDEN|TAG_DIREC|TAG_NORMAL;
 }
}

/* Returns real size in bytes for diskette size shortcuts (i.e., 360, 720, and
   so on...) */

static unsigned long select_preset_size(unsigned long rsize)
{
 if(rsize==360)
  return(362000L);
 else if(rsize==720)
  return(730000L);
 else if(rsize==1200)
  return(1213000L);
 else if(rsize==1440)
  return(1457000L);
 return(rsize);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Returns 1 if the switch has a "tail" of extra dataa */

static int get_switch_state(char *sw)
{
 if(sw[0]=='\0')
  return(0);
 if((sw[0]=='+'||sw[0]=='-')&&sw[1]=='\0')
  return(0);
 return(1);
}

/* Parses query list given by -jy for ARJ and -y for ARJSFX */

static void parse_yes_queries(char *sw)
{
 char *swptr;
 unsigned int c;
 int **index;
 FMSG *table;
 FMSG *entry;
 int num;

 swptr=sw;
 while((c=(unsigned int)*(swptr++))!='\0')
 {
  c=toupper(c);
  index=jysw_index;
  table=M_JYSW_TABLE;
  if((entry=msg_strchr(table, (char)c))==NULL)
   error(M_INVALID_SWITCH, sw);
  num=entry-table;
  if(*swptr=='+')
  {
   *index[num]=1;
   swptr++;
  }
  else if(*swptr=='-')
  {
   *index[num]=0;
   swptr++;
  }
  *index[num]=!*index[num];
 }
}

#endif

#if SFX_LEVEL>=ARJ&&TARGET==UNIX

/* Disables/enables archiving for a particular block device */

static void add_blkdev_spec(char *swptr)
{
 int is_excl=0;
 char *fnm;

 if(swptr[0]=='-')
 {
  is_excl=1;
  swptr++;
 }
 else if(swptr[0]=='+')
  swptr++;
 fnm=(swptr[0]=='\0')?".":swptr;
 set_dev_mode(is_excl);
 if(add_dev(fnm))
  msg_cprintf(H_ALERT, M_BAD_DEV_SPEC, fnm);
}

#endif

#if SFX_LEVEL>=ARKSFXV

/* A user-friendly strtoul(). Can tell between hex and decimal notations */

unsigned long stoul(char *p, char **rp)
{
 unsigned int radix;
 unsigned long rc;
 char c;

 if(rp==NULL)
  rp=&p;
 if(p==NULL)
 {
  *rp=p;
  return(0);
 }
 if(p[0]=='0'&&p[1]=='x')
 {
  p+=2;
  radix=16;
 }
 else
  radix=10;
 rc=strtoul(p, rp, radix);
 c=toupper(**rp);
 if(c=='K')
 {
  *rp++;
  rc*=1000L;
 }
 else if(c=='M')
 {
  *rp++;
  rc*=1000000L;
 }
 else if(c=='G')
 {
  *rp++;
  rc*=1000000000L;
 }
 else if(c=='T'||c=='P'||c=='E')        /* BUGBUG: Reserved */
 {
  *rp++;
  rc*=0xFFFFFFFF;
 }
 return(rc);
}

#endif

#if SFX_LEVEL>=ARJSFXJR

/* Sets internal variables depending on the switch given */

void analyze_arg(char *sw)
{
 char *swptr;
 unsigned int c;
 FMSG *entry;
 int num;                               /* Switch number within the table */
 #if SFX_LEVEL>=ARJSFXV
  int done;
  FMSG *table;
  FMSG *params;
  int **index;
  char lim;
  int sw_tail;
 #endif
 #if SFX_LEVEL>=ARJ
  int type;
  char vol_sw;                          /* -v... subswitch storage */
  int p_len;
  char *p_ptr;
  unsigned long cnv_num;
 #endif

 swptr=sw;
 if(swptr[0]==swptr[1]&&swptr[2]=='\0')
  skip_switch_processing=1;
 else
 {
  swptr++;
  #if SFX_LEVEL>=ARJ
   hswitch=jswitch=os2switch=0;
   if(toupper(*swptr)=='H'&&*(swptr+1)=='2')
    swptr++;
   if(*swptr=='2')
   {
    os2switch=1;
    swptr++;
   }
  #endif
  #if SFX_LEVEL>=ARJSFXV
   done=0;
  #endif
  while((c=(unsigned int)*(swptr++))!='\0')
  {
   c=toupper(c);
   #if SFX_LEVEL>=ARJ
    if(jswitch)
    {
     table=M_JSW_TABLE;
     params=M_JSW_PARAMS;
     index=jsw_index;
    }
    else if(hswitch)
    {
     table=M_HSW_TABLE;
     params=M_HSW_PARAMS;
     index=hsw_index;
    }
    else if(os2switch)
    {
     table=M_OS2SW_TABLE;
     params=M_OS2SW_PARAMS;
     index=os2sw_index;
    }
    else
    {
     table=M_SW_TABLE;
     params=M_SW_PARAMS;
     index=sw_index;
    }
   #elif SFX_LEVEL>=ARJSFXV
    table=M_SW_TABLE;
    params=M_SW_PARAMS;
    index=sw_index;
   #endif
   #if SFX_LEVEL>=ARJSFXV
    entry=msg_strchr(table, (char)c);
   #else
    entry=msg_strchr(M_SW_TABLE, (char)c);
   #endif
   if(entry==NULL)
   {
    #if SFX_LEVEL>=ARJSFXV
     error(M_INVALID_SWITCH, sw);
    #else
     msg_cprintf(0, M_ARJSFX_BANNER, exe_name);
     msg_cprintf(0, M_INVALID_SWITCH, (char)c);
     check_fmsg(CHKMSG_NOSKIP);
     exit(ARJSFX_ERL_ERROR);
    #endif
   }
   #if SFX_LEVEL>=ARJSFXV
    num=entry-table;
   #else
    num=entry-M_SW_TABLE;
   #endif
   #if SFX_LEVEL>=ARJSFXV
    lim=params[num];
    sw_tail=get_switch_state(swptr);
   #endif
   /* ARJ parameters */
   #if SFX_LEVEL>=ARJ
    if(!jswitch&&!hswitch&&!os2switch&&c=='G'&&sw_tail)
    {
     done=1;
     garble_enabled=1;
     garble_password=swptr;
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='E'&&sw_tail)
    {
     done=1;
     left_trim=(unsigned int)stoul(swptr, &swptr);
     exclude_paths=(left_trim==0)?EP_PATH:EP_BASEDIR;
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='L'&&sw_tail)
    {
     done=1;
     create_list_file=1;
     list_file=swptr;
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='O'&&sw_tail)
    {
     done=1;
     if(toupper(*swptr)=='B')
     {
      if(*++swptr=='-')
       filter_older=TCHECK_NOTHING;
      else
      {
       filter_older=TCHECK_FTIME;
       timestr_older=swptr;
      }
     }
     else if(toupper(*swptr)=='D')
     {
      swptr++;
      if(*swptr=='-')
       filter_same_or_newer=TCHECK_NOTHING;
      else if(toupper(*swptr)=='B')
      {
       filter_older=TCHECK_NDAYS;
       swptr++;
       timestr_older=swptr;
      }
      else
      {
       filter_same_or_newer=TCHECK_NDAYS;
       timestr_newer=swptr;
      }
     }
     else if(toupper(*swptr)=='C')
     {
      swptr++;
      if(toupper(*swptr)=='B')
      {
       filter_older=TCHECK_CTIME;
       swptr++;
       timestr_older=swptr;
      }
      else
      {
       filter_same_or_newer=TCHECK_CTIME;
       timestr_newer=swptr;
      }
     }
     else if(toupper(*swptr)=='A')
     {
      swptr++;
      if(toupper(*swptr)=='B')
      {
       filter_older=TCHECK_ATIME;
       swptr++;
       timestr_older=swptr;
      }
      else
      {
       filter_same_or_newer=TCHECK_ATIME;
       timestr_newer=swptr;
      }
     }
     else
     {
      filter_same_or_newer=TCHECK_FTIME;
      timestr_newer=swptr;
     }
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='T'&&sw_tail)
    {
     done=1;
     type_override=FT_BINARY;
     type=(int)(*swptr-'0');
     if(type!=ARJT_BINARY&&type!=ARJT_TEXT)
      error(M_INVALID_SWITCH, sw);
     swptr++;
     /* ASR fix 25/01/2004: the "-t1gf" combination was the only way to
        enforce "text with graphics" which was not trivial. Now "-t1g"
        should do it as well. */
     if(type==ARJT_TEXT)
      type_override=FT_TEXT;
     while((c=toupper(*swptr))=='G'||c=='F')
     {
      if(c=='G')
       type_override=FT_TEXT_GRAPHICS;
      else if(c=='F'&&type_override<FT_TEXT_FORCED)
       type_override=FT_TEXT_FORCED;
      swptr++;
     }
     if(*swptr=='.')
     {
      swptr_t=swptr;
      secondary_file_type=type;
     }
     else
      primary_file_type=type;
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='V'&&sw_tail)
    {
     done=1;
     multivolume_option=MV_STD;
     while(*swptr!='\0')
     {
      vol_sw=(char)toupper(*swptr);
      if(vol_sw=='V')
      {
       swptr++;
       beep_between_volumes=1;
      }
      else if(vol_sw=='W')
      {
       swptr++;
       whole_files_in_mv=1;
      }
      else if(vol_sw=='A')
      {
       swptr++;
       multivolume_option=MV_AVAIL;
       volume_limit=MIN_VOLUME_SIZE;
      }
      else if(vol_sw=='E')
      {
       swptr++;
       use_sfxstub=1;
      }
      else if(vol_sw=='I')
      {
       swptr++;
       inhibit_change_test=1;
      }
      else if(vol_sw=='P')
      {
       swptr++;
       pause_between_volumes=1;
       if((change_vol_delay=(int)stoul(swptr, &swptr))==0)
        change_vol_delay=STD_CHANGE_VOL_DELAY;
      }
      else if(vol_sw=='R')
      {
       swptr++;
       mv_reserve_space=stoul(swptr, &swptr);
      }
      else if(vol_sw=='S'||vol_sw=='Z'||vol_sw=='D')
      {
       swptr++;
       mv_cmd_state=MVC_RUN_CMD;
       if(vol_sw=='Z')
        mv_cmd_state=MVC_RUN_CMD_NOECHO;
       else if(vol_sw=='D')
       {
        mv_cmd_state=MVC_DELETION;
        if(*swptr=='\0')
         error(M_INVALID_SWITCH, sw);
       }
       if(*swptr!='\0')
       {
        mv_cmd=swptr;
        while(*swptr!='\0')
         swptr++;
       }
      }
      else if(isdigit(vol_sw))
      {
       volume_limit=stoul(swptr, &swptr);
       break;
      }
      else
       error(M_INVALID_SWITCH, sw);
     }
     volume_limit=select_preset_size(volume_limit);
     mv_reserve_space=select_preset_size(mv_reserve_space);
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='W'&&sw_tail)
    {
     done=1;
     assign_work_directory=1;
     work_directory=swptr;
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='X'&&sw_tail)
    {
     if(!exclude_files)
     {
      flist_cleanup(&flist_exclusion);
      flist_init(&flist_exclusion, FCLIM_EXCLUSION, FL_STANDARD);
     }
     done=1;
     exclude_files=1;
     create_excl_list(swptr);
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='Z'&&sw_tail)
    {
     done=1;
     use_comment=1;
     archive_cmt_name=swptr;
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='!'&&sw_tail)
    {
     done=1;
     listchars_allowed=1;
     listchar=toupper(*swptr);
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='$'&&sw_tail)
    {
     done=1;
     handle_labels=1;
     label_drive=toupper(*swptr);
     if(!isalpha(*swptr)||strlen(swptr)>2)
      error(M_INVALID_SWITCH, sw);
     if(swptr[1]!=':'&&swptr[1]!='\0')
      error(M_INVALID_SWITCH, sw);
    }
    else if(!jswitch&&!hswitch&&!os2switch&&c=='+'&&sw_tail)
     done=1;
    else if(hswitch&&c=='B')
    {
     done=1;
     filter_attrs=1;
     parse_attrs(swptr);
    }
    else if(hswitch&&c=='C'&&sw_tail)
    {
     done=1;
     run_cmd_at_start=1;
     start_cmd=swptr;
    }
    else if(hswitch&&c=='D')
    {
     if(*swptr=='\0')
      error(M_INVALID_SWITCH, sw);
     done=1;
     debug_enabled=1;
     debug_opt=swptr;
    }
    else if(hswitch&&c=='G')
    {
     done=1;
     gost_cipher=GOST256;
     if(*swptr=='!'&&swptr[1]=='\0')
      gost_cipher=GOST40;
     else
      arjcrypt_name=swptr;
    }
    else if(hswitch&&c=='M')
    {
     done=1;
     filelist_storage=BST_DISK;
     max_filenames=(FILE_COUNT)stoul(swptr, &swptr);
     if(max_filenames==0)
      max_filenames=EXT_FILELIST_CAPACITY;
     if(*swptr=='!'&&swptr[1]!='\0')
      swptr_hm=++swptr;
    #if TARGET==DOS
     else if(*swptr=='!'&&swptr[1]=='\0')
      filelist_storage=BST_XMS;
    #endif
    }
    else if(hswitch&&c=='N')
    {
     done=1;
     nonexist_filespec=1;
     nonexist_name=swptr;
    }
    else if(hswitch&&c=='P')
    {
     done=1;
     arjdisp_enabled=1;
     arjdisp_ptr=swptr;
    }
    else if(hswitch&&c=='T')
    {
     done=1;
     set_target_directory=1;
     p_len=strlen(swptr);
     p_ptr=&swptr[p_len-1];
     while(*p_ptr==' ')
      p_ptr--;
     if(strchr(path_separators, *p_ptr)!=NULL)
      target_dir=swptr;
     else
     {
      strcpy(target_dir=malloc_msg(p_len+2), swptr);
      target_dir[p_len]=PATHSEP_DEFAULT;
      target_dir[p_len+1]='\0';
     }
    }
    else if(hswitch&&c=='V')
    {
     done=1;
     chk_arj_version=1;
     swptr_hv=swptr;
    }
    else if(hswitch&&c=='X')
    {
     done=1;
     override_archive_exts=1;
     archive_ext_list=swptr;
     if(swptr[0]!='.'||swptr[1]=='\0')
      error(M_INVALID_SWITCH, sw);
    }
    else if(hswitch&&c=='Z')
    {
     done=1;
     sign_with_arjsec=1;
     arjsec_env_name=swptr;
    }
    else if(hswitch&&c=='#'&&*swptr!='\0'&&!isdigit(*swptr))
    {
     done=1;
     append_curtime=1;
     time_str=swptr;
    }
    else if(jswitch&&c=='C'&&sw_tail)
    {
     done=1;
     exit_after_count=1;
     exit_count=(FILE_COUNT)stoul(swptr, &swptr);
    }
    else if(jswitch&&c=='D'&&sw_tail)
    {
     done=1;
     chk_free_space=1;
     minfree=stoul(swptr, &swptr);
    }
    else if(jswitch&&c=='B'&&sw_tail)
    {
     done=1;
     chapter_mode=CHAP_USE;
     if(*swptr=='*')
     {
      swptr++;
      current_chapter=1;
      chapter_to_process=RESERVED_CHAPTER;
     }
     else
     {
      cnv_num=stoul(swptr, &swptr);
      chapter_to_process=current_chapter=(int)cnv_num;
      if(*swptr++=='-')
      {
       if(*swptr=='\0')
        chapter_to_process=RESERVED_CHAPTER;
       else
       {
        cnv_num=stoul(swptr, &swptr);
        chapter_to_process=(int)cnv_num;
        if(chapter_to_process>CHAPTERS_MAX)
         error(M_INVALID_SWITCH, sw);
       }
      }
      if(current_chapter==0&&chapter_to_process==0)
       chapter_mode=CHAP_REMOVE;
     }
    }
    else if(jswitch&&c=='H'&&sw_tail)
    {
     done=1;
     jh_enabled=1;
     cnv_num=stoul(swptr, &swptr);
     if(cnv_num<(unsigned long)MIN_BUFSIZ||cnv_num>(unsigned long)MAX_USER_BUFSIZ)
      error(M_INVALID_SWITCH, sw);
     #if MAX_BUFSIZ<MAX_USER_BUFSIZ
      if(cnv_num>(unsigned long)MAX_BUFSIZ)
       cnv_num=MAX_BUFSIZ;
     #endif
     user_bufsiz=(unsigned int)cnv_num;
    }
    else if(jswitch&&c=='I'&&sw_tail)
    {
     done=1;
     create_index=1;
     index_name=swptr;
    }
    else if(jswitch&&c=='N'&&sw_tail)
    {
     done=1;
     restart_at_filename=1;
     filename_to_restart=swptr;
    }
    else if(jswitch&&c=='Q'&&sw_tail)
    {
     done=1;
     set_string_parameter=1;
     string_parameter=swptr;
    }
    else if(jswitch&&c=='P'&&sw_tail)
    {
     done=1;
     prompt_for_more=1;
     cnv_num=stoul(swptr, &swptr);
     if(cnv_num>0L)
      lines_per_page=(int)cnv_num;
    }
    else if(jswitch&&c=='S'&&sw_tail)
    {
     done=1;
     store_by_suffix=1;
     free(archive_suffixes);
     archive_suffixes=swptr;
    }
    else if(jswitch&&c=='W'&&sw_tail)
    {
     done=1;
     extract_to_file=1;
     extraction_filename=swptr;
    }
    else if(jswitch&&c=='X'&&sw_tail)
    {
     done=1;
     start_at_ext_pos=1;
     ext_pos=stoul(swptr, &swptr);
    }
    else if(jswitch&&c=='Y'&&sw_tail)
    {
     done=1;
     assume_yes=1;
     yes_query_list=swptr;
     parse_yes_queries(yes_query_list);
    }
    else if(jswitch&&c=='Z'&&sw_tail)
    {
     done=1;
     supply_comment_file=1;
     comment_file=swptr;
    }
#if TARGET==UNIX    
    else if(os2switch&&c=='B')
    {
     done=1;
     add_blkdev_spec(swptr);
    }
#endif    
    else if(os2switch&&c=='E')
    {
     done=1;
     if(!sw_tail)
      ea_supported=0;
     else
     {
      include_eas=1;
      #if defined(HAVE_EAS)
       flist_add_files(&flist_ea, NULL, swptr, 0, 0, 0, NULL);
      #endif
     }
    }
    else if(os2switch&&c=='I'&&sw_tail)
    {
     done=1;
     start_with_seek=1;
     arcv_ext_pos=stoul(swptr, &swptr);
    }
    else if(os2switch&&c=='P')
    {
     if(!sw_tail)
      error(M_INVALID_SWITCH, sw);
     priority.class=stoul(swptr, &swptr);
     if(priority.class<1||priority.class>PRIORITY_CLASSES)
      error(M_INVALID_SWITCH, sw);
     #if TARGET==OS2||TARGET==WIN32
      if((p_ptr=strchr(swptr, ':'))==NULL)
       priority.delta=0;
      else
      {
       swptr=p_ptr+1;
       priority.delta=stoul(swptr, &swptr);
       #if TARGET==OS2
        if(priority.delta<-31||priority.delta>31)
       #elif TARGET==WIN32
        if(priority.delta<-2||priority.delta>2)
       #else
        #error No priority delta limits!
       #endif
        error(M_INVALID_SWITCH, sw);
      }
     #else
      priority.delta=0;
     #endif
    }
#ifdef COLOR_OUTPUT    
    else if(os2switch&&c=='T')
    {
     done=!parse_colors(swptr);
     if(!done)
      error(M_INVALID_SWITCH, sw);
    }
#endif
    else if(os2switch&&c=='X')
    {
     done=1;
     if(!sw_tail)
      error(M_MISSING_FILENAME_ARG, "-2x");
     else
     {
      exclude_eas=1;
      #if defined(HAVE_EAS)
       flist_add_files(&flist_xea, NULL, swptr, 0, 0, 0, NULL);
      #endif
     }
    }
    else if(*swptr=='+')
    {
     *index[num]=1;
     swptr++;
    }
    else if(*swptr=='-')
    {
     *index[num]=0;
     swptr++;
    }
    else if(*swptr>='0'&&*swptr<='9')
    {
     if(!debug_enabled||strchr(debug_opt, 's')==NULL)
     {
      if(*swptr>lim)
       error(M_INVALID_SWITCH, sw);
     }
     *index[num]=(int)(*(swptr++)+1-'0');
    }
    else
     *index[num]=!*index[num];
   /* ARJSFXV parameters */
   #elif SFX_LEVEL==ARJSFXV
    if(c=='G'&&sw_tail)
    {
     done=1;
     garble_enabled=1;
     garble_password=swptr;
    }
    else if(c=='+'&&sw_tail)
     done=1;
    else if(c=='&')
    {
     if(*swptr=='\0')
      error(M_INVALID_SWITCH, sw);
     done=1;
     debug_enabled=1;
     debug_opt=swptr;
    }
    else if(c=='@')
    {
     done=1;
     arjdisp_enabled=1;
     arjdisp_ptr=swptr;
    }
    else if(c=='!')
    {
     done=1;
     execute_extr_cmd=1;
     extr_cmd_text=swptr;
    }
    else if(c=='$'&&sw_tail)
    {
     done=1;
     handle_labels=1;
     label_drive=toupper(*swptr);
     if(!isalpha(*swptr)||strlen(swptr)>2)
      error(M_INVALID_SWITCH, sw);
     if(swptr[1]!=':'&&swptr[1]!='\0')
      error(M_INVALID_SWITCH, sw);
    }
    else if(c=='W'&&sw_tail)
    {
     done=1;
     extract_to_file=1;
     extraction_filename=swptr;
    }
    else if(c=='D'&&sw_tail)
    {
     done=1;
     chk_free_space=1;
     minfree=stoul(swptr, &swptr);
    }
    else if(c=='#'&&sw_tail)
    {
     done=1;
     skip_volumes=1;
     first_volume_number=stoul(swptr, &swptr);
    }
    else if(c=='O'&&sw_tail)
    {
     done=1;
     gost_cipher=GOST256;
     arjcrypt_name=swptr;
    }
    else if(c=='Z'&&sw_tail)
    {
     done=1;
     assume_yes=1;
     yes_query_list=swptr;
     parse_yes_queries(yes_query_list);
    }
    else if(*swptr=='+')
    {
     *index[num]=1;
     swptr++;
    }
    else if(*swptr=='-')
    {
     *index[num]=0;
     swptr++;
    }
    else if(*swptr>='0'&&*swptr<='3')
    {
     if(!debug_enabled||strchr(debug_opt, 's')==NULL)
     {
      if(*swptr>lim)
       error(M_INVALID_SWITCH, sw);
     }
     *index[num]=(int)(*(swptr++)+1-'0');
    }
    else
     *index[num]=!*index[num];
   /* ARJSFX parameters */
   #elif SFX_LEVEL==ARJSFX
    *sw_index[num]=1;
    if(c=='G'&&*swptr!='\0')
    {
     garble_password=swptr;
     while(*swptr!='\0')
      swptr++;
    }
    if(c=='!')
    {
     extr_cmd_text=swptr;
     while(*swptr!='\0')
      swptr++;
    }
   #endif
   #if SFX_LEVEL>=ARJSFXV
    if(done)
    {
     while(*swptr!='\0')
      swptr++;
    }
   #endif
  }
  /* This will become obsolete as COLOR_OUTPUT has changed the semantics of
     quiet_mode - ASR fix 23/01/2003 */
#ifndef COLOR_OUTPUT
  if(quiet_mode&&!arjdisp_enabled)
   quiet_mode=0;
#endif
 }
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Initializes system variables with default settings prior to setup
   procedures */

void init()
{
 unsigned int i;

 #if SFX_LEVEL>=ARJ
  multivolume_option=0;
 #else
  multivolume_option=1;
 #endif
 #if SFX_LEVEL>=ARJ
  for(i=0; i<SEARCH_STR_MAX; i++)
   search_str[i]=NULL;
  search_reserve=NULL;
  reserve_size=0;
 #endif
 for(i=0; i<params_max; i++)
  order[i]=0;
 #if SFX_LEVEL>=ARJ
  for(i=0; i<TOTAL_QUERIES; i++)
   queries_assume_yes[i]=queries_assume_no[i]=0;
 #endif
 #if SFX_LEVEL>=ARJ
  primary_file_type=ARJT_BINARY;
 #endif
 listchar=LISTCHAR_DEFAULT;
 #if SFX_LEVEL>=ARJ
  lines_per_page=query_screen_height();
 #endif
 listchars_allowed=1;
 ctrlc_not_busy=1;
 #if SFX_LEVEL>=ARJ
  file_args=-1;
 #else
  file_args=0;
 #endif
 #if SFX_LEVEL<=ARJSFXV
  extract_expath=0;
  extract_cmd=0;
  list_sfx_cmd=0;
  verbose_list=0;
  test_sfx_cmd=0;
  error_occured=0;
  licensed_sfx=0;
  logo_shown=0;
 #endif
 #if SFX_LEVEL>=ARJ
  max_filenames=EXT_FILELIST_CAPACITY;
  ctrlc_processing=0;
  display_totals=0;
  lines_scrolled=0;
 #endif
 errors=0;
 #if SFX_LEVEL>=ARJ
  ts_store(&tested_ftime_newer, OS_SPECIAL, 0);
  ts_store(&tested_ftime_older, OS_SPECIAL, 0);
  last_hdr_offset=0L;
  tmp_archive_used=0;
  arch_wildcard_allowed=0;
  file_attr_mask=TAG_FILES;
  recursion_order=RO_LAST;
  encryption_id=0;
  use_ansi_cp=0;
  filter_fa_arch=0;
  serialize_exts=0;
 #else
  file_garbled=0;
 #endif
 allow_any_attrs=0;
 #if SFX_LEVEL>=ARJ
  set_target_directory=0;
  chapter_mode=0;
 #endif
 install_errhdl=0;
 #if SFX_LEVEL<=ARJSFXV
  prompt_for_directory=0;
 #endif
 debug_enabled=0;
 #if SFX_LEVEL>=ARJ
  delete_processed=0;
  run_cmd_at_start=0;
  arjsec_opt=0;
  exclude_paths=0;
  execute_cmd=0;
  start_at_ext_pos=0;
  start_with_seek=0;
  arcv_ext_pos=0;
  subdir_extraction=0;
  extm_mode=0;
  override_archive_exts=0;
  disable_comment_series=0;
  skip_century=CENT_DEFAULT;
  show_filenames_only=0;
  force_lfn=0;
  chk_free_space=0;
  freshen_criteria=FC_NONE;
  validate_style=0;
  jh_enabled=0;
  clear_archive_bit=0;
  ignore_archive_errors=0;
  ignore_open_errors=0;
  detailed_index=0;
  create_index=0;
  keep_bak=0;
  keep_tmp_archive=0;
  sign_with_arjsec=0;
  handle_labels=0;
  listfile_err_opt=0;
  create_list_file=0;
  std_list_cmd=0;
  filelist_storage=0;
  max_compression=0;
  custom_method=0;
  skip_time_attrs=0;
  indicator_style=0;
  yes_on_all_queries=0;
  disable_sharing=0;
  skip_switch_processing=0;
  no_file_activity=0;
  new_files_only=0;
  filter_same_or_newer=0;
  rsp_per_line=0;
  gost_cipher=0;
  marksym_expansion=0;
  fnm_matching=0;
  arcmail_sw=0;
  dos_host=0;
  priority.class=priority.delta=0;
 #endif
 arjdisp_enabled=0;
 #if SFX_LEVEL<=ARJSFXV
  subdir_extraction=0;
  execute_cmd=0;
  show_filenames_only=0;
  chk_free_space=0;
  freshen_criteria=FC_NONE;
  validate_style=VALIDATE_ALL;
  garble_enabled=0;
  overwrite_ro=0;
  handle_labels=0;
  listfile_err_opt=0;
  std_list_cmd=0;
  indicator_style=0;
  yes_on_all_queries=0;
  disable_sharing=1;
  skip_switch_processing=0;
  new_files_only=0;
  fnm_matching=0;
  execute_extr_cmd=0;
 #endif
 #if SFX_LEVEL>=ARJ
  protfile_option=0;
  query_for_each_file=0;
  set_string_parameter=0;
  lowercase_names=0;
 #endif
 ignore_crc_errors=0;
 recurse_subdirs=0;
 quiet_mode=0;
 #if SFX_LEVEL<=ARJSFXV
  skip_volumes=0;
 #endif
 keep_tmp_file=0;
 print_with_more=0;
 #if SFX_LEVEL<=ARJSFXV
  valid_envelope=0;
  process_lfn_archive=0;
  skip_preset_options=0;
 #endif
 #if SFX_LEVEL>=ARJ
  search_mode=0;
  select_backup_files=0;
  filter_attrs=0;
  create_sfx=0;
  lfn_mode=0;
  comment_display=0;
 #endif
 skip_ts_check=0;
 #if SFX_LEVEL>=ARJ
  store_by_suffix=0;
  test_archive_crc=0;
  timestamp_override=0;
  type_override=0;
  translate_unix_paths=0;
 #endif
 update_criteria=UC_NONE;
 #if SFX_LEVEL>=ARJ
  verbose_display=0;
  chk_arj_version=0;
  beep_between_volumes=0;
  allow_mv_update=0;
  mv_cmd_state=0;
  whole_files_in_mv=0;
 #endif
 #if SFX_LEVEL>=ARJSFXV                 /* To keep v 2.71 order */
  use_sfxstub=0;
 #endif
 #if SFX_LEVEL>=ARJ
  assign_work_directory=0;
 #endif
 extract_to_file=0;
 assume_yes=0;
 kbd_cleanup_on_input=0;
 skip_append_query=0;
 prompt_for_mkdir=0;
 #if SFX_LEVEL>=ARJ
  query_delete=0;
 #endif
 skip_space_query=0;
 skip_rename_prompt=0;
 overwrite_existing=0;
 #if SFX_LEVEL>=ARJ
  skip_scanned_query=0;
 #endif
 skip_next_vol_query=0;
 #if SFX_LEVEL>=ARJ
  accept_shortcut_keys=0;
 #else
  reg_id=0;
  first_volume_number=0;
 #endif
 #if SFX_LEVEL>=ARJ
  use_comment=0;
  supply_comment_file=0;
  current_chapter=0;
  chapter_to_process=0;
  resume_volume_num=0;
  exit_count=0;
  left_trim=0;
  ext_pos=0;
 #endif
 label_drive=0;
 minfree=0L;
 #if SFX_LEVEL>=ARJ
  volume_limit=0L;
  mv_reserve_space=0L;
  t_volume_offset=0L;
 #endif
 av_uncompressed=0L;
 av_compressed=0L;
 av_total_files=0;
 av_total_longnames=0;
 #if SFX_LEVEL>=ARJ
  total_size=0L;
  user_bufsiz=current_bufsiz=BUFSIZ_DEFAULT;
  ntext=NULL;                           /* ASR fix for 2.76.06 */
  #if TARGET==UNIX
   sl_entries.list=l_entries.list=NULL;
   sl_entries.total=sl_entries.alloc=l_entries.total=l_entries.alloc=0;
  #endif
 #endif
 nonexist_name=nonexistent_name;
 archive_suffixes=malloc_fmsg(M_ARCHIVE_SUFFIXES);
 #if SFX_LEVEL>=ARJ
  swptr_t=nullstr;
  work_directory=nullstr;
 #endif
 target_dir=nullstr;
 #if SFX_LEVEL>=ARJ
  swptr_hm=nullstr;
  start_cmd=nullstr;
  cmd_to_exec=nullstr;
  archive_ext_list=nullstr;
  index_name=nullstr;
 #endif
 debug_opt=nullstr;
 #if SFX_LEVEL>=ARJ
  timestr_newer=nullstr;
  timestr_older=nullstr;
 #else
  extr_cmd_text=nullstr;
  garble_password=nullstr;
 #endif
 arjdisp_ptr=nullstr;
 #if SFX_LEVEL>=ARJ
  filename_to_restart=nullstr;
  mv_cmd=nullstr;
  arjsec_env_name=nullstr;
  list_file=nullstr;
  arjcrypt_name=nullstr;
  string_parameter=nullstr;
  swptr_hv=nullstr;
  time_str=nullstr;
 #endif
 extraction_filename=nullstr;
 yes_query_list=nullstr;
 #if SFX_LEVEL>=ARJ
  archive_cmt_name=nullstr;
  comment_file=nullstr;
 #endif
 tmp_tmp_filename[0]='\0';
 archive_name[0]='\0';
 #if SFX_LEVEL<=ARJSFXV
  aistream=NULL;
  atstream=NULL;
 #endif
 file_packing=1;
 #if SFX_LEVEL>=ARJSFXV
  eh=NULL;
  valid_ext_hdr=0;
 #endif
 #if SFX_LEVEL>=ARJ
  include_eas=0;
  exclude_eas=0;
  crit_eas=0;
  fix_longnames=0;
  symlink_accuracy=0;
  do_chown=0;
  suppress_hardlinks=0;
 #endif
}

/* Returns 1 if the given argument is a command-line switch */

int is_switch(char *arg)
{
 int rc;

 if(!skip_switch_processing&&switch_char!=0&&(int)arg[0]==switch_char)
  rc=1;
 else if(!skip_switch_processing&&switch_char==0)
  rc=(strchr(switch_chars, arg[0])==NULL)?0:1;
 else
  rc=0;
 if(rc&&switch_char==0)
  switch_char=(int)arg[0];
 return(rc);
}

#endif

#if SFX_LEVEL>=ARJ

/* Performs general command-line analysis and returns the command being
   requested. */

int preprocess_cmdline(int argc, char *argv[])
{
 int i;
 int cmd;
 char *arg;

 cmd=0;
 new_stdout=stdout;
 disable_arj_sw=0;
 skip_switch_processing=0;
 rsp_name=nullstr;                      /* ASR fix -- 15/10/2000 (ARJ/2-32) */
 switch_char=0;
 install_errhdl=0;
 quiet_mode=0;
 use_ansi_cp=0;
 file_garbled=0;
 garble_enabled=0;
 garble_password=nullstr;
 arj_env_name=malloc_fmsg(M_ARJ_SW);
 for(i=1; i<argc; i++)
 {
  arg=argv[i];
  if(is_switch(arg))
  {
   if(arg[1]=='+')
   {
    if(arg[2]=='\0')
     disable_arj_sw=1;
    else
    {
     free_fmsg(arj_env_name);
     arj_env_name=malloc_str(arg+2);
    }
   }
   else if(arg[1]=='&'&&arg[2]=='\0')
    install_errhdl=1;
   else if(arg[1]=='*'&&arg[2]=='\0')
    quiet_mode=ARJ_QUIET;
   else if(arg[1]=='*'&&arg[2]=='1'&&arg[3]=='\0')
    quiet_mode=ARJ_SILENT;
   else if(arg[1]=='*'&&arg[2]=='2'&&arg[3]=='\0') /* v 2.72 - New function */
    quiet_mode=ARJ_QUIET2;
   else if(toupper(arg[1])=='G')
   {
    garble_enabled=1;
    garble_password=arg+2;
   }
   else if(toupper(arg[1])=='H'&&toupper(arg[2])=='Y')
   {
    use_ansi_cp=ANSICP_CONVERT;
    if(arg[3]=='1')
     use_ansi_cp=ANSICP_SKIP;
    else if(arg[3]=='2')
     use_ansi_cp=ANSICP_USE_OEM;
    else if(arg[3]=='3')
     use_ansi_cp=ANSICP_USE_ANSI;
   }
   else if(arg[0]==arg[1]&&arg[2]=='\0')
    skip_switch_processing=1;
  }
  else
  {
   if(i==1&&arg[0]=='@'&&arg[1]!='\0')
    rsp_name=arg+1;
   else if(cmd==0&&rsp_name[0]=='\0')
   {
    if(!stricmp(arg, cmd_ac))
     cmd=ARJ_CMD_ADDC;
    else if(!stricmp(arg, cmd_cc))
     cmd=ARJ_CMD_CNVC;
    else if(!stricmp(arg, cmd_dc))
     cmd=ARJ_CMD_DELC;
    else
     cmd=toupper(arg[0]);
   }
  }
 }
 if(cmd==ARJ_CMD_PRINT||cmd==ARJ_CMD_SAMPLE)
  new_stdout=stderr;
 if(install_errhdl)
  ignore_errors=1;
 return(cmd);
}

#endif

#if SFX_LEVEL>=ARJSFX||defined(REARJ)

/* Splits the given name to pathname and filename. On return, pathname
   contains ASCIIZ path specification including path terminator, filename
   contains ASCIIZ filename (with no preceding path terminators), and the
   return value is the offset of filename within the given name. */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
int split_name(char *name, char *pathname, char *filename)
#else
int split_name(char *name)
#endif
{
 char *f_sep, *last_sep;
 int i, sep_offset;

 last_sep=NULL;
 for(i=0; path_separators[i]!='\0'; i++)
 {
  if((f_sep=strrchr(name, path_separators[i]))!=NULL)
  {
   if(last_sep==NULL||f_sep>last_sep)
    last_sep=f_sep;
  }
 }
 sep_offset=(last_sep==NULL)?0:last_sep-name+1;
 #if SFX_LEVEL>=ARJSFXV||defined(REARJ)
  if(pathname!=NULL)
   strcpyn(pathname, name, sep_offset+1);
  if(filename!=NULL)
   strcpy(filename, name+sep_offset);
 #endif
 return(sep_offset);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Returns the error code for error message given */

int subclass_errors(FMSG *errmsg)
{
 if(errmsg==M_OUT_OF_MEMORY||errmsg==M_OUT_OF_NEAR_MEMORY)
  return(ARJ_ERL_NO_MEMORY);
 if(errmsg==M_HEADER_CRC_ERROR||errmsg==M_CRC_ERROR)
  return(ARJ_ERL_CRC_ERROR);
 #if SFX_LEVEL>=ARJ
  if(errmsg==M_DAMAGED_SEC_ARCHIVE||errmsg==M_CANT_UPDATE_SEC||errmsg==M_SKIPPING_SEC)
   return(ARJ_ERL_ARJSEC_ERROR);
 #endif
 if(errmsg==M_DISK_FULL)
  return(ARJ_ERL_DISK_FULL);
 if(errmsg==M_CANTOPEN)
  return(ARJ_ERL_CANTOPEN);
 if(errmsg==M_NOT_ARJ_ARCHIVE)
  return(ARJ_ERL_NOT_ARJ_ARCHIVE);
 #if SFX_LEVEL>=ARJ
  #if TARGET==DOS
   if(errmsg==M_LISTING_XMS_ERROR)
    return(ARJ_ERL_XMS_ERROR);
  #endif
  if(errmsg==M_TOO_MANY_CHAPTERS)
   return(ARJ_ERL_TOO_MANY_CHAPTERS);
 #endif
 if(errmsg==M_INVALID_SWITCH||errmsg==M_ARGTABLE_OVERFLOW||errmsg==M_NO_FILE_GIVEN||
 #if SFX_LEVEL>=ARJ
    errmsg==M_NO_DELETE_ARG||errmsg==M_INVALID_VOL_SIZE||
    errmsg==M_NO_STR_ENTERED||errmsg==M_JT_UNUSABLE||
 #endif
    errmsg==M_NO_PWD_OPTION||
    errmsg==M_MISSING_FILENAME_ARG||errmsg==M_INVALID_DATE_STRING||errmsg==M_BAD_SYNTAX)
  return(ARJ_ERL_USER_ERROR);
 return(ARJ_ERL_FATAL_ERROR);
}

#endif

#if SFX_LEVEL>=ARJ

/* Retrieves search data from string parameter given by -jq */

static int get_str_from_jq()
{
 char *sptr, *tsptr;
 char *endptr;
 int patterns;
 char pt;

 sptr=string_parameter;
 if(sptr[0]!='+'&&sptr[0]!='-')
  error(M_INVALID_PARAM_STR, sptr);
 ignore_pcase=sptr[0]=='+';
 fdisp_lines=(int)stoul(sptr, &sptr);
 patterns=0;
 if(*sptr!='\0')
 {
  pt=*sptr;
  sptr++;
  /* Tokenize string_parameter */
  for(tsptr=sptr; *tsptr!='\0'; tsptr++)
   if(*tsptr==pt)
    *tsptr='\0';
  endptr=tsptr;
  tsptr=sptr;
  while((unsigned int)tsptr<(unsigned int)endptr&&patterns<SEARCH_STR_MAX)
  {
   while(*tsptr=='\0')
    tsptr++;
   if((unsigned int)tsptr<(unsigned int)endptr)
   {
    search_str[patterns++]=tsptr;
    while(*tsptr!='\0'&&(unsigned int)tsptr<(unsigned int)endptr)
     tsptr++;
   }
  }
 }
 return(patterns);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Performs an optimized seek operation */

void file_seek(FILE *stream, long offset, int whence)
{
 char *buffer;

 if(whence==SEEK_CUR&&offset>=0L&&offset<=(long)CACHE_SIZE)
 {
  buffer=malloc_msg(CACHE_SIZE);
  if(offset>0L)
   fread(buffer, 1, (int)offset, stream);
  free(buffer);
 }
 else
  fseek(stream, offset, whence);
}

#endif

#if SFX_LEVEL>=ARJ

/* Performs a search operation set-up */

void search_setup()
{
 char entry[INPUT_LENGTH];
 int patterns;

 if(set_string_parameter&&string_parameter[0]!='\0')
  patterns=get_str_from_jq();
 else
 {
  ignore_pcase=query_action(REPLY_NO, QUERY_CRITICAL, M_QUERY_CASE_IGNORE);
  msg_cprintf(0, M_ENTER_NUM_MATCHES);
  read_line(entry, sizeof(entry));
  fdisp_lines=stoul(entry, NULL);
  msg_cprintf(0, M_ENTER_SEARCH_STR, SEARCH_STR_MAX);
  for(patterns=0; patterns<SEARCH_STR_MAX; patterns++)
  {
   msg_cprintf(0, (FMSG *)le_prompt, patterns+1);
   if(read_line(entry, sizeof(entry))<=0)
    break;
   search_str[patterns]=malloc_str(entry);
  }
 }
 if(patterns==0)
  error(M_NO_STR_ENTERED);
 while(patterns-->0)
 {
  if(ignore_pcase)
   strupper(search_str[patterns]);
 }
 if(fdisp_lines!=0)
  indicator_style=IND_NONE;
 reserve_size=0;
 search_reserve=malloc_msg(sizeof(entry)*2);
}

#endif

#if (SFX_LEVEL>=ARJSFX)||defined(ARJDISP)

/* Based on the unsigned long values given, calculates their proportion (per
   mille, so 42.3% is returned as 423). */

int calc_percentage(unsigned long partial, unsigned long total)
{
 int dec;

 for(dec=0; dec<3; dec++)
 {
  if(partial<=0x19999999)
   partial*=10L;
  else
   total/=10L;
 }
 if(partial+total/2<=partial)
 {
  partial/=2;
  total/=2;
 }
 if(total==0)
  return(0);
 else
  return((partial+total/2)/total);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Performs a "smart" seeking, depending on file type (special handling is
   performed for text files) */

void smart_seek(unsigned long position, FILE *stream)
{
 char *tmp_buf;
 int fetch_size;

 fseek(stream, 0L, SEEK_SET);
 if(position>0L)
 {
  if(file_type==ARJT_BINARY)
   fseek(stream, position, SEEK_SET);
  else
  {
   tmp_buf=(char *)malloc_msg(PROC_BLOCK_SIZE);
   while(position>0L)
   {
    fetch_size=(int)min(position, (unsigned long)PROC_BLOCK_SIZE);
    if(fread(tmp_buf, 1, fetch_size, stream)!=fetch_size)
     error(M_SEEK_FAILED);
    position-=(unsigned long)fetch_size;
   }
   fseek(stream, 0L, SEEK_CUR);
   free(tmp_buf);
  }
 }
}

#endif

#if SFX_LEVEL>=ARJSFX||defined(REARJ)||defined(REGISTER)

/* This procedure trims the extra spaces and tabs at the left and right of line
   given */

void alltrim(char *cmd)
{
 int fchars;
 char *lpos;

 lpos=cmd;
 for(fchars=strlen(cmd)-1; fchars>=0; fchars--)
 {
  if(cmd[fchars]!='\x09'&&cmd[fchars]!=' ')
   break;
 }
 if(fchars>=0)
 {
  while(lpos[0]=='\x09'||lpos[0]==' ')
  {
   lpos++;
   fchars--;
  }
  while(fchars>=0)
  {
   (cmd++)[0]=(lpos++)[0];
   fchars--;
  }
 }
 cmd[0]='\0';
}

#endif

#if SFX_LEVEL>=ARJSFX

/* Extracts a stored file */

void unstore(int action)
{
 char *fetch;
 #if SFX_LEVEL>=ARJSFXV
  unsigned int fetch_size;
  unsigned long cur_pos;
 #endif
 unsigned long bytes_written;
 int count;

 #if SFX_LEVEL>=ARJSFXV
  fetch=NULL;
  for(fetch_size=PROC_BLOCK_SIZE; fetch_size>=512; fetch_size-=512)
  {
   if((fetch=(char *)malloc(fetch_size))!=NULL)
    break;
  }
  if(fetch==NULL)
   error(M_OUT_OF_MEMORY);
  mem_stats();
 #else
  fetch=dec_text;
 #endif
 display_indicator(bytes_written=0L);
 #if SFX_LEVEL>=ARJSFXV
  if(file_packing)
  {
   cur_pos=ftell(aistream);
   count=min(fetch_size-(cur_pos%fetch_size), compsize);
  }
  else
   count=min(fetch_size, compsize);
 #else
  count=min(DICSIZ, compsize);
 #endif
 while(compsize>0L)
 {
  if(file_packing)
  {
   if(fread(fetch, 1, count, aistream)!=count)
    error(M_CANTREAD);
  }
  else
  {
   far_memmove((char FAR *)fetch, packblock_ptr, count);
   packblock_ptr+=count;
   packmem_remain-=count;
  }
  if(file_garbled)
   #if SFX_LEVEL>=ARJ
    garble_decode_stub(fetch, count);
   #else
    garble_decode(fetch, count);
   #endif
  bytes_written+=(unsigned long)count;
  display_indicator(bytes_written);
  compsize-=(unsigned long)count;
  if(extraction_stub(fetch, count, action))
   break;
  #if SFX_LEVEL>=ARJSFXV
   count=min(fetch_size, compsize);
  #else
   count=min(DICSIZ, compsize);
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  free(fetch);
 #endif
}

#endif

#if SFX_LEVEL>=ARJ

/* Performs a "hollow" file decoding (compares the CRC if requested to do so,
   otherwise quits). */

void hollow_decode(int action)
{
 char *fetch;
 unsigned long bytes_written;
 unsigned long cur_pos;
 int count;

 if(action==BOP_COMPARE)
 {
  fetch=(char *)malloc_msg(PROC_BLOCK_SIZE);
  mem_stats();
  display_indicator(bytes_written=0L);
  cur_pos=origsize;
  count=min(cur_pos, (unsigned long)PROC_BLOCK_SIZE);
  while(cur_pos>0L)
  {
   if(fread(fetch, 1, count, tstream)!=count)
   {
    identical_filedata=0;
    break;
   }
   crc32_for_block(fetch, count);
   bytes_written+=(unsigned long)count;
   display_indicator(bytes_written);
   cur_pos-=(unsigned long)count;
   count=min(PROC_BLOCK_SIZE, cur_pos);
  }
  free(fetch);
 }
}

#endif

#if SFX_LEVEL>=ARJ

/* Packs a memory block. The destination area must be large enough to hold
   an unpacked copy. */

void pack_mem(struct mempack *mempack)
{
 unsigned long s_compsize, s_origsize;
 int s_method, s_packing;
 int s_type;
 unsigned long c_t;

 s_compsize=compsize;
 s_origsize=origsize;
 s_method=method;
 s_packing=file_packing;
 s_type=file_type;
 origsize=mempack->origsize;
 compsize=0L;
 method=mempack->method;
 encblock_ptr=mempack->orig;
 packblock_ptr=mempack->comp+MEMPACK_OVERHEAD;
 encmem_remain=mempack->origsize;
 packmem_remain=0;
 unpackable=0;
 file_packing=0;
 file_type=ARJT_BINARY;
 if(garble_enabled)
  garble_init(password_modifier);
 crc32term=CRC_MASK;
 if(method==1||method==2||method==3)
  encode_stub(method);
 else if(method==4)
  encode_f_stub();
 if(unpackable)                         /* Fall back to method #0 */
 {
  encblock_ptr=mempack->orig;
  packblock_ptr=mempack->comp+MEMPACK_OVERHEAD;
  encmem_remain=mempack->origsize;
  method=0;
  if(garble_enabled)
   garble_init(password_modifier);
  crc32term=CRC_MASK;
 }
 if(method==0)
  store();
 c_t=crc32term^CRC_MASK;
 mempack->comp[0]=c_t&0x000000FF;
 mempack->comp[1]=(c_t&0x0000FF00)>>8;
 mempack->comp[2]=(c_t&0x00FF0000)>>16;
 mempack->comp[3]=(c_t&0xFF000000)>>24;
 mempack->compsize=compsize+MEMPACK_OVERHEAD;
 mempack->method=method;
 file_type=s_type;
 file_packing=s_packing;
 compsize=s_compsize;
 origsize=s_origsize;
 method=s_method;
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Unpacks a memory block. The destination area must be large enough to hold
   an unpacked copy. */

void unpack_mem(struct mempack *mempack)
{
 unsigned long s_compsize, s_origsize;
 int s_method, s_packing, s_type;
 unsigned long c_t;

 s_type=file_type;
 s_compsize=compsize;
 s_origsize=origsize;
 s_method=method;
 s_packing=file_packing;
 file_type=ARJT_BINARY;
 origsize=mempack->origsize;
 encmem_limit=mempack->origsize;
 compsize=mempack->compsize-MEMPACK_OVERHEAD;
 method=mempack->method;
 encblock_ptr=mempack->orig;
 packblock_ptr=mempack->comp+MEMPACK_OVERHEAD;
 encmem_remain=0;
 file_packing=0;
 packmem_remain=mempack->compsize-MEMPACK_OVERHEAD;
 /* v 2.76.04+ - to allow for ARJCRYPT modules within SFXV, we reinitialize
    the encryption only for garbled files (was for garble_enabled until now) */
 if(file_garbled)
  garble_init(password_modifier);
 crc32term=CRC_MASK;
 if(method==1||method==2||method==3)
  decode(BOP_NONE);
 #if SFX_LEVEL>=ARJ
 else if(method==4)
  decode_f(BOP_NONE);
 #endif
 else if(method==0)
  unstore(BOP_NONE);
 c_t=(unsigned long)((unsigned char)mempack->comp[0])+
     ((unsigned long)((unsigned char)mempack->comp[1])<<8)+
     ((unsigned long)((unsigned char)mempack->comp[2])<<16)+
     ((unsigned long)((unsigned char)mempack->comp[3])<<24);
 if(c_t!=(crc32term^CRC_MASK))
  error(M_CRC_ERROR);
 file_type=s_type;
 file_packing=s_packing;
 compsize=s_compsize;
 origsize=s_origsize;
 method=s_method;
}

#endif

/* Strips ending LF character from the given string */

#if SFX_LEVEL>=ARJSFX||defined(REGISTER)||defined(REARJ)
void strip_lf(char *str)
{
 int i;

 if((i=strlen(str))>0)
 {
  if(str[i-1]==LF)
   str[i-1]='\0';
 }
}
#endif

/* Trims leftmost spaces */

#if SFX_LEVEL>=ARJ||defined(REGISTER)||defined(REARJ)
char *ltrim(char *str)
{
 char *rc;

 for(rc=str; *rc==' '; rc++);
 return(rc);
}
#endif

#if defined(WORDS_BIGENDIAN)&&!defined(ARJDISP)&&!defined(REGISTER)
/* Model-independent routine to get 2 bytes from far RAM */

unsigned int mget_word(char FAR *p)
{
 unsigned int b0, b1;

 b0=mget_byte(p);
 b1=mget_byte(p+1);
 return (b1<<8)|b0;
}

/* Model-independent routine to get 4 bytes from far RAM */

unsigned long mget_dword(char FAR *p)
{
 unsigned long w0, w1;

 w0=mget_word(p);
 w1=mget_word(p+2);
 return (w1<<16)|w0;
}

/* Model-independent routine to store 2 bytes in far RAM */

void mput_word(unsigned int w, char FAR *p)
{
 mput_byte(w&0xFF, p);
 mput_byte(w>>8  , p+1);
}

/* Model-independent routine to store 4 bytes in far RAM */

void mput_dword(unsigned long d, char FAR *p)
{
 mput_word(d&0xFFFF, p);
 mput_word(d>>16   , p+2);
}
#endif
