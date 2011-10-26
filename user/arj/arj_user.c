/*
 * $Id: arj_user.c,v 1.11 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * High-level routines that perform ARJ command processing are located in this
 * module. It may be partially inherited by ARJSFXV and ARJSFX.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Operating system names used in short listings. For their numerical
   equivalents see ARJ_USER.H. */

static char *host_os_names[]={"MS-DOS", "PRIMOS", "UNIX", "AMIGA", "MAC-OS",
                              "OS/2", "APPLE GS", "ATARI ST", "NEXT",
                              "VAX VMS", "WIN95", "WIN32", NULL};

/* Binary/Text/... - type signature */

#if SFX_LEVEL>=ARJSFXV
static char type_sig[]={'B', 'T', '?', 'D', 'V', 'C', 'U'};
#else
static char type_sig[]={'B', 'T', '?', 'D'};
#endif

/* Combined volume/extfile flags for UNIX-mode lists */

#if TARGET==UNIX&&SFX_LEVEL>=ARJSFXV
static char vfext_flags[]={' ', '>', '<', '*'};
#endif

/* List order */

#if SFX_LEVEL>=ARJSFXV
 #if TARGET==UNIX
  #define LFLAGS is_chapter?'*':' ', is_in_subdir?'+':' ', method, enc_type, vfext_flags[(is_volume?1:0)+(is_extfile?2:0)]
 #else
  #define LFLAGS is_chapter?'*':' ', type_sig[uf_type], is_in_subdir?'+':' ', method, enc_type, is_volume?'V':' ', is_extfile?'X':' '
 #endif
#else
 #if TARGET==UNIX
  #define LFLAGS is_in_subdir?'+':' ', method, enc_type
 #else
  #define LFLAGS type_sig[uf_type], is_in_subdir?'+':' ', method, enc_type
 #endif
#endif
#if TARGET!=UNIX
 #define LMODESTR file_crc, mode_str
#else
 #define LMODESTR mode_str
#endif

/* Y2K mess */

#if SFX_LEVEL>=ARJSFXV
static char century_sig[]={' ', ' ', '1'}; /* 20th/21st/22nd centuries */
#endif

/* Misc. */

static char volfmt_2digit[]="%s%02d";
static char volfmt_3digit[]="%s%03d";
static char volfmt_4digit[]="%s%4d";
static char stub_fmt[]="%s%03d%s";
static char bell[]="\a";

/* Local variables */

static FILE_COUNT total_processed;      /* Number of already processed files */
static unsigned long FAR *order_list;   /* List of files to order */
#if SFX_LEVEL>=ARJ
static FILE_COUNT cf_num;               /* Current file # */
#endif
static FILE_COUNT order_fcap;           /* Size of order array */
static FILE_COUNT order_fcount;         /* # of files in order array */
static FILE_COUNT vol_file_num;
static unsigned long saved_timestamp;
#if SFX_LEVEL>=ARJ
static char *arjsec_signature;
#else
static char arjsec_signature[ARJSEC_SIG_MAXLEN];
#endif
static unsigned long first_file_offset; /* Offset of first file within arch. */

#if SFX_LEVEL>=ARJSFXV
static int total_os;
static int is_removable;                /* 1 if the current archive is on a
                                           removable media */
#endif

/* Since ARJSFX has totally static allocation, the cache buffers are statically
   allocated, too */

#if SFX_LEVEL<=ARJSFX&&!defined(NO_CACHING)
static char cache_buf[VBUF_SFX];
#endif

/* Return 1 if the given system is similar to ARJ host OS */

int test_host_os(int os)
{
 int i;

 for(i=0; friendly_systems[i]>=0; i++)
 {
  if(friendly_systems[i]==os)
   return(1);
 }
 return(0);
}

#if SFX_LEVEL>=ARJ

/* Allocates RAM for and composes the protection filename */

char *form_prot_name()
{
 int name_len;
 char *result;                          /* Address of newly-formed buffer */
 char *tmp_ptr;

 name_len=strlen(archive_name)+far_strlen(M_PROT_SUFFIX)+2;
 strcpy(result=malloc_msg(name_len), archive_name);
 name_len=split_name(result, NULL, NULL);
 if((tmp_ptr=strchr(&result[name_len], '.'))==NULL)
  msg_strcat(result, M_PROT_SUFFIX);
 else if(tmp_ptr[1]=='\0')
  msg_strcat(result, M_PROT_SUFFIX);
 else
  tmp_ptr[1]=M_PROT_SUFFIX[1];          /* Substitute first letter of extension
                                           with the one from prot_name suffix */
 return(result);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Checks for the occurence of the destination file, returns 1 if the file can
   be extracted, 0 if it already exists and must be skipped */

int destfile_extr_validation()
{
 char tmp_name[FILENAME_MAX];

 if(!new_files_only)
  return(1);
 strcpy(tmp_name, filename);
 add_base_dir(tmp_name);
 return(!file_exists(tmp_name));
}

#endif

#if SFX_LEVEL>=ARJ

/* Writes an index file entry */

void write_index_entry(char *prefix)
{
 int bytes_written;

 if(create_index)
 {
  if(prefix[0]=='\0')
   bytes_written=msg_fprintf(idxstream, M_IDXFMT_NP, filename);
  else
   bytes_written=msg_fprintf(idxstream, (strlen(prefix)>3)?M_IDXFMT_LONG:M_IDXFMT_SHORT, prefix, filename);
  if(bytes_written==0)
   error(M_DISK_FULL);
 }
}

#endif

/* Outputs the listing header */

static void show_list_header()
{
 #if SFX_LEVEL>=ARJ
  if(std_list_cmd)
  {
   if(verbose_display==VERBOSE_STD)
    return;
   if(verbose_display==VERBOSE_ENH)
    msg_cprintf(0, M_VLIST_P1);
   else
   {
    msg_cprintf(0, M_VLIST_HDR);
    msg_cprintf(0, M_VLIST_P1);
   }
  }
  else
   msg_cprintf(0, M_LIST_P1);
  msg_cprintf(0, verbose_display?M_LIST_P2_CHAP:M_LIST_P2);
 #else
  if(std_list_cmd)
  {
   msg_cprintf(0, M_VLIST_HDR);
   msg_cprintf(0, M_VLIST_P1);
  }
  else
   msg_cprintf(0, M_LIST_P1);
  msg_cprintf(0, M_LIST_P2);
 #endif
 msg_cprintf(0, M_LIST_SEPARATOR);
}

/* Picks the most favorable century character */

#if SFX_LEVEL>=ARJSFXV
static char pick_century(char *timetext)
{
 int n_centuries;

 #if SFX_LEVEL>=ARJ
  switch(skip_century)
  {
   case CENT_DEFAULT:
    if(timetext[0]=='2'&&timetext[1]=='0')
     n_centuries=1;
    else if(timetext[0]=='2'&&timetext[1]=='1')
     n_centuries=2;
    else
     n_centuries=0;
    return(century_sig[n_centuries]);
   case CENT_SKIP:
    return(' ');
   case CENT_SMART:
    if(timetext[0]=='1'||(timetext[0]=='2'&&timetext[1]=='0'&&timetext[2]<'7'))
     return(' ');
    else
     return(timetext[1]);
  }
  return(' ');
 #elif SFX_LEVEL>=ARJSFXV
  if(timetext[0]=='2'&&timetext[1]=='0')
   n_centuries=1;
  else if(timetext[0]=='2'&&timetext[1]=='1')
   n_centuries=2;
  else
   n_centuries=0;
  return(century_sig[n_centuries]);
 #endif
}
#endif

/* List command itself */

#if SFX_LEVEL>=ARJSFXV
static int list_cmd(FILE_COUNT lnum, FILE_COUNT fnum)
#else
static void list_cmd()
#endif
{
 int is_in_subdir;
 #if SFX_LEVEL>=ARJSFXV
  int is_volume, is_extfile;
  int is_chapter;                   /* Chapter or backup */
  char FAR *raw_ea;
  unsigned int raw_ea_size;
  struct ext_hdr FAR *p_eh;
 #endif
 #if SFX_LEVEL>=ARJ
  char tmp_name[FILENAME_MAX];
 #endif
 int uf_type;
 unsigned int ratio;
 unsigned int entry;
 char timetext[22];
 char mode_str[16];                 /* ASR fix for 2.77 */
 char *tmp_ptr;                     /* Either from the host_os_names list or
                                       nullstr */
 char enc_type;

 #if SFX_LEVEL>=ARJSFXV
  if(!destfile_extr_validation())
   return(0);
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(lnum==0)
   show_list_header();
 #else
  if(total_files==0)
   show_list_header();
 #endif
 #if SFX_LEVEL>=ARJ
  for(total_os=0; host_os_names[total_os]!=NULL; total_os++);
 #endif
 enc_type=(arj_flags&GARBLED_FLAG)?ext_hdr_flags+'0':' ';
 #if SFX_LEVEL>=ARJSFXV
  is_volume=(arj_flags&VOLUME_FLAG)?1:0;
  is_extfile=(arj_flags&EXTFILE_FLAG)?1:0;
 #endif
 #if SFX_LEVEL>=ARJ
  is_chapter=(total_chapters!=0&&((int)chapter_number<total_chapters||(int)ext_flags>total_chapters))?1:0;
 #elif SFX_LEVEL==ARJSFXV
  is_chapter=(arj_flags&BACKUP_FLAG)?1:0;
 #endif
 is_in_subdir=entry_pos>0;
 ratio=calc_percentage(compsize, origsize);
 total_uncompressed+=origsize;
 total_compressed+=compsize;
 #if SFX_LEVEL>=ARJSFXV
  if(chk_free_space)
   disk_space_used+=((origsize+(unsigned long)alloc_unit_size-1L)/(unsigned long)alloc_unit_size)*(unsigned long)alloc_unit_size;
 #endif
 timestamp_to_str(timetext, &ftime_stamp);
 #if SFX_LEVEL>=ARJ
  uf_type=(file_type==ARJT_BINARY||file_type==ARJT_TEXT||file_type==ARJT_DIR||file_type==ARJT_UXSPECIAL||file_type==ARJT_LABEL||file_type==ARJT_CHAPTER)?file_type:ARJT_COMMENT;
 #elif SFX_LEVEL==ARJSFXV
  uf_type=(file_type==ARJT_BINARY||file_type==ARJT_TEXT||file_type==ARJT_DIR||file_type==ARJT_UXSPECIAL||file_type==ARJT_LABEL)?file_type:ARJT_DIR;
 #else
  uf_type=(file_type==ARJT_BINARY||file_type==ARJT_TEXT||file_type==ARJT_DIR)?file_type:ARJT_DIR;
 #endif
 /* In ARJSFX, there are no non-host OSes */
 #if SFX_LEVEL<=ARJSFX
  mode_str[0]='\0';
 #else
  msg_strcpy(mode_str, M_EMPTY_ATTR);
 #endif
 if(test_host_os(host_os))
 {
  get_mode_str(mode_str, file_mode.native);
  #if TARGET==UNIX
   if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
    mode_str[0]='-';
   else
    mode_str[0]=tolower(type_sig[uf_type]);
  #endif
 }
 #if SFX_LEVEL>=ARJ
  strcpy(tmp_name, filename);
  if((uf_type==ARJT_BINARY||uf_type==ARJT_TEXT||uf_type==ARJT_DIR||file_type==ARJT_UXSPECIAL)&&(host_os==OS_WIN95||host_os==OS_WINNT))
  {
   total_longnames++;
   if(volume_flag_set)
    split_longnames++;
  }
 #endif
 if(std_list_cmd)
 {
  #if SFX_LEVEL>=ARJSFXV
  #if SFX_LEVEL>=ARJ
   if(verbose_display!=VERBOSE_ENH)
   {
    if(verbose_display==VERBOSE_NONE)
    {
  #endif
     msg_cprintf(H_HL, M_LIST_NUM_FMT, fnum);
  #if SFX_LEVEL>=ARJ
    }
  #endif
    #if SFX_LEVEL>=ARJ
     entry=(exclude_paths==EP_PATH)?(unsigned int)entry_pos:0;
     msg_cprintf(H_HL, M_FILENAME_FORM, tmp_name+entry);
    #else
     entry=0;
     msg_cprintf(H_HL, M_FILENAME_FORM, filename);
    #endif
    #if SFX_LEVEL>=ARJ
     if(verbose_display==VERBOSE_STD)
      return(1);
    #endif
    if(comment[0]!='\0')
    {
     display_comment(comment);
     #if SFX_LEVEL>=ARJ
      msg_cprintf(0, (FMSG *)lf);
     #endif
    }
    #if SFX_LEVEL>=ARJ
     if(ext_flags!=0)
      msg_cprintf(H_HL|H_NFMT, M_CHAPTER_LIST_FMT, (int)ext_flags, (int)chapter_number);
    #endif
  #if SFX_LEVEL>=ARJ
   }
  #endif
   tmp_ptr=((int)host_os>=total_os)?nullstr:host_os_names[host_os];
   msg_cprintf(H_HL|H_NFMT, M_REV_OS_FMT, (int)arj_nbr, tmp_ptr);
  #else
   msg_cprintf(H_HL, M_VERBOSE_NAME_FMT, filename);
   if(comment[0]!='\0')
   {
    if(show_ansi_comments)
     printf(strform, comment);
    else
     display_comment(comment);
   }
   msg_cprintf(H_HL|H_NFMT, M_REV_OS_FMT, (int)arj_nbr, host_os_names[host_os]);
  #endif
 }
 else
  #if SFX_LEVEL>=ARJ
   msg_cprintf(0, (strlen(tmp_name+entry_pos)>12)?M_LONG_NAME_FMT:M_SHORT_NAME_FMT, tmp_name+entry_pos);
  #elif SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, (strlen(filename+entry_pos)>12)?M_LONG_NAME_FMT:M_SHORT_NAME_FMT, filename+entry_pos);
  #else
   msg_cprintf(0, (strlen(list_adapted_name)>12)?M_LONG_NAME_FMT:M_SHORT_NAME_FMT, list_adapted_name);
  #endif
#if SFX_LEVEL>=ARJ
 if(verbose_display)
  msg_cprintf(H_HL|H_NFMT, M_VERBOSE_LIST_LINE, origsize, compsize, ratio/1000, ratio%1000, pick_century(timetext), timetext+2, (int)ext_flags, (int)chapter_number, mode_str, LFLAGS);
 else
#endif
 #if SFX_LEVEL>=ARJSFXV
  msg_cprintf(H_HL|H_NFMT, M_STD_LIST_LINE, origsize, compsize, ratio/1000, ratio%1000, pick_century(timetext), timetext+2, LMODESTR, LFLAGS);
 #else
  msg_cprintf(H_HL|H_NFMT, M_STD_LIST_LINE, origsize, compsize, ratio/1000, ratio%1000, timetext+2, LMODESTR, LFLAGS);
 #endif
 #if SFX_LEVEL>=ARJ
  if(std_list_cmd&&verbose_display==VERBOSE_ENH)
  {
   if((tmp_ptr=strrchr(tmp_name, '.'))==NULL)
    tmp_ptr=nullstr;
   msg_cprintf(H_HL|H_NFMT, M_PATH_LIST_FMT, tmp_ptr, tmp_name+entry_pos, filename);
  }
  msg_cprintf(0, (FMSG *)lf);
  if(std_list_cmd&&ts_valid(atime_stamp)&&verbose_display!=VERBOSE_ENH)
  {
   timestamp_to_str(timetext, &atime_stamp);
   msg_cprintf(H_HL|H_NFMT, M_ATIME_FMT, pick_century(timetext), timetext+2);
   timestamp_to_str(timetext, &ctime_stamp);
   msg_cprintf(H_HL|H_NFMT, M_CTIME_FMT, pick_century(timetext), timetext+2);
  }
  /* Report the extended headers */
  if(std_list_cmd&&valid_ext_hdr&&!(arj_flags&VOLUME_FLAG)&&verbose_display!=VERBOSE_ENH)
  {
   /* UNIX special files */
   if((p_eh=eh_lookup(eh, UXSPECIAL_ID))!=NULL)
    uxspecial_stats(p_eh->raw, UXSTATS_LONG);
   /* Owner (character) */
   if((p_eh=eh_lookup(eh, OWNER_ID))!=NULL)
    owner_stats(p_eh->raw, 1);
   /* Owner (UID/GID). The archiving won't allow simultaneous storage of both
      numeric and character IDs */
   if((p_eh=eh_lookup(eh, OWNER_ID_NUM))!=NULL)
    owner_stats(p_eh->raw, 0);
   /* EAs */
   if((p_eh=eh_lookup(eh, EA_ID))!=NULL&&(!file_garbled||garble_enabled))
   {
    raw_ea=unpack_ea(p_eh);
    raw_ea_size=get_eablk_size(raw_ea);
    ratio=calc_percentage((unsigned long)p_eh->size, (unsigned long)raw_ea_size);
    msg_cprintf(H_HL|H_NFMT, M_EA_LIST, raw_ea_size, p_eh->size, ratio/1000, ratio%1000, get_num_eas(raw_ea));
    farfree(raw_ea);
   }
  }
  write_index_entry(nullstr);
 #else
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, (FMSG *)lf);
  #endif
 #endif
 #if SFX_LEVEL>=ARJSFXV
  return(1);
 #endif
}

/* A simplified set of filelist routines */

#if SFX_LEVEL<=ARJSFX

/* Looks for the given fully-qualified filename in the file argument array */

static int f_arg_lookup(char *name)
{
 int i;

 for(i=0; i<sflist_args; i++)
  if(!strcmp_os(name, sflist[i]))
   return(i+1);
 return(0);
}

/* Adds a new filename to the arg table if it's not present there */

static void add_f_arg(char *name)
{
 char *nptr;

 if(f_arg_lookup(name)==0)
 {
  if((nptr=(char *)malloc(strlen(name)+1))==NULL)
   error(M_OUT_OF_MEMORY);
  strcpy(nptr, name);
  sflist[sflist_args++]=nptr;
 }
}

#endif

#if SFX_LEVEL>=ARJ

/* Checks if an archived file can be processed, returns 1 if yes. */

static int processing_validation()
{
 int rc;
 int entry;

 if(filter_attrs)
 {
  rc=0;
  if(file_attr_mask&TAG_WINLFN&&(host_os==OS_WIN95||host_os==OS_WINNT)&&
     (file_type==ARJT_DIR||file_type==ARJT_UXSPECIAL||file_type==ARJT_BINARY||file_type==ARJT_TEXT))
   rc=1;
  if(file_attr_mask&TAG_LABEL&&file_type==ARJT_LABEL)
   rc=1;
  if(file_attr_mask&TAG_CHAPTER&&file_type==ARJT_CHAPTER)
   rc=1;
  if(file_attr_mask&TAG_DIREC&&file_type==ARJT_DIR)
   rc=1;
  if(file_attr_mask&TAG_UXSPECIAL&&file_type==ARJT_UXSPECIAL)
   rc=1;
  if(file_attr_mask&TAG_NORMAL&&(file_type==ARJT_BINARY||file_type==ARJT_TEXT))
  {
   if((file_mode.dos&FATTR_DIREC)!=FATTR_DIREC&&
      (file_mode.dos&FATTR_RDONLY)!=FATTR_RDONLY&&
      (file_mode.dos&FATTR_SYSTEM)!=FATTR_SYSTEM&&
      (file_mode.dos&FATTR_HIDDEN)!=FATTR_HIDDEN&&
      file_type!=ARJT_UXSPECIAL)
    rc=1;
  }
  if(file_attr_mask&TAG_RDONLY&&file_mode.dos&FATTR_RDONLY)
   rc=1;
  if(file_attr_mask&TAG_HIDDEN&&file_mode.dos&FATTR_HIDDEN)
   rc=1;
  if(file_attr_mask&TAG_SYSTEM&&file_mode.dos&FATTR_SYSTEM)
   rc=1;
  if(file_attr_mask&TAG_ARCH&&(file_mode.dos&FATTR_ARCH)!=FATTR_ARCH)
   return(0);
  if(file_attr_mask&TAG_NOT_ARCH&&file_mode.dos&FATTR_ARCH)
   return(0);
  if(!rc)
   return(0);
 }
 if(ts_valid(tested_ftime_newer)&&(filter_same_or_newer==TCHECK_FTIME||filter_same_or_newer==TCHECK_NDAYS))
 {
  if(ts_cmp(&ftime_stamp, &tested_ftime_newer)<0)
   return(0);
 }
 if(ts_valid(tested_ftime_older)&&(filter_older==TCHECK_FTIME||filter_older==TCHECK_NDAYS))
 {
  if(ts_cmp(&ftime_stamp, &tested_ftime_older)>=0)
   return(0);
 }
 /* ctime */
 if(ts_valid(tested_ftime_newer)&&filter_same_or_newer==TCHECK_CTIME)
 {
  if(ts_cmp(&ctime_stamp, &tested_ftime_newer)<0)
   return(0);
 }
 if(ts_valid(tested_ftime_older)&&filter_older==TCHECK_CTIME)
 {
  if(ts_cmp(&ctime_stamp, &tested_ftime_older)>=0)
   return(0);
 }
 /* atime */
 if(ts_valid(tested_ftime_newer)&&filter_same_or_newer==TCHECK_ATIME)
 {
  if(ts_cmp(&atime_stamp, &tested_ftime_newer)<0)
   return(0);
 }
 if(ts_valid(tested_ftime_older)&&filter_older==TCHECK_ATIME)
 {
  if(ts_cmp(&atime_stamp, &tested_ftime_older)>=0)
   return(0);
 }
 entry=(add_command&&exclude_paths==EP_BASEDIR)?strlen(target_dir):0;
 return(!flist_find(&flist_exclusion, filename+entry));
}

/* Retrieves total statistics for the archive */

static void get_totals()
{
 FILE_COUNT cur_file;

 if(add_command)
 {
  total_size=0L;
  total_written=0L;
  display_totals=1;
  for(cur_file=0; cur_file<flist_main.files; cur_file++)
  {
   flist_retrieve(filename, &properties, &flist_main, cur_file);
   if(match_attrib(&properties))
    total_size+=properties.fsize;
  }
 }
}

/* Basic archive processing routine */

static void process_archive(int cmd, int no_in_arch)
{
 FILE_COUNT pf_num;
 FILE_COUNT cur_file;
 int val_result;
 int update_perm;                       /* Update permission */
 int pack_rc;
 int sp_action;

 ts_store(&ftime_stamp, OS_SPECIAL, 0L);
 force_volume_flag=0;
 if(modify_command)
  ext_hdr_capacity=LONG_MAX;            /* ASR fix 15/05/2003 */
 while(!no_in_arch&&read_header(0, aistream, archive_name))
 {
  if(!modify_command&&exit_after_count&&total_processed+comment_entries+total_files-split_files>=exit_count)
   break;
  pf_num=flist_lookup(++cf_num);
  val_result=processing_validation();
  switch(cmd)
  {
   case ARJ_CMD_ADD:
    if(pf_num!=0&&file_type!=ARJT_LABEL)
    {
     flist_retrieve(filename, &properties, &flist_main, pf_num-1);
     update_perm=1;
     if(serialize_exts)
     {
      msg_sprintf(misc_buf, M_QUERY_UPDATE, filename);
      update_perm=query_action(REPLY_YES, QUERY_UPDATE, (FMSG *)misc_buf);
     }
     if(update_perm)
     {
      if(!new_files_only)
      {
       pack_rc=pack_file_stub(0, 1);
       if(pack_rc!=0)
       {
        if(volume_flag_set)
        {
         vol_file_num=pf_num;
         break;
        }
        if(pack_rc!=1)
         break;
        cfa_store(pf_num-1, FLFLAG_PROCESSED);
        break;
       }
      }
     }
     cfa_store(pf_num-1, FLFLAG_SKIPPED);
    }
    special_processing(CFA_NONE, aistream);
    break;
   case ARJ_CMD_COMMENT:
    if(pf_num&&val_result&&(!use_comment||supply_comment_file)&&!(arj_flags&EXTFILE_FLAG))
    {
     update_perm=1;
     if(query_for_each_file)
     {
      msg_sprintf(misc_buf, M_QUERY_COMMENT, filename);
      update_perm=query_action(REPLY_YES, QUERY_ARCH_OP, (FMSG *)misc_buf);
     }
     if(update_perm)
     {
      if(supply_comment(comment_file, filename))
       comment_entries++;
     }
    }
    special_processing(CFA_NONE, aistream);
    break;
   case ARJ_CMD_DELETE:
    if(pf_num&&val_result)
    {
     if(arcv_delete(cf_num))
      break;
    }
    special_processing(CFA_NONE, aistream);
    break;
   case ARJ_CMD_FRESHEN:
   case ARJ_CMD_UPDATE:
    if(pf_num&&file_type!=ARJT_LABEL)
    {
     flist_retrieve(filename, &properties, &flist_main, pf_num-1);
     pack_rc=pack_file_stub(1, 1);
     if(pack_rc!=0)
     {
      if(vol_file_num==pf_num)
      {
       if(volume_flag_set)
        break;
       if(pack_rc==1)
        cfa_store(vol_file_num-1, FLFLAG_PROCESSED);
       vol_file_num=0;
       break;
      }
      if(volume_flag_set)
       vol_file_num=pf_num;
      else if(pack_rc==1)
       cfa_store(pf_num-1, FLFLAG_PROCESSED);
      break;
     }
     special_processing(CFA_NONE, aistream);
     cfa_store(pf_num-1, FLFLAG_SKIPPED);
     break;
    }
    special_processing(CFA_NONE, aistream);
    break;
   case ARJ_CMD_GARBLE:
    sp_action=CFA_NONE;
    if(pf_num!=0&&val_result)
    {
     update_perm=1;
     if(query_for_each_file)
     {
      msg_sprintf(misc_buf, M_QUERY_GARBLE, filename);
      update_perm=query_action(REPLY_YES, QUERY_ARCH_OP, (FMSG *)misc_buf);
     }
     if(update_perm)
      sp_action=CFA_GARBLE;
    }
    special_processing(sp_action, aistream);
    break;
   case ARJ_CMD_RENAME:
    if(pf_num!=0&&val_result)
    {
     if(rename_file())
      total_files++;
    }
    special_processing(CFA_NONE, aistream);
    break;
   case ARJ_CMD_ORDER:
    if(arj_flags&VOLUME_FLAG||arj_flags&EXTFILE_FLAG)
     error(M_CANT_ORDER_MV);
    if(order_fcount>=order_fcap)
    {
     if(order_fcap==0)
      order_fcap=flist_main.files;
     order_fcap+=FILELIST_INCREMENT;
     if((order_list=(unsigned long FAR *)farrealloc(order_list, order_fcap*sizeof(unsigned long)))==NULL)
      error(M_OUT_OF_MEMORY);
    }
    if(pf_num!=0)
    {
     arch_hdr_index[pf_num-1]=cur_header_pos;
     cfa_store(pf_num-1, FLFLAG_PROCESSED);
     order_list[order_fcount++]=0L;
    }
    else
     order_list[order_fcount++]=cur_header_pos;
    total_files++;
    skip_compdata();
    break;
   case ARJ_CMD_REMPATH:
    sp_action=CFA_NONE;
    if(pf_num!=0&&val_result)
    {
     update_perm=1;
     if(query_for_each_file)
     {
      msg_sprintf(misc_buf, M_QUERY_GARBLE, filename);
      update_perm=query_action(REPLY_YES, QUERY_ARCH_OP, (FMSG *)misc_buf);
     }
     if(update_perm)
      sp_action=CFA_REMPATH;
    }
    special_processing(sp_action, aistream);
    break;
   case ARJ_CMD_JOIN:
   case ARJ_CMD_SECURE:
    special_processing(CFA_NONE, aistream);
    total_files++;
    break;
   case ARJ_CMD_COPY:
    sp_action=CFA_NONE;
    if(pf_num!=0&&val_result)
    {
     if(chapter_mode==CHAP_USE)
      sp_action=CFA_MARK_EXT;
     else if(chapter_mode==CHAP_REMOVE)
      sp_action=CFA_UNMARK_EXT;
     else if(garble_enabled)
      sp_action=CFA_UNGARBLE;
    }
    special_processing(sp_action, aistream);
    break;
   case ARJ_CMD_EXTR_NP:
   case ARJ_CMD_PRINT:
    if(pf_num!=0&&val_result)
    {
     update_perm=1;
     if(query_for_each_file)
     {
      if(!first_vol_passed||!continued_prevvolume)
      {
       msg_sprintf(misc_buf, M_QUERY_EXTRACT, filename);
       update_perm=query_action(REPLY_YES, QUERY_ARCH_OP, (FMSG *)misc_buf);
      }
      else
      {
       if(ofstream==NULL)
        update_perm=0;
      }
     }
     if(update_perm)
     {
      if(unpack_file_proc(cmd==ARJ_CMD_PRINT, cf_num))
      {
       total_files++;
       if(volume_flag_set)
        split_files++;
      }
      tmp_tmp_filename[0]='\0';
     }
     else
      skip_compdata();
    }
    else
     skip_compdata();
    break;
   case ARJ_CMD_LIST:
    if(pf_num!=0&&val_result)
    {
     if(list_cmd(total_files, cf_num))
      total_files++;
    }
    skip_compdata();
    break;
   case ARJ_CMD_TEST:
    if(pf_num!=0&&val_result)
    {
     if(test_archive_crc==TC_CRC_AND_CONTENTS)
      add_base_dir(filename);
     if(unpack_validation(cmd))
      total_files++;
    }
    else
     skip_compdata();
    break;
   case ARJ_CMD_WHERE:
    if(pf_num!=0&&val_result)
    {
     if(unpack_validation(cmd))
      total_files++;
    }
    else
     skip_compdata();
    break;
  }
 }
 if((cmd==ARJ_CMD_ADD||cmd==ARJ_CMD_UPDATE)&&multivolume_option&&continued_nextvolume&&!no_inarch)
  volume_flag_set=1;
 if(multivolume_option&&add_command)
  continued_nextvolume=1;
 ext_voldata=0;
 /* ASR fix for v 2.76.04 - prevent phantom EAs at archive joints */
 if(!continued_nextvolume)
 {
  if(eh!=NULL)
  {
   eh_release(eh);
   eh=NULL;
  }
 }
 if(cmd==ARJ_CMD_ADD||cmd==ARJ_CMD_UPDATE)
 {
  if(cf_num!=0)
  {
   resume_position=0L;
   continued_prevvolume=0;
  }
  if(multivolume_option&&check_multivolume(MULTIVOLUME_INCREMENT)<MULTIVOLUME_INCREMENT)
   volume_flag_set=1;
  if(!volume_flag_set&&vol_file_num!=0)
  {
   flist_retrieve(filename, &properties, &flist_main, vol_file_num-1);
   if(pack_file_stub(0, 0)&&!volume_flag_set)
   {
    cfa_store(vol_file_num-1, FLFLAG_PROCESSED);
    vol_file_num=0;
   }
  }
  for(cur_file=0; !volume_flag_set&&cur_file<flist_main.files; cur_file++)
  {
   if(cfa_get(cur_file)==FLFLAG_TO_PROCESS)
   {
    flist_retrieve(filename, &properties, &flist_main, cur_file);
    if(pack_file_stub(0, 0))
    {
     if(volume_flag_set)
      vol_file_num=cur_file+1;
     else
      cfa_store(cur_file, FLFLAG_PROCESSED);
    }
    else
     cfa_store(cur_file, FLFLAG_SKIPPED);
    if(multivolume_option&&check_multivolume(MULTIVOLUME_INCREMENT)<MULTIVOLUME_INCREMENT&&(cur_file+1)<flist_main.files)
     volume_flag_set=1;
   }
  }
  if(multivolume_option&&check_multivolume(MULTIVOLUME_INCREMENT)<MULTIVOLUME_INCREMENT&&cur_file<flist_main.files)
   volume_flag_set=1;
#ifdef HAVE_VOL_LABELS
  if(handle_labels&&!volume_flag_set)
   store_label();
#endif
  if(multivolume_option&&check_multivolume(MULTIVOLUME_INCREMENT)<MULTIVOLUME_INCREMENT&&cur_file<flist_main.files)
   volume_flag_set=1;
  if(total_chapters!=0&&!volume_flag_set&&current_chapter<=CHAPTERS_MAX&&total_chapters>recent_chapter)
   create_chapter_mark();
 }
 else if(cmd==ARJ_CMD_JOIN)
  total_files+=copy_archive();
 else if(cmd==ARJ_CMD_ORDER)
 {
  pf_num=0;
  for(cur_file=0; cur_file<flist_main.files; cur_file++)
  {
   /* has been previously selected? Otherwise its "default" value is FLFLAG_TO_PROCESS :-o */   
   if(cfa_get(cur_file)==FLFLAG_PROCESSED)
   {
    fseek(aistream, arch_hdr_index[cur_file], SEEK_SET);
    read_header(0, aistream, archive_name);
    special_processing(CFA_NONE, aistream);
    pf_num++;
   }
  }
  for(cur_file=0; cur_file<order_fcount; cur_file++)
  {
   if(order_list[cur_file]>0L)
   {
    fseek(aistream, order_list[cur_file], SEEK_SET);
    read_header(0, aistream, archive_name);
    special_processing(CFA_NONE, aistream);
    pf_num++;
   }
  }
  if(total_files!=pf_num)
   error(M_ORDER_CNT_MISMATCH);
  msg_cprintf(0, M_FILES_REORDERED);
 }
 if(cmd==ARJ_CMD_COPY&&total_chapters!=0&&!volume_flag_set&&total_files!=0&&total_chapters>recent_chapter)
  create_chapter_mark();
}

/* Some post-processing actions */

static void finish_processing(int cmd)
{
 int skip_query;
 unsigned long cur_pos, eof_pos;
 int entry;
 char *ext_ptr;
 char *bak_name;
 FILE_COUNT cur_file;
 int vol_code;
 char *msg_ptr;
 int ratio;
 unsigned long free_space;
 int protected=0;
 int is_prot;

 if(modify_command)
 {
  if(cmd==ARJ_CMD_DELETE&&total_files!=0&&file_args==1&&!strcmp_os(f_arg_array[0], all_wildcard))
  {
   skip_query=yes_on_all_queries||query_delete;
   if(!skip_query)
   {
    msg_sprintf(misc_buf, M_QUERY_DELETE_N_FILES, total_files);
    if(!query_action(REPLY_YES, QUERY_DELETE_N_FILES, (FMSG *)misc_buf))
    {
     errors++;
     tmp_archive_cleanup();
     longjmp(main_proc, 1);
    }
   }
  }
  if(cmd==ARJ_CMD_DELETE&&total_chapters!=0&&current_chapter!=RESERVED_CHAPTER&&total_chapters>max_chapter)
   final_header(FP_CHAPTER);
  if(cmd==ARJ_CMD_DELETE&&!first_vol_passed&&!continued_nextvolume&&ftell(aostream)==first_file_offset)
  {
   msg_cprintf(H_HL|H_NFMT, M_DELETING_EMPTY_ARCH, archive_name);
   file_close(aistream);
   aistream=NULL;
   if(!no_file_activity)
   {
    if(file_unlink(archive_name))
     error(M_CANT_DELETE, archive_name);
    tmp_archive_cleanup();
   }
  }
  /* ASR fix: the original didn't check for ARJ_CMD_COMMENT */
  else if(total_files!=0||(cmd==ARJ_CMD_COMMENT&&comment_entries!=0)||create_sfx!=0)
  {
   fput_word(HEADER_ID, aostream);
   fput_word(0, aostream);
   last_hdr_offset=0L;
   if(!no_file_activity)
   {
    eof_pos=ftell(aostream);
    if(continued_nextvolume&&add_command&&!volume_flag_set&&!force_volume_flag)
    {
     final_header(FP_VOLUME);
     continued_nextvolume=0;
    }
    if(!encryption_applied&&encryption_id!=ENCID_NONE)
     final_header(FP_GARBLE);
    if(sign_with_arjsec)
    {
     msg_cprintf(0, M_WORKING);
     cur_pos=ftell(aostream);
     secured_size=cur_pos-main_hdr_offset;
     arjsec_offset=(unsigned long)is_registered*cur_pos;
     final_header(FP_SECURITY);
     if(create_envelope(aostream, arjsec_offset, ARJSEC_ITER))
     {
      arj_delay(5);
      error(M_NO_ARJSEC_KEY);
     }
    }
    if(test_archive_crc)
    {
     archive_cleanup();
     cmd_verb=cmd;
    }
    protected=0;
    if(arjprot_tail)
    {
     if(prot_blocks==0)
      prot_blocks=arjprot_tail;
     fseek(aostream, 0L, SEEK_END);
     arjsec_offset=ftell(aostream);
     if(!sign_with_arjsec)
      final_header(FP_PROT);
     protected=1;
     create_protfile(aostream, prot_blocks, 0);
    }
    if(multivolume_option)
    {
     fseek(aostream, 0L, SEEK_END);
     if(debug_enabled&&strchr(debug_opt, 'a')!=NULL&&create_index)
     {
      if(msg_fprintf(idxstream, M_ARCH_SIZE, ftell(aostream), archive_name)<0)
       error(M_DISK_FULL);
     }
     if(ftell(aostream)>volume_limit&&create_index)
     {
      if(msg_fprintf(idxstream, M_VOLUME_BUG, archive_name)<0)
       error(M_DISK_FULL);
     }
    }
    if(ferror(aostream)||fclose(aostream)==EOF)
     error(M_DISK_FULL);
    aostream=NULL;
    if(test_archive_crc&&protected)
    {
     protected=1;
     if(debug_enabled&&strchr(debug_opt, 'a')!=NULL)
      protected=2;
     msg_strcpy(tmp_tmp_filename, M_ARJFIXED_NAME);
     if(recover_file(tmp_archive_name, nullstr, tmp_tmp_filename, protected, eof_pos))
     {
      msg_cprintf(H_HL, M_CANT_FIND_DAMAGE, archive_name);
      printf(lf);
     }
     else
     {
      if(create_index)
      {
       if(msg_fprintf(idxstream, M_AUTOPROT_DAMAGE, archive_name)<0)
        error(M_DISK_FULL);
      }
     }
     tmp_tmp_filename[0]='\0';
    }
   }
   aostream=NULL;
   if(create_sfx&&!first_vol_passed)
   {
    entry=split_name(archive_name, NULL, NULL);
    if((ext_ptr=strchr(archive_name+entry, '.'))==NULL)
     msg_strcat(archive_name, M_EXE_EXT);
    #ifndef NULL_EXE_EXTENSION
     else
      msg_strcpy(ext_ptr, M_EXE_EXT);
    #endif
   }
   if(aistream!=NULL)
   {
    file_close(aistream);
    aistream=NULL;
    if(!no_file_activity)
    {
     if(keep_bak&&file_exists(archive_name))
     {
      bak_name=(char *)malloc_msg(far_strlen(M_BAK_EXT)+strlen(archive_name)+1);
      strcpy(bak_name, archive_name);
      entry=split_name(bak_name, NULL, NULL);
      if((ext_ptr=strchr(bak_name+entry, '.'))==NULL)
       msg_strcat(bak_name, M_BAK_EXT);
      else
       msg_strcpy(ext_ptr, M_BAK_EXT);
      file_unlink(bak_name);
      rename_with_check(archive_name, bak_name);
      free(bak_name);
     }
     else
     {
      if(create_sfx)
      {
       if(file_exists(archive_name))
        if(file_unlink(archive_name))
         error(M_CANT_DELETE, archive_name);
      }
      else
      {
       if(file_unlink(archive_name))
        error(M_CANT_DELETE, archive_name);
      }
     }
    }
   }
   if(!no_file_activity)
   {
    if(assign_work_directory)
    {
     msg_cprintf(H_HL|H_NFMT, M_COPYING_TEMP, tmp_archive_name, archive_name);
     tmp_archive_used=1;
     if(file_copy(archive_name, tmp_archive_name, test_archive_crc))
      error(M_CANT_COPY_TEMP, tmp_archive_name, archive_name);
     tmp_archive_used=0;
     if(file_unlink(tmp_archive_name))
      error(M_CANT_DELETE, archive_name);
    }
    else
     rename_with_check(tmp_archive_name, archive_name);
    if(create_sfx&&!first_vol_passed)
     msg_cprintf(0, M_SFX_CREATED);
   }
   tmp_archive_name[0]='\0';
  }
  else
  {
   fput_word(HEADER_ID, aostream);
   fput_word(0, aostream);
   last_hdr_offset=0L;
   if(!no_file_activity&&delete_processed&&add_command&&test_archive_crc)
   {
    for(cur_file=0; cur_file<flist_main.files; cur_file++)
     if(cfa_get(cur_file)==FLFLAG_PROCESSED)
      break;
    if(cur_file<flist_main.files)
    {
     archive_cleanup();
     cmd_verb=cmd;
    }
   }
   file_close(aistream);
   aistream=NULL;
   tmp_archive_cleanup();
   if(continued_nextvolume&&!volume_flag_set&&no_inarch)
    continued_nextvolume=0;
  }
 }
 if(create_index&&(cmd==ARJ_CMD_ADD||cmd==ARJ_CMD_UPDATE))
 {
  filename[0]='\0';
  vol_code=2;
  if(continued_nextvolume&&volume_flag_set)
  {
   vol_code=continued_prevvolume;
   far_strcpy((char FAR *)filename, tmp_filename);
  }
  if(msg_fprintf(idxstream, M_NEXT_VOLUME_STATS, volume_number, vol_code, resume_position, filename)<0)
   error(M_DISK_FULL);
 }
 if(cmd==ARJ_CMD_ADD||cmd==ARJ_CMD_FRESHEN||cmd==ARJ_CMD_UPDATE||cmd==ARJ_CMD_JOIN)
 {
  if(filter_fa_arch==FAA_BACKUP_CLEAR||filter_fa_arch==FAA_CLEAR)
   group_clear_arch(&flist_main);
  if(delete_processed)
   delete_processed_files(&flist_main);
 }
 total_processed+=total_files+comment_entries;
 av_compressed+=total_compressed;
 av_uncompressed+=total_uncompressed;
 av_total_files+=total_files;
 av_total_longnames+=total_longnames;
 if(quiet_mode==ARJ_QUIET2)
  new_stdout=stdout;
 /* Now produce statistics for each command individually */
 if(cmd==ARJ_CMD_LIST)
 {
  if(!std_list_cmd||verbose_display!=VERBOSE_ENH)
  {
   if(total_files==0||(std_list_cmd&&verbose_display==VERBOSE_STD))
   {
    if(total_longnames==0)
     msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
    else
     msg_cprintf(H_HL|H_NFMT, M_N_FILES_LFN, total_files, total_longnames);
    if(total_chapters!=0)
    {
     msg_cprintf(0, M_CHAPTERS_ON);
     msg_cprintf(0, (FMSG *)lf);
    }
   }
   else
   {
    msg_cprintf(0, M_BRIEF_LIST_SEPARATOR);
    if(total_chapters!=0)
    {
     msg_strcpy(strcpy_buf, M_CHAPTERS_ON);
     msg_ptr=strcpy_buf;
    }
    else
     msg_ptr=nullstr;
    ratio=calc_percentage(total_compressed, total_uncompressed);
    if(total_longnames==0)
     msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS, total_files, total_uncompressed, total_compressed, ratio/1000, ratio%1000, msg_ptr);
    else
     msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS_LFN, total_files, total_uncompressed, total_compressed, ratio/1000, ratio%1000, msg_ptr, total_longnames);
    if(av_total_files>total_files)
    {
     ratio=calc_percentage(av_compressed, av_uncompressed);
     if(total_longnames==0)
      msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS, av_total_files, av_uncompressed, av_compressed, ratio/1000, ratio%1000, nullstr);
     else
      msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS_LFN, av_total_files, av_uncompressed, av_compressed, ratio/1000, ratio%1000, nullstr, av_total_longnames);
    }
   }
  }
  if(chk_free_space)
  {
   free_space=file_getfree(target_dir);
   if(disk_space_used+minfree>free_space)
   {
    msg_cprintf(H_ALERT, M_NOT_ENOUGH_SPACE_X, disk_space_used+minfree-free_space);
    errors++;
   }
  }
 }
 else if(cmd==ARJ_CMD_PRINT)
 {
  if(!help_issued)
   msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
 }
 else if(cmd==ARJ_CMD_COMMENT)
  msg_cprintf(H_HL|H_NFMT, M_N_COMMENTS, comment_entries);
 else if(cmd==ARJ_CMD_ADD||cmd==ARJ_CMD_FRESHEN||cmd==ARJ_CMD_UPDATE)
 {
  if(total_files==0)
  {
   if(total_longnames==0)
    msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
   else
    msg_cprintf(H_HL|H_NFMT, M_N_FILES_LFN, total_files, total_longnames);
  }
  else
  {
   if(verbose_display==VERBOSE_STD)
   {
    msg_cprintf(0, M_FINAL_FOOTER);
    ratio=calc_percentage(total_compressed, total_uncompressed);
    msg_cprintf(H_HL|H_NFMT, M_VERBOSE_FOOTER, total_files, total_uncompressed, total_compressed, ratio/10, ratio%10);
    if(total_files<av_total_files)
    {
     ratio=calc_percentage(av_compressed, av_uncompressed);
     msg_cprintf(H_HL|H_NFMT, M_VERBOSE_FOOTER, av_total_files, av_uncompressed, av_compressed, ratio/10, ratio%10);
    }
   }
   else
   {
    if(total_longnames==0)
     msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
    else
     msg_cprintf(H_HL|H_NFMT, M_N_FILES_LFN, total_files, total_longnames);
   }
  }
  if(comment_entries!=0)
   msg_cprintf(H_HL|H_NFMT, M_N_COMMENTS, comment_entries);
 }
 else if(cmd==ARJ_CMD_TEST&&total_files!=0&&errors==0&&(protfile_option||arjprot_tail||security_state==ARJSEC_SIGNED))
 {
  eof_pos=ftell(aistream);
  fseek(aistream, 0L, SEEK_END);
  arjsec_offset=ftell(aistream);
  is_prot=(security_state==ARJSEC_SIGNED&&chk_prot_sig(aistream, eof_pos))?1:0;
  file_close(aistream);
  aistream=NULL;
  if(arjprot_tail||is_prot)
  {
   protected=1;
   if(debug_enabled&&strchr(debug_opt, 'a')!=NULL)
    protected=2;
   if(recover_file(archive_name, nullstr, nullstr, protected, eof_pos))
   {
    msg_cprintf(H_HL, M_CANT_FIND_DAMAGE, archive_name);
    printf(lf);
   }
   else
   {
    if(create_index)
    {
     if(msg_fprintf(idxstream, M_AUTOPROT_DAMAGE, archive_name)<0)
      error(M_DISK_FULL);
    }
   }
  }
  if(protfile_option&&protected)
  {
   arjprot_tail=protfile_option;
   if(prot_blocks==0)
    prot_blocks=protfile_option;
   if((aostream=file_open(archive_name, m_rbp))==NULL)
    error(M_CANTOPEN, archive_name);
   if(security_state==ARJSEC_NONE)
    final_header(FP_PROT);
   create_protfile(aostream, prot_blocks, 0);
   file_close(aostream);
   aostream=NULL;
  }
 }
 else
 {
  if(cmd==ARJ_CMD_COPY&&chapter_mode)
  {
   if(chapter_mode==CHAP_USE)
    msg_cprintf(0, M_CHAPTERS_ON);
   else if(chapter_mode==CHAP_REMOVE)
    msg_cprintf(0, M_CHAPTERS_OFF);
   msg_cprintf(0, strform, lf);
  }
  if(cmd==ARJ_CMD_COPY&&protfile_option&&!arjprot_tail)
   msg_cprintf(0, M_ARJPROT_DISABLED);
  msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
  if(comment_entries>0)
   msg_cprintf(H_HL|H_NFMT, M_N_COMMENTS, comment_entries);
 }
 if(security_state==ARJSEC_SIGNED&&arjsec_opt!=ARJSECP_SKIP)
 {
  msg_cprintf(H_HL|H_NFMT, M_VALID_ARJSEC, arjsec_signature);
  msg_strcpy(strcpy_buf, M_SDN_1);
  if(strstr(arjsec_signature, strcpy_buf)!=NULL)
  {
   msg_cprintf(0, M_SDN_ADD_DESC);
   msg_cprintf(0, M_SDN_SECURITY_TEST);
  }
  msg_strcpy(strcpy_buf, M_SDN_2);
  if(strstr(arjsec_signature, strcpy_buf)!=NULL)
  {
   msg_cprintf(0, M_SDN_DIST_DESC);
   msg_cprintf(0, M_SDN_SECURITY_TEST);
  }
 }
 file_close(aistream);
 aistream=NULL;
 if(arjprot_tail)
  msg_cprintf(0, M_ARJPROT_ENABLED, prot_blocks);
 if(arjsec_signature!=NULL)
 {
  free(arjsec_signature);
  arjsec_signature=NULL;
 }
 if(((modify_command&&timestamp_override==ATO_SAVE_ARCHIVE)||
    timestamp_override==ATO_NEWEST)&&ts_valid(ftime_max))
  file_setftime(archive_name, ts_native(&ftime_max, OS));
 else if((timestamp_override==ATO_SAVE_ORIGINAL||timestamp_override==ATO_SAVE_BOTH)&&saved_timestamp!=0L)
  file_setftime(archive_name, saved_timestamp);
 if(modify_command&&file_is_removable(archive_name))
  reset_drive(archive_name);
 if(!modify_command&&total_processed==0&&!continued_nextvolume)
 {
  if(errorlevel==ARJ_ERL_SUCCESS)
   errorlevel=ARJ_ERL_WARNING;
  errors++;
 }
 total_processed-=split_files;
 av_total_files-=split_files;
 av_total_longnames-=split_longnames;
}

#endif

/* Changes SFX executable name (for -ve) */

#if SFX_LEVEL>=ARJSFXV
static char *iterate_sfxname()
{
 char *rc, *p;
 int l;
 char *tmp_str;

 for(l=strlen(archive_name); l>0; l--)
 {
  if(archive_name[l]=='.')
   break;
 }
 if(l<4)
 {
  p=(l>0)?(archive_name+l):nullstr;
  l=0;
  rc=archive_name;
 }
 else
 {
  p=archive_name+l;
  l-=3;
  rc=archive_name+l;
 }
 if(volume_number>0)
 {
  tmp_str=malloc_str(archive_name);
  tmp_str[l]='\0';
  sprintf(archive_name, stub_fmt, tmp_str, volume_number, p);
  free(tmp_str);
 }
 return(rc);
}
#endif

/* Mangles the filename so it can be transformed to an aesthetic SFX name.
   ASR fix 26/08/2001 for UNIX. */

#if SFX_LEVEL>=ARJSFXV
static void fix_sfx_name()
{
 #ifdef NULL_EXE_EXTENSION
  char *digit_pos;
  static char exe_append[]=".exe";

  if(!first_vol_passed)
   return;
  digit_pos=strrchr(archive_name, PATHSEP_DEFAULT);
  if(digit_pos==NULL)
   digit_pos=archive_name;
  digit_pos=strchr(digit_pos, '.');
  if(digit_pos==NULL)                   /* "test" -> "test.exe" */
   strcat(archive_name, exe_append);
  else if(strlen(digit_pos)<3)          /* ".xx" -> ".01" */
   strcpy(digit_pos, exe_append);
 #endif
}
#endif

/* Extended archive processing routine. A non-zero return value indicates
   that processing of further volumes must be omitted. */

#if SFX_LEVEL>=ARJ
static int process_archive_proc(int cmd)
{
 struct timestamp tmp_time;
 static unsigned int t_buf, v_buf;
 char *tmp_ptr;
 int vol_num_digits;
 int encryption_version;
 char *vol_name_fmt;
 int filename_length;
 unsigned long avail_space;
 char timetext[22];
 char *sfx_name;
 int entry;
 int query_result;
 int no_input;
 FILE *cmtstream;
 int cmt_len;
 char *digit_pos;
 unsigned long arch_size;
 unsigned int desc_word, reg_id;        /* SFX */

 order_fcount=0;
 order_fcap=0;
 order_list=NULL;
 arjsec_signature=NULL;
 volume_flag_set=0;
 main_hdr_offset=last_hdr_offset=0L;
 tmp_archive_used=0;
 cf_num=0;
 total_files=total_longnames=0;
 comment_entries=0;
 security_state=ARJSEC_NONE;
 disk_space_used=0L;
 total_uncompressed=0L;
 total_compressed=0L;
 archive_size=0L;
 ts_store(&ftime_max, OS_SPECIAL, 0L);
 saved_timestamp=0L;
 ext_hdr_flags=0;
 encryption_applied=0;
 split_files=0;
 split_longnames=0;
 cmd_verb=cmd;
 if(!setjmp(main_proc))
 {
  set_file_apis(use_ansi_cp);
  v_buf=add_command?VBUF_ADD:VBUF_EXTRACT;
  t_buf=TBUF_ARJ;
  if(coreleft()<TBUF_MINFREE)
   t_buf>>=1;
  if(coreleft()<VBUF_MINFREE)
   v_buf>>=1;
  if((tmp_ptr=strchr(debug_opt, 'b'))!=NULL)
  {
   tmp_ptr++;
   v_buf=(int)strtol(tmp_ptr, &tmp_ptr, 10);
  }
  if((tmp_ptr=strchr(debug_opt, 'p'))!=NULL)
  {
   tmp_ptr++;
   t_buf=(int)strtol(tmp_ptr, &tmp_ptr, 10);
  }
  if((tmp_ptr=strchr(debug_opt, 'v'))!=NULL)
   msg_cprintf(H_HL|H_NFMT, M_BRIEF_MEMSTATS, coreleft(), t_buf, v_buf);
  if(chk_free_space)
   alloc_unit_size=get_bytes_per_cluster(target_dir);
  ts_store(&ftime_stamp, OS_SPECIAL, 0L);
  first_hdr_size=FIRST_HDR_SIZE;
  if(multivolume_option)
  {
   if(use_sfxstub)
    digit_pos=iterate_sfxname();
   else
   {
    vol_num_digits=2;
    tmp_ptr=volfmt_2digit;
    fix_sfx_name();
    filename_length=strlen(archive_name)-vol_num_digits;
    if(volume_number>99||isdigit(archive_name[filename_length-1]))
    {
     vol_num_digits=3;
     tmp_ptr=volfmt_3digit;
     filename_length--;
     if(volume_number>999&&lfn_supported)
     {
      if(volume_number>1000)
       filename_length--;
      tmp_ptr=volfmt_4digit;
     }
     else if(volume_number>999)
      volume_number=1;
    }
    if(volume_number>0)
    {
     vol_name_fmt=malloc_str(archive_name);
     vol_name_fmt[filename_length]='\0';
     sprintf(archive_name, tmp_ptr, vol_name_fmt, volume_number);
     free(vol_name_fmt);
    }
    digit_pos=archive_name+filename_length;
   }
   continued_nextvolume=1;
   if(modify_command)
   {
    do
    {
     avail_space=file_getfree(archive_name);
     arch_size=0L;
     if(assign_work_directory&&file_exists(archive_name))
     {
      arch_size=file_getfsize(archive_name);
      if(file_getfree(work_directory)<(avail_space+arch_size)*2)
       arch_size=0L;
      avail_space+=arch_size;
     }
     if(multivolume_option==MV_AVAIL)
      volume_limit=avail_space;
     if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
      msg_cprintf(H_HL|H_NFMT, M_AVAIL_SPACE, avail_space);
     if(avail_space<MIN_VOLUME_SIZE)
     {
      msg_cprintf(H_HL|H_NFMT, M_FILENAME_FORM, archive_name);
      if(!yes_on_all_queries&&!skip_space_query)
      {
       msg_cprintf(H_ALERT, M_NOT_ENOUGH_SPACE_V);
       return(0);
      }
      else
       error(M_NOT_ENOUGH_SPACE_V);
     }
     if(volume_limit>avail_space)
     {
      if(!yes_on_all_queries&&!skip_space_query)
      {
       msg_cprintf(H_HL|H_NFMT, M_FILENAME_FORM, archive_name);
       msg_sprintf(misc_buf, M_LOW_SPACE_WARNING, avail_space);
       if(!query_action(REPLY_YES, QUERY_LOW_SPACE, (FMSG *)misc_buf))
        return(0);
      }
     }
    } while((arch_size+avail_space)!=file_getfree(archive_name));
   }
  }
  ctrlc_not_busy=0;
  aistream=NULL;
  if(file_exists(archive_name))
  {
   if(modify_command)
   {
    saved_timestamp=file_getftime(archive_name);
    aistream=file_open_noarch(archive_name, m_rbp);
   }
   else
    aistream=file_open(archive_name, m_rb);
   fseek(aistream, arcv_ext_pos, SEEK_SET);
   arcv_ext_pos=0L;
  }
  ctrlc_not_busy=1;
  if(aistream==NULL&&msg_strchr(M_UPDATE_COMMANDS, (char)cmd)==NULL)
  {
   if(multivolume_option&&!yes_on_all_queries&&!skip_next_vol_query)
   {
    error_report();
    msg_cprintf(H_ERR, M_CANTOPEN, archive_name);
    nputlf();
    return(0);
   }
   else
    error(M_CANTOPEN, archive_name);
  }
  if(create_index)
  {
   cur_time_stamp(&tmp_time);
   timestamp_to_str(timetext, &tmp_time);
   if(msg_fprintf(idxstream, M_IDX_VOLUME_HEADER, timetext, resume_position, archive_name)<0)
    error(M_DISK_FULL);
  }
  no_inarch=1;
  if(aistream!=NULL)
  {
   #ifndef NO_CACHING
    setvbuf(aistream, NULL, _IOFBF, v_buf);
   #endif
   no_inarch=0;
  }
  if(!modify_command)
   msg_cprintf(H_HL|H_NFMT, M_PROCESSING_ARCHIVE, archive_name);
  else
  {
   if(!tmp_archive_name)
   {
    tmp_archive_used=-1;
    tmp_archive_name=(char *)malloc_msg(FILENAME_MAX);
    tmp_archive_name[0]='\0';
    tmp_archive_used=0;
   }
   if(create_sfx)
   {
    if(!first_vol_passed)
    {
     sfx_name=malloc_msg(filename_length=strlen(archive_name)+far_strlen(M_EXE_EXT)+1);
     strcpy(sfx_name, archive_name);
     entry=split_name(sfx_name, NULL, NULL);
     if((tmp_ptr=strchr(sfx_name+entry, '.'))==NULL)
      msg_strcat(sfx_name, M_EXE_EXT);
    #ifndef NULL_EXE_EXTENSION
     else
      msg_strcpy(tmp_ptr, M_EXE_EXT);
    #endif
     if(file_exists(sfx_name))
     {
      query_result=yes_on_all_queries||overwrite_existing;
      if(!query_result)
      {
       msg_cprintf(H_HL|H_NFMT, M_EXISTS, sfx_name);
       msg_sprintf(misc_buf, M_QUERY_UPDATE, sfx_name);
       query_result=query_action(REPLY_YES, QUERY_OVERWRITE, (FMSG *)misc_buf);
      }
      if(!query_result||(stricmp(archive_name, sfx_name)&&file_unlink(sfx_name)))
       error(M_CANT_DELETE, sfx_name);
     }
     msg_cprintf(H_HL|H_NFMT, M_CREATING_SFX, sfx_name);
     free(sfx_name);
    }
   }
   else
    msg_cprintf(H_HL|H_NFMT, (aistream==NULL)?M_CREATING_ARCHIVE:M_UPDATING_ARCHIVE, archive_name);
   if(!no_file_activity)
   {
    if(aistream==NULL)
    {
     aostream=file_open_noarch(archive_name, m_wb);
     file_close(aostream);
     aostream=NULL;
     file_unlink(archive_name);
    }
    tmp_archive_used=-1;
    if(assign_work_directory)
    {
     strcpy(tmp_archive_name, work_directory);
     add_pathsep(tmp_archive_name);
    }
    else
     split_name(archive_name, tmp_archive_name, NULL);
    strcat(tmp_archive_name, arjtemp_spec);
    find_tmp_filename(tmp_archive_name);
    aostream=file_open_noarch(tmp_archive_name, m_wbp);
    tmp_archive_used=0;
    #ifndef NO_CACHING
     setvbuf(aostream, NULL, _IOFBF, t_buf);
    #endif
    avail_space=file_getfree(tmp_archive_name);
    if(volume_limit>avail_space)
    {
     if(!yes_on_all_queries&&!skip_space_query)
     {
      msg_cprintf(H_HL|H_NFMT, M_FILENAME_FORM, tmp_archive_name);
      msg_sprintf(misc_buf, M_LOW_SPACE_WARNING, avail_space);
      if(!query_action(REPLY_YES, QUERY_LOW_SPACE, (FMSG *)misc_buf))
      {
       tmp_archive_cleanup();
       return(0);
      }
     }
    }
    if(create_sfx==SFXCRT_SFX&&multivolume_option)
    {
     if(!first_vol_passed)
      fetch_sfxv();
     else
      if(use_sfxstub)
       fetch_sfxstub();
    }
    else if(create_sfx==SFXCRT_SFX)
     fetch_sfx();
    else if(create_sfx==SFXCRT_SFXJR)
     fetch_sfxjr();
    /* Adjust the privileges on UNIX platforms */
    #if TARGET==UNIX
     if(create_sfx)
     {
      if(create_sfx==SFXCRT_SFX&&multivolume_option&&first_vol_passed&&!use_sfxstub)
       make_nonexecutable(aostream);
      else
       make_executable(aostream);
     }
     else
      make_nonexecutable(aostream);
    #endif
   }
  }
  no_input=0;
  if(aistream==NULL)
  {
   no_input=1;
   fill_archive_header();
   if(win32_platform&&use_ansi_cp)
    msg_cprintf(0, M_ANSI_CP_ARCHIVE);
  }
  else
  {
   if((main_hdr_offset=find_header(0, aistream))<0L)
   {
    msg_cprintf(H_ALERT, M_NOT_ARJ_ARCHIVE, archive_name);
    msg_cprintf(0, (FMSG *)lf);
    file_close(aistream);
    aistream=NULL;
    if(errorlevel==ARJ_ERL_SUCCESS)
     errorlevel=ARJ_ERL_NOT_ARJ_ARCHIVE;
    errors++;
    tmp_archive_cleanup();
    return(ARJ_ERL_NOT_ARJ_ARCHIVE);
   }
   if(main_hdr_offset==0L&&modify_command&&create_sfx)
    copy_bytes(main_hdr_offset);
   if(main_hdr_offset>EXESIZE_MINSFX)
   {
    fseek(aistream, main_hdr_offset, SEEK_SET);
    fseek(aistream, -8L, SEEK_CUR);
    desc_word=fget_word(aistream);
    reg_id=fget_word(aistream);
    sfx_desc_word=desc_word;
    /* Perform a simple integrity check */
    if(reg_id!=REG_ID&&reg_id!=UNREG_ID)
     sfx_desc_word=SFXDESC_NONSFX;
    if(sfx_desc_word<SFXDESC_MIN||sfx_desc_word>SFXDESC_MAX)
     sfx_desc_word=SFXDESC_NONSFX;
   }
   fseek(aistream, main_hdr_offset, SEEK_SET);
   if(!read_header(1, aistream, archive_name))
    error(M_INVALID_COMMENT_HDR);
   if(use_sfxstub)
    digit_pos=iterate_sfxname();
   if(modify_command&&continued_nextvolume&&!multivolume_option)
   {
    msg_cprintf(0, M_MV_UPDATE_REQ_SW);
    file_close(aistream);
    aistream=NULL;
    errors++;
    tmp_archive_cleanup();
    return(0);
   }
   if(modify_command&&(cmd==ARJ_CMD_GARBLE||garble_enabled))
   {
    if(arj_nbr>=ARJ_NEWCRYPT_VERSION&&ext_hdr_flags==0&&!encryption_applied)
    {
     ext_hdr_flags=ENCRYPT_STD;
     if(gost_cipher==GOST256)
      ext_hdr_flags=ENCRYPT_UNK;
     else if(gost_cipher==GOST40)
      ext_hdr_flags=ENCRYPT_GOST40;
    }
    else
    {
     if((gost_cipher!=GOST256||(ext_hdr_flags!=ENCRYPT_GOST256&&ext_hdr_flags!=ENCRYPT_GOST256L))&&
        (gost_cipher!=GOST40||ext_hdr_flags!=ENCRYPT_GOST40)&&
        gost_cipher!=GOST_NONE)
      error(M_WRONG_ENC_VERSION, 0);
    }
   }
   if(!win32_platform&&create_sfx&&!multivolume_option&&ext_hdr_flags>=ENCRYPT_STD)
    error(M_BAD_SYNTAX);
   if(cmd!=ARJ_CMD_COPY&&chapter_mode&&total_chapters==0)
    error(M_NOT_A_CHAPTER_ARCH);
   if(cmd==ARJ_CMD_DELETE&&delete_processed==DP_EXTRACT&&total_chapters!=0)
    error(M_BAD_SYNTAX);
   if(cmd==ARJ_CMD_DELETE&&current_chapter==RESERVED_CHAPTER&&total_chapters==0)
    error(M_NOT_A_CHAPTER_ARCH);
   if(arjsec_opt==ARJSECP_SET_ERROR&&arj_flags&SECURED_FLAG)
    error(M_SKIPPING_SEC);
   if(protfile_option&&(multivolume_option||continued_nextvolume)&&
      !arjprot_tail&&is_removable)
    error(M_ARJPROT_REJECTED);
   timestamp_to_str(timetext, &ftime_stamp);
   msg_cprintf(H_HL|H_NFMT, M_ARCHIVE_CREATED, timetext);
   if(arj_nbr>=ARJ_M_VERSION)
   {
    ts_store(&tmp_time, host_os, compsize);
    timestamp_to_str(timetext, &tmp_time);
    msg_cprintf(H_HL|H_NFMT, M_MODIFIED, timetext);
    if(total_chapters!=0)
     msg_cprintf(H_HL, M_CHAPTER_NUMBER, total_chapters);
   }
   msg_cprintf(0, (FMSG *)lf);
   if((!modify_command||!use_comment)&&(cmd!=ARJ_CMD_COMMENT||supply_comment_file))
   {
    if((cmd!=ARJ_CMD_LIST||!std_list_cmd||verbose_display!=VERBOSE_ENH)&&comment_display!=CMTD_NONE)
     display_comment(comment);
   }
   set_file_apis(ansi_codepage);
   if(ansi_codepage)
   {
    msg_cprintf(0, M_ANSI_CP_ARCHIVE);
#if TARGET!=WIN32
    if(cmd==ARJ_CMD_EXTR_NP&&!use_ansi_cp)
     error(M_REQUIRES_ARJ32);
#endif
   }
   if(cmd==ARJ_CMD_LIST&&debug_enabled&&strchr(debug_opt, 'l')!=NULL)
    msg_cprintf(H_HL|H_NFMT, M_ENCRYPT_VALUE, ext_hdr_flags);
  }
  if(multivolume_option)
   volume_number=strtol(digit_pos, &digit_pos, 10)+1;
  if(modify_command)
  {
   main_hdr_offset=ftell(aostream);
   if(security_state)
   {
    msg_cprintf(0, M_CANT_UPDATE_SEC);
    msg_cprintf(0, (FMSG *)lf);
    file_close(aistream);
    aistream=NULL;
    errors++;
    errorlevel=ARJ_ERL_ARJSEC_ERROR;
    tmp_archive_cleanup();
    return(0);
   }
   if(timestamp_override!=ATO_SAVE_BOTH)
   {
    cur_time_stamp(&tmp_time);
    compsize=ts_native(&tmp_time, host_os);
   }
   if(ts_valid(secondary_ftime))
    compsize=ts_native(&secondary_ftime, host_os); /* Archive modification time */
   if(garble_enabled)
   {
    encryption_version=garble_init(0);
    if(ext_hdr_flags==ENCRYPT_UNK)
     ext_hdr_flags=encryption_version;
    if(ext_hdr_flags!=0&&encryption_version!=ext_hdr_flags)
     error(M_WRONG_ENC_VERSION, ext_hdr_flags);
   }
   ext_flags=ext_hdr_flags;
   if(protfile_option)
   {
    arjprot_tail=protfile_option;
    if(prot_blocks==0)
     prot_blocks=arjprot_tail%256;      /* v 2.75+ - %'ing is pointless! */
   }
   if(sfx_desc_word!=SFXDESC_NONSFX)
   {
    if(chapter_mode)
     error(M_CHAPTER_SFX_CREATION);
    if(custom_method==5||method_specifier==4)
     error(M_INVALID_METHOD_SFX);
    if(sfx_desc_word<=SFXDESC_SFX&&multivolume_option)
     error(M_BAD_SYNTAX);
    /* Skip check for EAs - an existing archive may contain them but
       they are harmless! */
    if(sfx_desc_word==SFXDESC_SFXJR&&(type_override||lfn_supported!=LFN_NOT_SUPPORTED))
     error(M_TEXTMODE_LFN_SFXJR);
    if(sfx_desc_word==SFXDESC_SFXJR&&garble_enabled)
     error(M_NO_GARBLE_IN_SFXJR);
    if(sfx_desc_word==SFXDESC_SFX&&ext_hdr_flags>ENCRYPT_STD)
     error(M_WRONG_ENC_VERSION, ext_hdr_flags);
   }
   if(cmd==ARJ_CMD_COPY)
   {
    if(chapter_mode==CHAP_USE&&total_chapters!=0&&!multivolume_option)
     error(M_ALREADY_CHAPTER_ARCH);
    if(chapter_mode==CHAP_REMOVE&&total_chapters==0)
     error(M_NOT_A_CHAPTER_ARCH);
    if(chapter_mode==CHAP_USE&&total_chapters==0)
    {
     chapter_number=1;
     total_chapters=1;
     current_chapter=HIGHEST_CHAPTER;
     comment_entries++;
    }
    else if(chapter_mode==CHAP_REMOVE&&total_chapters!=0)
    {
     chapter_number=0;
     total_chapters=0;
     current_chapter=HIGHEST_CHAPTER;
     comment_entries++;
    }
    if(garble_enabled)
    {
     ext_flags=0;
     arj_flags&=~GARBLED_FLAG;
     if(!test_archive_crc)
      test_archive_crc=TC_ARCHIVE;
    }
    if(use_ansi_cp==ANSICP_SKIP)
    {
     if(arj_nbr==ARJ_ANSI_VERSION||arj_flags&ANSICP_FLAG)
     {
      msg_cprintf(H_ALERT, M_NOT_OEM_CP_ARCHIVE);
      file_close(aistream);
      aistream=NULL;
      errors++;
      errorlevel=ARJ_ERL_WARNING;
      tmp_archive_cleanup();
      return(0);
     }
     arj_flags|=ANSICP_FLAG;
     comment_entries++;
    }
    if(protfile_option)
    {
     arjprot_tail=0;
     prot_blocks=0;
     arj_flags&=~PROT_FLAG;
     comment_entries++;
    }
   }
   if(add_command&&multivolume_option)
    arj_flags|=VOLUME_FLAG;
   if(arj_flags&DUAL_NAME_FLAG)
    dual_name=1;
   if(add_command&&!dual_name&&(lfn_mode==LFN_DUAL||lfn_mode==LFN_DUAL_EXT))
    error(M_CANT_CNV_TO_DUAL_N);
   if(arj_flags&ANSICP_FLAG)
    ansi_codepage=1;
   if(add_command&&!ansi_codepage&&use_ansi_cp==ANSICP_CONVERT)
    error(M_ARCHIVE_CP_MISMATCH);
   if(!win32_platform&&ansi_codepage)
    error(M_ARCHIVE_CP_MISMATCH);
   create_header(1);
   if((cmd==ARJ_CMD_COMMENT&&!supply_comment_file)||use_comment)
   {
    if(supply_comment(archive_cmt_name, archive_name))
     comment_entries++;
   }
   write_header();
   first_file_offset=ftell(aostream);
  }
  else
  {
   first_file_offset=ftell(aistream);
   if(security_state&&arjsec_opt!=ARJSECP_SKIP)
   {
    if(method>ARJSEC_VERSION)
    {
     msg_cprintf(H_HL|H_NFMT, M_CANT_HANDLE_ARJSEC_V, method);
     msg_cprintf(0, (FMSG *)misc_buf);
    }
    else
    {
     msg_cprintf(0, M_VERIFYING_ARJSEC);
     if(arjsec_signature==NULL)
      arjsec_signature=(char *)malloc_msg(ARJSEC_SIG_MAXLEN+1);
     if(get_arjsec_signature(aistream, arjsec_offset, arjsec_signature, ARJSEC_ITER))
     {
      arj_delay(5);
      msg_cprintf(0, M_DAMAGED_SEC_ARCHIVE);
      fclose(aistream);
      aistream=NULL;
      errors++;
      return(0);
     }
     msg_cprintf(0, M_VALID_ENVELOPE);
     fseek(aistream, first_file_offset, SEEK_SET);
     security_state=ARJSEC_SIGNED;
    }
   }
   if(garble_enabled)
   {
    encryption_version=garble_init(0);
    if((encryption_version!=ENCRYPT_GOST256&&encryption_version!=ENCRYPT_GOST256L)||
       (ext_hdr_flags!=ENCRYPT_GOST256&&ext_hdr_flags!=ENCRYPT_GOST256L))
    {
     if(ext_hdr_flags!=0&&encryption_version!=ext_hdr_flags)
      error(M_WRONG_ENC_VERSION, encryption_version);
    }
   }
   if(test_archive_crc==TC_ARCHIVE)
   {
    cmd_verb=ARJ_CMD_TEST;
    while(read_header(0, aistream, archive_name))
     unpack_validation(ARJ_CMD_TEST);
    cmd_verb=cmd;
    if(errors!=0)
     error(M_FOUND_N_ERRORS, errors);
    fseek(aistream, first_file_offset, SEEK_SET);
   }
   if(cmd==ARJ_CMD_EXTR_NP&&use_comment&&archive_cmt_name[0]!='\0')
   {
    msg_cprintf(H_HL|H_NFMT, M_EXTRACTING_CMT_TO_F, archive_cmt_name);
    cmtstream=file_create(archive_cmt_name, m_w);
    if(hdr_comment[0]=='\0')
    {
     msg_strcpy(strcpy_buf, M_EMPTY_COMMENT);
     if(fputs(strcpy_buf, cmtstream)==EOF)
      error(M_DISK_FULL);
    }
    else
    {
     cmt_len=strlen(hdr_comment);
     if(fwrite(hdr_comment, 1, cmt_len, cmtstream)!=cmt_len)
      error(M_DISK_FULL);
    }
    comment_entries++;
    fclose(cmtstream);
   }
  }
  if((tmp_ptr=strchr(debug_opt, 'v'))!=NULL)
   msg_cprintf(H_HL|H_NFMT, M_BRIEF_MEMSTATS, coreleft(), t_buf, v_buf);
  /* The main part of the whole routine */
  process_archive(cmd, no_input);
  finish_processing(cmd);
 }
 if(order_list!=NULL)
 {
  farfree(order_list);
  order_list=NULL;
 }
 file_close(aistream);
 aistream=NULL;
 return(0);
}

#elif SFX_LEVEL<=ARJSFXV                /* Simplified routine for ARJSFXV */

#if SFX_LEVEL>=ARJSFXV
static
#endif
void process_archive()
{
 char timetext[22];
 int query_result;
 FILE_COUNT pf_num;
 unsigned int ratio;
 int lt;
 #if SFX_LEVEL>=ARJSFXV
  struct timestamp tmp_time;
  static unsigned int t_buf, v_buf;
  char *tmp_ptr, *msg_ptr;
  char *digit_pos;
  int vol_num_digits;
  char *vol_name_fmt;
  int filename_length;
  char FAR *cmt_ptr;
  int no_in_arch;
  int enc_version;
  unsigned long free_space;
  unsigned int cf_num;
 #else
  char *cmt_ptr;
  int i;
  char tmp_name[FILENAME_MAX];
 #endif

 #if SFX_LEVEL>=ARJSFXV
  cf_num=0;
  volume_flag_set=0;
  main_hdr_offset=last_hdr_offset=0L;
  total_files=0;
  comment_entries=0;
  security_state=ARJSEC_NONE;
  dual_name=0;
  ansi_codepage=0;
  disk_space_used=0L;
  total_uncompressed=0L;
  total_compressed=0L;
  archive_size=0L;
  ts_store(&ftime_max, OS, 0L);
  ts_store(&ftime_stamp, OS_SPECIAL, 0L);
  valid_ext_hdr=0;
  if(eh!=NULL)
   eh_release(eh);
  eh=NULL;
  first_hdr_size=STD_HDR_SIZE;
  for(total_os=0; host_os_names[total_os]!=NULL; total_os++);
  v_buf=VBUF_SFX;
  if((tmp_ptr=strchr(debug_opt, 'b'))!=NULL)
  {
   tmp_ptr++;
   v_buf=(int)strtol(tmp_ptr, &tmp_ptr, 10);
  }
  t_buf=TBUF_ARJ;
  if((tmp_ptr=strchr(debug_opt, 'p'))!=NULL)
  {
   tmp_ptr++;
   t_buf=(int)strtol(tmp_ptr, &tmp_ptr, 10);
  }
  if(multivolume_option)
  {
   if(use_sfxstub)
    digit_pos=iterate_sfxname();
   else
   {
    vol_num_digits=2;
    tmp_ptr=volfmt_2digit;
    if(volume_number>99)
    {
     vol_num_digits++;
     tmp_ptr=volfmt_3digit;
    }
    if(volume_number>1000)              /* ASR fix 20/10/2000 */
    {
     vol_num_digits++;
     tmp_ptr=volfmt_4digit;
    }
    fix_sfx_name();
    filename_length=strlen(archive_name)-vol_num_digits;
    if(volume_number>0)
    {
     vol_name_fmt=malloc_str(archive_name);
     vol_name_fmt[filename_length]='\0';
     sprintf(archive_name, tmp_ptr, vol_name_fmt, volume_number);
     free(vol_name_fmt);
    }
    digit_pos=archive_name+filename_length;
   }
   continued_nextvolume=1;
  }
  ctrlc_not_busy=0;
  aistream=file_open(archive_name, m_rb);
  ctrlc_not_busy=1;
  if(aistream==NULL)
  {
   if(multivolume_option&&!yes_on_all_queries&&!skip_next_vol_query)
   {
    show_sfx_logo();
    msg_cprintf(H_ERR, M_CANTOPEN, archive_name);
    msg_cprintf(0, (FMSG *)lf);
    return;
   }
   else
    error(M_CANTOPEN, archive_name);
  }
 #endif
 /* ARJSFX initialization... quite short */
 #if SFX_LEVEL<=ARJSFX
  /* Set up ARJ$DISP screen if needed */
  if(arjdisp_enabled)
  {
   cmd_verb=ARJDISP_CMD_START;
   filename[0]='+';
   filename[1]='\0';
   uncompsize=compsize=0L;
   display_indicator(0L);
  }
  if((aistream=file_open(archive_name, m_rb))==NULL)
   error(M_CANTOPEN, archive_name);
 #endif
 /* Initialize caching */
 #ifndef NO_CACHING
  #if SFX_LEVEL>=ARJSFXV
   if(aistream!=NULL)
    setvbuf(aistream, NULL, _IOFBF, v_buf);
  #else
   setvbuf(aistream, cache_buf, _IOFBF, VBUF_SFX);
  #endif
 #endif
 /* Skip EXE header */
 #if SFX_LEVEL>=ARJSFXV
  if(!first_vol_passed)
   sfx_seek();
  else
   main_hdr_offset=find_header(0, aistream);
 #else
  sfx_seek();
 #endif
 /* Header verification */
 #if SFX_LEVEL>=ARJSFXV
  if(main_hdr_offset<0L)
  {
   msg_cprintf(H_ALERT, M_NOT_ARJ_ARCHIVE, archive_name);
   msg_cprintf(0, (FMSG *)lf);
   file_close(aistream);
   aistream=NULL;
   if(errorlevel==ARJ_ERL_SUCCESS)
    errorlevel=ARJ_ERL_NOT_ARJ_ARCHIVE;
   errors++;
   return;
  }
  fseek(aistream, main_hdr_offset, SEEK_SET);
 #endif
 /* Read the main archive header */
 #if SFX_LEVEL>=ARJSFXV
  if(!read_header(1, aistream, archive_name))
   error(M_INVALID_COMMENT_HDR);
 #else
  if(!read_header(1))
   error(M_BAD_HEADER);
 #endif
 /* ARJSFXV: increment SFXNAME */
 #if SFX_LEVEL>=ARJSFXV
  if(use_sfxstub)
   digit_pos=iterate_sfxname();
  if(multivolume_option)
   volume_number=strtol(digit_pos, &digit_pos, 10)+1;
 #endif
 /* Analyze preset options */
 cmt_ptr=comment;
 #if SFX_LEVEL>=ARJSFXV
  if(!first_vol_passed)
  {
   if(!skip_preset_options)
    cmt_ptr=preprocess_comment(cmt_ptr);
   sfx_setup();
   show_sfx_logo();
   msg_cprintf(H_HL|H_NFMT, M_PROCESSING_ARCHIVE, archive_name);
   timestamp_to_str(timetext, &ftime_stamp);
   msg_cprintf(H_HL|H_NFMT, M_ARCHIVE_CREATED, timetext);
   if(arj_nbr>=ARJ_M_VERSION)
   {
    ts_store(&tmp_time, host_os, compsize);
    timestamp_to_str(timetext, &tmp_time);
    msg_cprintf(H_HL|H_NFMT, M_MODIFIED, timetext);
   }
   msg_cprintf(0, (FMSG *)lf);
   if(ansi_codepage)
    msg_cprintf(0, M_ANSI_CP_ARCHIVE);
   if(chk_free_space)
    alloc_unit_size=get_bytes_per_cluster(target_dir);
   if(process_lfn_archive==1)
    lfn_supported=LFN_NOT_SUPPORTED;
   display_comment(cmt_ptr);
   if(!first_vol_passed&&cmd_verb==ARJ_CMD_EXTRACT&&!yes_on_all_queries&&!skip_extract_query)
    if(!query_action(REPLY_YES, QUERY_CRITICAL, M_CONTINUE_EXTRACTION))
     exit(ARJ_ERL_WARNING);
  }
 #endif
 /* */ /* Nag screen removed */ /* */
 #if SFX_LEVEL>=ARJSFXV
  if(!first_vol_passed)
  {
   if((garble_enabled&&!strcmp(garble_password, "?"))||
      (file_garbled&&!garble_enabled&&(cmd_verb==ARJ_CMD_EXTRACT||cmd_verb==ARJ_CMD_TEST)))
   {
    garble_enabled=1;
    tmp_ptr=(char *)malloc_msg(INPUT_LENGTH+1);
    msg_cprintf(0, M_ENTER_PWD);
    read_line_noecho(tmp_ptr, INPUT_LENGTH);
    garble_password=malloc_str(tmp_ptr);
    free(tmp_ptr);
   }
   if(chk_free_space)
    alloc_unit_size=get_bytes_per_cluster(target_dir);
   if(process_lfn_archive==1)
    lfn_supported=LFN_NOT_SUPPORTED;
   #if SFX_LEVEL>=ARJ
    if(garble_enabled)
    {
     enc_version=garble_init(0);
     if(ext_hdr_flags!=0&&enc_version!=ext_hdr_flags)
      error(M_WRONG_ENC_VERSION, ext_hdr_flags);
    }
   #endif
  }
 #else
  if(!skip_preset_options)
   cmt_ptr=preprocess_comment(cmt_ptr);
  if(quiet_mode&&!yes_on_all_queries)
   quiet_mode=0;
  if(quiet_mode)
   freopen(dev_null, m_w, stdout);
  if(!process_lfn_archive)
   lfn_supported=LFN_NOT_SUPPORTED;
  msg_cprintf(H_HL|H_NFMT, M_ARJSFX_BANNER, exe_name);
  msg_cprintf(H_HL|H_NFMT, M_PROCESSING_ARCHIVE, archive_name);
  logo_shown=1;
  timestamp_to_str(timetext, &ftime_stamp);
  msg_cprintf(H_HL|H_NFMT, M_ARCHIVE_CREATED, timetext);
  if(show_ansi_comments)
   printf(cmt_ptr);
  else
   display_comment(cmt_ptr);
  /* The sfx_setup() occurs here */
  if(list_sfx_cmd)
   cmd_verb=ARJ_CMD_LIST;
  else if(verbose_list)
  {
   cmd_verb=ARJ_CMD_LIST;
   std_list_cmd=1;
  }
  else if(test_sfx_cmd)
   cmd_verb=ARJ_CMD_TEST;
  else
  {
   cmd_verb=ARJ_CMD_EXTR_NP;
   test_mode=1;
  }
  if(garble_enabled&&garble_password[0]=='\0')
   error(M_NO_PWD_OPTION);
  if(file_args==0)
   f_arg_array[file_args++]=all_wildcard;
  case_path(target_dir);
  for(i=0; i<file_args; i++)
  {
   strcpy(tmp_name, f_arg_array[i]);
   case_path(tmp_name);
   add_f_arg(tmp_name);
  }
  if(cmd_verb==ARJ_CMD_EXTR_NP&&!yes_on_all_queries&&!skip_extract_query)
  {
   msg_cprintf(0, M_CONTINUE_EXTRACTION);
   if(!query_action())
    exit(ARJSFX_ERL_ERROR);
  }
 #endif
 #if SFX_LEVEL>=ARJSFXV
 if(!first_vol_passed&&prompt_for_directory)
 #else
 if(prompt_for_directory)
 #endif
 {
  query_result=0;
  if(target_dir[0]!='\0')
  {
   #if SFX_LEVEL>=ARJSFXV
    msg_sprintf(misc_buf, M_QUERY_DEST_DIR, target_dir);
    query_result=query_action(REPLY_YES, QUERY_CRITICAL, (FMSG *)misc_buf);
   #else
    msg_cprintf(H_HL|H_NFMT, M_QUERY_DEST_DIR, target_dir);
    query_result=query_action();
   #endif
  }
  if(!query_result)
  {
   msg_cprintf(0, M_ENTER_INSTALL_DIR);
   read_line(target_dir, FILENAME_MAX-2);
   alltrim(target_dir);
   if(target_dir[0]!='\0')
   {
    if(target_dir[lt=strlen(target_dir)-1]!=PATHSEP_DEFAULT)
    {
     target_dir[lt+1]=PATHSEP_DEFAULT;
     target_dir[lt+2]='\0';
    }
    case_path(target_dir);
   }
  }
 }
 if(security_state&&!skip_integrity_test)
 {
  if(get_arjsec_signature(aistream, arjsec_offset, arjsec_signature, ARJSEC_ITER))
  {
   arj_delay(5);
   error(M_DAMAGED_SEC_ARCHIVE);
  }
  licensed_sfx=1;
 }
 if(test_sfx_cmd&&cmd_verb==ARJ_CMD_EXTRACT)
 {
  last_hdr_offset=ftell(aistream);
 #if SFX_LEVEL>=ARJSFXV
  while(read_header(0, aistream, archive_name))
 #else
  while(read_header(0))
 #endif
   unpack_validation();
  if(errors!=0)
   error(M_FOUND_N_ERRORS, errors);
  fseek(aistream, last_hdr_offset, SEEK_SET);
 }
 #if SFX_LEVEL>=ARJSFXV
  ts_store(&ftime_stamp, OS, 0L);
  if(first_volume_number!=0)
  {
   volume_number=first_volume_number;
   first_volume_number=0;
   first_vol_passed=1;
   no_in_arch=1;
  }
  else
   no_in_arch=0;
 #endif
#if SFX_LEVEL>=ARJSFXV
 while(!no_in_arch&&read_header(0, aistream, archive_name))
#else
 while(read_header(0))
#endif
 {
  pf_num=flist_lookup();
  #if SFX_LEVEL>=ARJSFXV
   cf_num++;
  #endif
  switch(cmd_verb)
  {
   case ARJ_CMD_EXTR_NP:
   case ARJ_CMD_EXTRACT:
    if(pf_num!=0)
    {
     if(unpack_file_proc())
      total_files++;
     tmp_tmp_filename[0]='\0';
    }
    else
     skip_compdata();
    break;
   case ARJ_CMD_LIST:
    if(pf_num!=0)
    {
     #if SFX_LEVEL>=ARJSFXV
      if(list_cmd(total_files, cf_num))
       total_files++;
     #else
      list_cmd();
      total_files++;
     #endif
    }
    skip_compdata();
    break;
   case ARJ_CMD_TEST:
    if(pf_num!=0)
    {
     if(unpack_validation())
      total_files++;
      #if SFX_LEVEL>ARJSFXV /* Avoid to skip data twice! Is this "minimal" fix safe????? */
     else
      skip_compdata();
      #endif
    }
    else
     skip_compdata();
    break;
  }
 }
 #if SFX_LEVEL>=ARJSFXV
  total_processed+=total_files+comment_entries;
  av_compressed+=total_compressed;
  av_uncompressed+=total_uncompressed;
  av_total_files+=total_files;
 #endif
 #if SFX_LEVEL>=ARJSFXV
 if(cmd_verb==ARJ_CMD_LIST)
 #else
 if(cmd_verb==ARJ_CMD_LIST&&total_files>0)
 #endif
 {
  msg_cprintf(0, M_BRIEF_LIST_SEPARATOR);
  #if SFX_LEVEL>=ARJSFXV
   msg_ptr=nullstr;
  #endif
  ratio=calc_percentage(total_compressed, total_uncompressed);
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS, total_files, total_uncompressed, total_compressed, ratio/1000, ratio%1000, msg_ptr, nullstr);
   if(av_total_files>total_files)
    msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS, av_total_files, av_uncompressed, av_compressed, ratio/1000, ratio%1000, nullstr, nullstr);
  #else
   msg_cprintf(H_HL|H_NFMT, M_TOTAL_STATS, total_files, total_uncompressed, total_compressed, ratio/1000, ratio%1000);
  #endif
  #if SFX_LEVEL>=ARJSFXV
   if(chk_free_space)
   {
    free_space=file_getfree(target_dir);
    if(disk_space_used+minfree>free_space)
    {
     msg_cprintf(H_ALERT, M_NOT_ENOUGH_SPACE_X, disk_space_used+minfree-free_space);
     errors++;
    }
   }
  #endif
 }
 else
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
   if(comment_entries!=0)
    msg_cprintf(H_HL|H_NFMT, M_N_COMMENTS, comment_entries);
  #else
   msg_cprintf(H_HL|H_NFMT, M_N_FILES, total_files);
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  file_close(aistream);
 #else
  fclose(aistream);
 #endif
 #if SFX_LEVEL>=ARJSFXV
  aistream=NULL;
  if(total_processed==0&&!continued_nextvolume)
  {
   if(errorlevel==ARJ_ERL_SUCCESS)
    errorlevel=ARJ_ERL_WARNING;
   errors++;
  }
 #endif
 if(valid_envelope)
  msg_cprintf(H_HL|H_NFMT, M_VALID_ARJSEC, arjsec_signature);
 #if SFX_LEVEL<=ARJSFX
  /* ARJDISP cleanup */
  if(arjdisp_enabled)
  {
   cmd_verb=ARJDISP_CMD_END;
   display_indicator(0L);
  }
 #endif
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Performs all archive processing actions including setup and so on... */

#if SFX_LEVEL>=ARJ
void perform_cmd(int cmd)
#else
void perform_cmd()
#endif
{
 char *tmp_ptr;
 char *syscmd;
 int vol_num;
 unsigned long arch_time;
 char reply;
 #if SFX_LEVEL>=ARJ
  int tries;
  int proc_rc;
 #endif

 #if SFX_LEVEL>=ARJ
  /* Set up ARJ$DISP screen if needed */
  if(arjdisp_enabled)
  {
   cmd_verb=ARJDISP_CMD_START;
   filename[0]='+';
   filename[1]='\0';
   uncompsize=compsize=0L;
   display_indicator(0L);
  }
 #endif
 ofstream=NULL;
 volume_flag_set=0;
 first_vol_passed=0;
 continued_nextvolume=0;
 total_processed=0;
 volume_number=0;
 resume_position=0L;
 is_removable=0;
 #if SFX_LEVEL>=ARJ
  if(eh!=NULL)
  {
   eh_release(eh);
   eh=NULL;
  }
  comment=NULL;
  tmp_filename=NULL;
  encstream=NULL;
  vol_file_num=0;
  split_files=0;
  dual_name=0;
  ansi_codepage=0;
  arjprot_tail=0;
  ext_hdr_flags=0;
  sfx_desc_word=0;
  total_chapters=0;
  recent_chapter=0;
  max_chapter=0;
  prot_blocks=0;
 #endif
 #if SFX_LEVEL>=ARJ
  modify_command=msg_strchr(M_MODIFY_COMMANDS, (char)cmd)!=NULL;
  add_command=msg_strchr(M_ADD_COMMANDS, (char)cmd)!=NULL;
  order_command=cmd==ARJ_CMD_ORDER;
  get_totals();
  if((tmp_ptr=strchr(debug_opt, 'o'))!=NULL)
   convert_strtime(&secondary_ftime, ++tmp_ptr);
  else
   ts_store(&secondary_ftime, OS_SPECIAL, 0L);
  if(resume_volume_num!=0)
  {
   volume_number=resume_volume_num;
   resume_volume_num=0;
   first_vol_passed=1;
  }
  if(start_at_ext_pos)
  {
   resume_position=ext_pos;
   continued_prevvolume=1;
   mvfile_type=-1;
  }
  t_volume_offset=mv_reserve_space;
 #endif
 comment=farmalloc_msg(COMMENT_MAX);
 comment[0]='\0';
 tmp_filename=farmalloc_msg(FILENAME_MAX);
 tmp_filename[0]='\0';
 is_removable=file_is_removable(archive_name);
 #if SFX_LEVEL>=ARJ
  if(mv_cmd_state!=MVC_NONE)
  {
   if(mv_cmd[0]!='\0')
   {
    if(mv_cmd_state==MVC_DELETION)
     delete_files(mv_cmd);
    else if(mv_cmd_state==MVC_RUN_CMD)
    {
     msg_cprintf(H_PROMPT, M_COMMAND);
     msg_cprintf(H_HL|H_NFMT, M_FILENAME_FORM, mv_cmd);
    #if TARGET==UNIX
     nputlf();
    #endif
     exec_cmd(mv_cmd);
    }
   }
   else
   {
    syscmd=(char *)malloc_msg(CMDLINE_LENGTH+1);
    while(1)
    {
     msg_cprintf(0, M_ENTER_CMD_EXIT);
     msg_cprintf(H_PROMPT, M_COMMAND);
     read_line(syscmd, CMDLINE_LENGTH);
     alltrim(syscmd);
     msg_strcpy(strcpy_buf, M_EXIT_CMD);
     if(!stricmp(strcpy_buf, syscmd))
      break;
     if(syscmd[0]!='\0')
      exec_cmd(syscmd);
    }
    free(syscmd);
   }
  }
 #endif
 /* The archive processing itself occurs now */
 #if SFX_LEVEL>=ARJ
  proc_rc=process_archive_proc(cmd);
 #else
  process_archive();
 #endif
#if SFX_LEVEL>=ARJ
 if(multivolume_option&&!proc_rc)
#else
 if(multivolume_option)
#endif
 {
  is_removable=file_is_removable(archive_name);
  #if SFX_LEVEL>=ARJ
   t_volume_offset=0L;
   tries=0;
  #endif
  first_vol_passed=1;
  #if SFX_LEVEL>=ARJ
   vol_num=volume_number;
  #endif
  while(continued_nextvolume)
  {
   #if SFX_LEVEL>=ARJ
    arch_time=file_getftime(archive_name);
    do
    {
     if(vol_num!=volume_number)
     {
      tries=0;
      vol_num=volume_number;
     }
     if(++tries>MAX_VOLUME_TRIES)
     {
      if(errorlevel==ARJ_ERL_SUCCESS)
       errorlevel=ARJ_ERL_FATAL_ERROR;
      errors++;
      goto all_volumes_done;
     }
     if(beep_between_volumes)
      msg_cprintf(0, (FMSG *)bell);
     if((!is_removable||skip_next_vol_query)&&(yes_on_all_queries||skip_next_vol_query))
      break;
     reply=M_YES[0];
     if(is_removable)
      msg_sprintf(misc_buf, M_INSERT_DISKETTE, volume_number, reply);
     else
      msg_sprintf(misc_buf, M_QUERY_NEXT_VOLUME, volume_number);
     if(!query_action(REPLY_YES, QUERY_NEXT_VOLUME, (FMSG *)misc_buf))
     {
      if(errorlevel==ARJ_ERL_SUCCESS)
       errorlevel=ARJ_ERL_WARNING;
      errors++;
      goto all_volumes_done;
     }
     if(inhibit_change_test||tries>MAX_VOLUME_FT_CHECKS||!is_removable)
      break;
     if(!file_exists(archive_name))
      break;
    } while(file_getftime(archive_name)==arch_time);
    if(mv_cmd_state!=MVC_NONE)
    {
     if(mv_cmd[0]!='\0')
     {
      if(mv_cmd_state==MVC_DELETION)
       delete_files(mv_cmd);
      else if(mv_cmd_state==MVC_RUN_CMD)
      {
       msg_cprintf(H_PROMPT, M_COMMAND);
       printf(strform, mv_cmd);
       exec_cmd(mv_cmd);
      }
     }
     else
     {
      syscmd=(char *)malloc_msg(CMDLINE_LENGTH+1);
      while(1)
      {
       msg_cprintf(0, M_ENTER_CMD_EXIT);
       msg_cprintf(H_PROMPT, M_COMMAND);
       read_line(syscmd, CMDLINE_LENGTH);
       alltrim(syscmd);
       msg_strcpy(strcpy_buf, M_EXIT_CMD);
       if(!stricmp(strcpy_buf, syscmd))
        break;
       if(syscmd[0]!='\0')
        exec_cmd(syscmd);
      }
      free(syscmd);
     }
    }
    if(pause_between_volumes)
     arj_delay(change_vol_delay);
   #else
    if(!yes_on_all_queries&&!skip_next_vol_query)
     msg_cprintf(0, (FMSG *)bell);
    if((is_removable&&!skip_next_vol_query)||(!yes_on_all_queries&&!skip_next_vol_query))
    {
     reply=M_YES[0];
     if(is_removable)
      msg_sprintf(misc_buf, M_INSERT_DISKETTE, volume_number, reply);
     else
      msg_sprintf(misc_buf, M_QUERY_NEXT_VOLUME, volume_number);
     if(!query_action(REPLY_YES, QUERY_CRITICAL, (FMSG *)misc_buf))
     {
      if(errorlevel==ARJ_ERL_SUCCESS)
       errorlevel=ARJ_ERL_WARNING;
      errors++;
      break;
     }
    }
   #endif
   /* Process next volume... */
   #if SFX_LEVEL>=ARJ
    process_archive_proc(cmd);
   #else
    process_archive();
   #endif
  }
all_volumes_done:
  #if SFX_LEVEL>=ARJ
   if(beep_between_volumes)
    msg_cprintf(0, (FMSG *)bell);
  #else
   if(volume_number>1)
    msg_cprintf(0, (FMSG *)bell);
  #endif
 }
 if(ofstream!=NULL)
 {
  file_close(ofstream);
  ofstream=NULL;
  far_strcpy((char FAR *)filename, tmp_filename);
  file_setftime(filename, ts_native(&volume_ftime, OS));
 }
 #if SFX_LEVEL>=ARJ
  if(tmp_filename!=NULL)
   farfree(tmp_filename);
  if(comment!=NULL)
   farfree(comment);
 #else
  farfree(tmp_filename);
  farfree(comment);
 #endif
 #if SFX_LEVEL>=ARJ
  /* ARJDISP cleanup */
  if(arjdisp_enabled)
  {
   cmd_verb=ARJDISP_CMD_END;
   display_indicator(0L);
  }
 #endif
}

#endif
