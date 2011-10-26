/*
 * $Id: rearj.c,v 1.10 2004/05/31 16:08:41 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This is the main file of the REARJ utility.
 *
 */

#include <stdio.h>
#include <signal.h>
#include <time.h>

#include "arj.h"

#if COMPILER==BCC
#include <dir.h>
#elif COMPILER==MSC
#include <direct.h>
#endif

#if TARGET==UNIX
#include <unistd.h>
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Limits for "*.*"-alike processing */
#ifdef TILED
 #define LARGE_FLIST_SIZE      20000
 #define EXCL_FLIST_SIZE       10000
#else
 #define LARGE_FLIST_SIZE FILELIST_CAPACITY
 #define EXCL_FLIST_SIZE FILELIST_CAPACITY
#endif

#define MAX_SUFFIXES              25    /* Number of supported suffixes */
#if TARGET!=UNIX
#define MAX_SUFFIX                 3    /* Consider increasing... */
#else
#define MAX_SUFFIX                32
#endif
#define MAX_ARGS                 100    /* Maximum # of command-line args */

#if TARGET==UNIX
 #define REARJ_SWITCHAR          "-"
#else
 #define REARJ_SWITCHAR          "/"
#endif

/* Time output sequence */

#define timeseq (int)log_ts.ti_hour, (int)log_ts.ti_min, (int)log_ts.ti_sec

/* Configuration entry structure */

struct archiver_entry
{
 char *suffix;
 char *pack_cmd;
 char *unpack_cmd;
 int hidden_supported;                  /* Consider making them chars */
 int subdirs_supported;
 /* The following is an ASR fix for REARJ v 2.42.05 (.tar.gz) */
 int manual_deletion;                   /* Can't delete errorneous archives */
};

/* Local variables */

static int logging_enabled;             /* 1 if actions are to be logged */
static struct time log_ts;              /* Current time (for logging) */
static int total_suffixes;              /* Number of suffixes in REARJ.CFG */
static struct archiver_entry archivers[MAX_SUFFIXES];
static int target_type;                 /* Target archive type */
static FILE *logstream;                 /* Log file */
static int ctrlc_busy;                  /* 1 if Ctrl+C can't be processed */
static int cnv_diskette_archives;       /* Convert diskette archives (-f) */
static int internal_archives_only;      /* Process only internal archive
                                           files (-e) */
static int update_with_backups;         /* Allow updates of archives with
                                           backup (-u) */
static int conversion_query;            /* Query for conversion (-q) */
static int skip_size_check;             /* Do not check total size and count */
static int run_preunpack_cmd;           /* Run a cmd. before unpacking */
static int run_precount_cmd;            /* 1 if a command must be run before
                                           counting files */
static int run_extract_cmd;             /* Run a command when all files have
                                           been extracted */
static int testing_mode;                /* /Y testing mode */
static char *backup_extension;          /* "BAK" (without a preceding dot) */
static char dot[]=".";                  /* Widely-used symbol */
static char work_dir[CCHMAXPATH];       /* Working directory */
static char name_fetch[CCHMAXPATH];     /* For parsing list files */
static int default_suffix;              /* For non-standard extensions */
static char *tmp_dir;
static char *preunpack_cmd_text;
static char *precount_cmd_text;
static char *extract_cmd_text;
static struct timestamp ts_newer;
static struct timestamp ts_older;
static int limit;
static int cleanup_initiated;
static int ctrlc_initiated;
static int skip_packing;
static int skip_rearj_sw;
static int skip_larger_output;
static int skip_timestamping;
static int pick_older;                  /* Pick older archives (/m) */
static int pick_newer;                  /* Pick newer archives (/n) */
static int exclusion_assigned;          /* Never used but implemented (/x) */
static int convert_nested_archives;
static char *acc_nested_suffixes;       /* Filter for nested archives */
static int delete_original_archives;
static unsigned long total_old_fsize, total_new_fsize;
static int skip_lfn;
static int chk_integrity;
static char *suffix_override;
static char *log_name;
static char *target_suffix;
static char *testing_marker;            /* Text to write (/Y****) */
static char *timestr_older;
static char *timestr_newer;
static FILE *liststream;
static struct date x_date;
static int work_directory_assigned;
static int skip_count;
static int clear_tmp_dir;               /* 1 if files in tmp. dir must be
                                           removed upon shutdown */
static char *arg_ptr[MAX_ARGS];         /* Argument table */
static char u_strform[]="%S";
static char single_spc[]=" ";
static int n_args;
static int tmpdir_malloced;
static char rearj_sw[]="REARJ_SW";

/* Filenames/extensions */

static char backup_ext[]="bak";
static char cfg_name[]="rearj.cfg";
static char rearj_log[]="rearj.log";

/* Pauses the execution and displays an error */

void pause_error(FMSG *msg)
{
 arj_delay(5);
 msg_cprintf(H_ERR, msg);
 exit(REARJ_ERL_WARNING);
}

/* Resets the attributes of all files in the current directory */

static void reset_attrs()
{
 char tmp_name[CCHMAXPATH];
 struct flist_root tmp_flist;
 FILE_COUNT i;

 strcpy(tmp_name, all_wildcard);
 flist_init(&tmp_flist, LARGE_FLIST_SIZE, 0, 0);
 wild_list(&tmp_flist, tmp_name, FETCH_DIRS, 1, 1, NULL);
 for(i=0; i<tmp_flist.files; i++)
 {
  retrieve_entry(tmp_name, &tmp_flist, i);
  flush_kbd();
  if(file_chmod(tmp_name, 1, 0)==-1)
   error(M_CANT_CLEAR_ATTRS, tmp_name);
 }
 flist_cleanup_proc(&tmp_flist);
}

/* Returns total size of the files located in the current directory */

static unsigned long count_total_size()
{
 char tmp_name[CCHMAXPATH];
 struct flist_root tmp_flist;
 FILE_COUNT i;
 unsigned long rc;

 rc=0L;
 strcpy(tmp_name, all_wildcard);
 flist_init(&tmp_flist, LARGE_FLIST_SIZE, 0, 0);
 wild_list(&tmp_flist, tmp_name, FETCH_DIRS, 1, 1, NULL);
 for(i=0; i<tmp_flist.files; i++)
 {
  retrieve_entry(tmp_name, &tmp_flist, i);
  flush_kbd();
  rc+=(unsigned long)file_getfsize(tmp_name);
 }
 flist_cleanup_proc(&tmp_flist);
 return(rc);
}

/* Copies one file to another with mandatory comparison */

static int file_copy_v(char *src, char *dest)
{
 FILE *istream, *ostream;
 char buf[CACHE_SIZE], dbuf[CACHE_SIZE];
 int bytes_read;

 istream=file_open(src, m_rb);
 if(istream==NULL)
  return(-1);
 ostream=file_open(dest, m_wb);
 if(ostream==NULL)
 {
  fclose(istream);
  return(-1);
 }
 flush_kbd();
 do
 {
  flush_kbd();
  if((bytes_read=fread(buf, 1, sizeof(buf), istream))==0)
   break;
 } while(fwrite(buf, 1, bytes_read, ostream)==bytes_read);
 if(fclose(istream))
 {
  fclose(ostream);
  return(-1);
 }
 if(fclose(ostream))
  return(-1);
 istream=file_open(src, m_rb);
 if(istream==NULL)
  return(-1);
 ostream=file_open(dest, m_rb);
 if(ostream==NULL)
 {
  fclose(istream);
  return(-1);
 }
 flush_kbd();
 while(1)
 {
  if((bytes_read=fread(buf, 1, CACHE_SIZE, istream))==0)
   break;
  if(fread(dbuf, 1, CACHE_SIZE, ostream)!=bytes_read)
   break;
  if(memcmp(buf, dbuf, bytes_read))
   break;
  flush_kbd();
 }
 fclose(ostream);
 fclose(istream);
 return((bytes_read>0)?-1:0);
}

/* Returns total number of the files located in the current directory */

static FILE_COUNT count_files()
{
 char tmp_name[CCHMAXPATH];
 struct flist_root tmp_flist;
 FILE_COUNT rc;

 strcpy(tmp_name, all_wildcard);
 flist_init(&tmp_flist, LARGE_FLIST_SIZE, 0, 0);
 wild_list(&tmp_flist, tmp_name, FETCH_DIRS, 1, 1, NULL);
 rc=tmp_flist.files;
 flist_cleanup_proc(&tmp_flist);
 return(rc);
}

/* Recursively removes files and subdirectories */

static void recursive_unlink(char *name)
{
 struct new_ffblk new_ffblk;
 char tmp_name[CCHMAXPATH];
 char subdir_wildcard[20];
 int attr_mask;
 int result;

 attr_mask=STD_FI_ATTRS;
 result=lfn_findfirst(name, &new_ffblk, attr_mask);
 while(result==0)
 {
  if(new_ffblk.ff_attrib&STD_DIR_ATTR)
  {
   if(strcmp(new_ffblk.ff_name, cur_dir_spec)&&strcmp(new_ffblk.ff_name, up_dir_spec))
   {
    split_name(name, tmp_name, subdir_wildcard);
    if(strlen(new_ffblk.ff_name)+strlen(tmp_name)+strlen(subdir_wildcard)+2>=CCHMAXPATH)
     error(M_MAXDIR_EXCEEDED, tmp_name);
    strcat(tmp_name, new_ffblk.ff_name);
    strcat(tmp_name, pathsep_str);
    strcat(tmp_name, subdir_wildcard);
    case_path(tmp_name);
    recursive_unlink(tmp_name);
    /* Remove the directory itself */
    split_name(name, tmp_name, NULL);
    strcat(tmp_name, new_ffblk.ff_name);
    flush_kbd();
    file_chmod(tmp_name, 1, 0);
    if(file_rmdir(tmp_name))
     error(M_CANT_RMDIR, tmp_name);
   }
  }
  else
  {
   split_name(name, tmp_name, NULL);
   strcat(tmp_name, new_ffblk.ff_name);
   case_path(tmp_name);
   flush_kbd();
   file_chmod(tmp_name, 1, 0);
   if(file_unlink(tmp_name))
    error(M_CANT_UNLINK, tmp_name);
  }
  result=lfn_findnext(&new_ffblk);
 }
 lfn_findclose(&new_ffblk);
}

/* Releases the working directory -- ASR fix 14/11/2000 */

static void release_dir(char *dir)
{
 char tmp_name[4];

 #ifdef HAVE_DRIVES
  if(dir[0]!='\0'&&dir[1]==':')
  {
   memcpy(tmp_name, dir, 2);
   strcpy(tmp_name+2, pathsep_str);
  }
  else
   strcpy(tmp_name, pathsep_str);
 #else
  strcpy(tmp_name, pathsep_str);
 #endif
 file_chdir(tmp_name);
}

/* Removes all files on the specified drive/path */

static void unlink_all(char *path)
{
 char tmp_path[CCHMAXPATH];
 char c;

 strcpy(tmp_path, path);
 case_path(tmp_path);
 c=tmp_path[strlen(tmp_path)-1];
 #ifdef HAVE_DRIVES
  strcat(tmp_path, (c==PATHSEP_DEFAULT||c==':')?all_wildcard:root_wildcard);
 #else
  strcat(tmp_path, (c==PATHSEP_DEFAULT)?all_wildcard:root_wildcard);
 #endif
 if(no_file_activity)
  msg_cprintf(H_HL|H_NFMT, M_DELETING, tmp_path);
 recursive_unlink(tmp_path);
}

/* Writes a "SKIPPED" log entry */

static void log_as_skipped(char *name, int reason)
{
 if(logging_enabled)
 {
  arj_gettime(&log_ts);
  if(fprintf(logstream, M_LOGENTRY_SKIP, timeseq, archivers[target_type].suffix, reason, name)<=0)
   error(M_CANT_WRITE_LOG);
 }
}

/* Checks if any subdirectories are present in the current directory */

static int check_for_dirs()
{
 char tmp_name[CCHMAXPATH];
 struct new_ffblk new_ffblk;
 int attr_mask;
 int result;

 strcpy(tmp_name, all_wildcard);
 attr_mask=STD_FI_ATTRS;
 result=lfn_findfirst(tmp_name, &new_ffblk, attr_mask);
 while(result==0)
 {
  if(new_ffblk.ff_attrib&STD_DIR_ATTR&&strcmp(new_ffblk.ff_name, cur_dir_spec)&&strcmp(new_ffblk.ff_name, up_dir_spec))
  {
   lfn_findclose(&new_ffblk);
   return(1);
  }
  result=lfn_findnext(&new_ffblk);
 }
 lfn_findclose(&new_ffblk);
 return(0);
}

/* Checks if any files and/or subdirectories are present in the current
   directory */

static int check_for_entries()
{
 char tmp_name[CCHMAXPATH];
 struct new_ffblk new_ffblk;
 int attr_mask;
 int result;

 strcpy(tmp_name, all_wildcard);
 attr_mask=STD_FI_ATTRS;
 result=lfn_findfirst(tmp_name, &new_ffblk, attr_mask);
 while(result==0)
 {
  if(!(new_ffblk.ff_attrib&STD_DIR_ATTR))
  {
   lfn_findclose(&new_ffblk);
   return(1);
  }
  else if(strcmp(new_ffblk.ff_name, cur_dir_spec)&&strcmp(new_ffblk.ff_name, up_dir_spec))
  {
   lfn_findclose(&new_ffblk);
   return(1);
  }
  result=lfn_findnext(&new_ffblk);
 }
 lfn_findclose(&new_ffblk);
 return(0);
}

/* Returns a fully-qualified filename */

static int truename(char *dest, char *name)
{
 char tmp_name[CCHMAXPATH], cur_dir[CCHMAXPATH];
 int tmp_entry;
#ifdef HAVE_DRIVES 
 int dsk;
#endif

 tmp_entry=split_name(name, dest, tmp_name);
 /* Verify if it's a root directory path or file path */
 if(
#ifdef HAVE_DRIVES  
    (dest[1]!=':'||dest[2]!='\0')&&
    (dest[1]!=':'||dest[2]!=PATHSEP_DEFAULT||dest[3]!='\0')&&
#endif    
    (dest[0]!=PATHSEP_DEFAULT||dest[1]!='\0')&&
    (tmp_entry>0))
  dest[tmp_entry-1]='\0';
#ifdef HAVE_DRIVES 
 dsk=getdisk();
 if(dest[1]==':')
  setdisk(toupper(dest[0])-'A');
#endif 
 if(file_getcwd(cur_dir)==NULL)
 {
  msg_cprintf(0, M_GETCWD_FAILED);
  return(1);
 }
 if(
#ifdef HAVE_DRIVES  
   (dest[1]!=':'||dest[2]!='\0')&&
#endif
    dest[0]!='\0')
 {
  if(file_chdir(dest))
  {
   msg_cprintf(H_HL|H_NFMT, M_PATH_NOT_FOUND, dest);
termination:
   if(file_chdir(cur_dir))
    error(M_CANT_CHDIR, cur_dir);
#ifdef HAVE_DRIVES
   setdisk(dsk);
#endif   
   return(1);
  }
 }
 if(file_getcwd(dest)==NULL)
 {
  msg_cprintf(0, M_GETCWD_FAILED);
  goto termination;
 }
 if(tmp_name[0]!='\0'&&dest[strlen(dest)-1]!=PATHSEP_DEFAULT)
  strcat(dest, pathsep_str);
 strcat(dest, tmp_name);
 if(file_chdir(cur_dir))
  error(M_CANT_CHDIR, cur_dir);
#ifdef HAVE_DRIVES 
 setdisk(dsk);
#endif
 return(0);
}

/* Runs an external command */

static int exec_cmd(char *cmd)
{
 int rc;

 if(no_file_activity)
  return(1);
 flush_kbd();
 ctrlc_busy=1;
 rc=system_cmd(cmd);
 ctrlc_busy=0;
 flush_kbd();
 return(rc);
}

/* Runs an external executable */

static int exec_exe(char *cmd)
{
 int rc;

 if(no_file_activity)
  return(1);
 flush_kbd();
 ctrlc_busy=1;
 rc=exec_pgm(cmd);
 ctrlc_busy=0;
 flush_kbd();
 return(rc);
}

/* Archive conversion procedure */

static int convert_archive(char *name)
{
 long old_fsize, new_fsize;
 int exec_rc=0;
 char full_name[CCHMAXPATH], target_name[CCHMAXPATH];
 char bak_name[CCHMAXPATH];
 char cnv_name[CCHMAXPATH];             /* Converted file in the work dir. */
 char filespec[40];
 int entry;
 char *dot_pos;
 int repack;
 char *tmp_name;
 int i;
 int src_type;
 struct timestamp old_ftime;
 char cmd_buffer[400];
 FILE_COUNT old_count=0, new_count;
 char *nst_suf_wildcard;
 unsigned long old_size=0, new_size;
 long gain;
 #if TARGET==UNIX
  int match, fspec_len, pattern_len;
 #else
  char extension[64];  
 #endif

 if(truename(full_name, name))
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_CANT_FIND, name);
  return(REARJ_ERL_WARNING);
 }
 entry=split_name(full_name, NULL, filespec);
 #if TARGET==UNIX
  fspec_len=strlen(filespec);
 #endif
 dot_pos=strrchr(filespec, '.');
 if(dot_pos==NULL)
 {
  #if TARGET!=UNIX
   extension[0]='\0';
  #endif
  strcpy(target_name, full_name);
  strcat(target_name, dot);
  strcat(target_name, archivers[target_type].suffix);
  strcpy(bak_name, full_name);
 }
 else
 {
  #if TARGET!=UNIX
   *dot_pos++='\0';
   strcpy(extension, dot_pos);
  #endif
  strncpy(target_name, full_name, entry);
  target_name[entry]='\0';
  strcpy(bak_name, target_name);
  #if TARGET!=UNIX
   strcat(target_name, filespec);
   strcat(target_name, dot);
   strcat(target_name, archivers[target_type].suffix);
  #endif
  strcat(bak_name, filespec);
 }
 strcat(bak_name, dot);
 strcat(bak_name, backup_extension);
 strcpy(cnv_name, work_dir);
 strcat(cnv_name, pathsep_str);
 strcat(cnv_name, filespec);
 strcat(cnv_name, dot);
 strcat(cnv_name, archivers[target_type].suffix);
 repack=!strcmp_os(target_name, full_name);
 tmp_name=cnv_diskette_archives?cnv_name:target_name;
 src_type=-1;
 for(i=0; i<total_suffixes; i++)
 {
  #if TARGET==UNIX
   match=0;
   if(dot_pos==NULL)
   {
    if(archivers[i].suffix[0]=='\0')
     match=1;
   }
   else
   {
    pattern_len=strlen(archivers[i].suffix);
    if(fspec_len>pattern_len&&
       filespec[fspec_len-pattern_len-1]=='.'&&
       !strcmp_os(filespec+fspec_len-pattern_len, archivers[i].suffix))
    {
     match=1;
     strcat(target_name, filespec);
     target_name[strlen(target_name)-pattern_len]='\0';
     strcat(target_name, archivers[target_type].suffix);
    }
   }
   if(match)
    src_type=i;
  #else
   if(!strcmp_os(extension, archivers[i].suffix))
    src_type=i;
  #endif
 }
 if(src_type==-1)
  src_type=default_suffix;
 if(src_type==-1)
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_UNKNOWN_TYPE, full_name);
  return(REARJ_ERL_UNCONFIGURED);
 }
 old_fsize=file_getfsize(full_name);
 if((!overwrite_existing&&!repack&&file_exists(target_name))||
    (cnv_diskette_archives&&!overwrite_existing&&file_exists(cnv_name)))
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_TGT_EXISTS, full_name);
  return(REARJ_ERL_TGT_EXISTS);
 }
 if(!update_with_backups&&repack)
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_REPACK, full_name);
  return(REARJ_ERL_UPD_SKIPPED);
 }
 msg_cprintf(H_HL|H_NFMT, M_CONVERTING_ARCHIVE, full_name, archivers[src_type].suffix, archivers[target_type].suffix);
 if(conversion_query)
 {
  msg_cprintf(0, M_QUERY_CONVERT);
  if(!query_action())
  {
   msg_cprintf(H_HL|H_NFMT, M_SKIPPING, full_name);
   return(REARJ_ERL_UPD_SKIPPED);
  }
 }
 if(overwrite_existing&&!repack&&file_exists(target_name)&&!no_file_activity)
  if(file_unlink(target_name))
   error(M_CANT_UNLINK, target_name);
 if(cnv_diskette_archives&&overwrite_existing&&file_exists(cnv_name)&&!no_file_activity)
  if(file_unlink(cnv_name))
   error(M_CANT_UNLINK, cnv_name);
 ts_store(&old_ftime, OS, file_getftime(full_name));
 unlink_all(tmp_dir);
 if(file_chdir(tmp_dir))
  error(M_CANT_CHDIR, tmp_dir);
 if(run_preunpack_cmd)
 {
  sprintf(cmd_buffer, "%s %s", preunpack_cmd_text, full_name);
  msg_cprintf(H_HL|H_NFMT, M_EXECUTING_PRE, cmd_buffer);
  exec_cmd(cmd_buffer);
 }
 sprintf(cmd_buffer, archivers[src_type].unpack_cmd, full_name);
 msg_cprintf(H_HL|H_NFMT, M_EXECUTING, cmd_buffer);
 exec_rc=exec_exe(cmd_buffer);
 if(exec_rc!=0)
 {
  if(exec_rc==-1)
   msg_cprintf(H_HL|H_NFMT, M_SKIP_EXE_MISSING, full_name);
  else
   msg_cprintf(H_HL|H_NFMT, M_SKIP_UNPACK_ERR, full_name, exec_rc);
  return(REARJ_ERL_UNPACK);
 }
 if(!archivers[target_type].subdirs_supported&&check_for_dirs())
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_UNSUPP_DIR, full_name);
  return(REARJ_ERL_DIRECTORIES);
 }
 if(!check_for_entries())
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_NO_FILES, full_name);
  return(REARJ_ERL_UNPACK);
 }
 if(run_precount_cmd)
 {
  sprintf(cmd_buffer, "%s %s", precount_cmd_text, full_name);
  msg_cprintf(H_HL|H_NFMT, M_EXECUTING_CNT, cmd_buffer);
  exec_cmd(cmd_buffer);
 }
 if(!skip_size_check)
  old_count=count_files();
 if(run_extract_cmd)
 {
  msg_cprintf(H_HL|H_NFMT, M_EXECUTING_EXTR, extract_cmd_text);
  exec_rc=exec_exe(extract_cmd_text);
  if(exec_rc!=0)
  {
   if(exec_rc==-1)
    msg_cprintf(H_HL|H_NFMT, M_SKIP_V_EXE_MISSING, full_name);
   else
    msg_cprintf(H_HL|H_NFMT, M_SKIP_V_ERR, full_name, exec_rc);
   return(REARJ_ERL_VIRUS);
  }
 }
 if(convert_nested_archives)
 {
  nst_suf_wildcard=(acc_nested_suffixes!=NULL)?acc_nested_suffixes:archivers[src_type].suffix;
  /* ASR FIX 30/12/1999: only 6 additional (%s) params in original REARJ v 2.42 */
  sprintf(cmd_buffer,
          "%s *.%s " REARJ_SWITCHAR "t%s " REARJ_SWITCHAR "d " REARJ_SWITCHAR "r " REARJ_SWITCHAR "a%s " REARJ_SWITCHAR "e%s%s%s%s%s%s%s",
          exe_name,
          nst_suf_wildcard,
          archivers[target_type].suffix,
          nst_suf_wildcard,
          skip_size_check?" " REARJ_SWITCHAR "s":nullstr,
          no_file_activity?" " REARJ_SWITCHAR "z":nullstr,
          update_with_backups?" " REARJ_SWITCHAR "u":nullstr,
          overwrite_existing?" " REARJ_SWITCHAR "o":nullstr,
          run_extract_cmd?" " REARJ_SWITCHAR "v":nullstr,
          skip_rearj_sw?" " REARJ_SWITCHAR "+":nullstr,
          skip_packing?" " REARJ_SWITCHAR "g":nullstr);
  msg_cprintf(H_HL|H_NFMT, M_EXECUTING, cmd_buffer);
  exec_rc=exec_exe(cmd_buffer);
  if(exec_rc!=0)
  {
   if(exec_rc==-1)
    msg_cprintf(H_HL|H_NFMT, M_SKIP_REARJ_MISSING, full_name);
   else
    msg_cprintf(H_HL|H_NFMT, M_SKIP_REARJ_FAILED, full_name, exec_rc);
   return(REARJ_ERL_INTERNAL);
  }
 }
 if(skip_packing)
 {
  if(logging_enabled)
  {
   arj_gettime(&log_ts);
   if(fprintf(logstream, M_LOGENTRY_CONV, timeseq, archivers[target_type].suffix, old_fsize, 0L, 0L, full_name)<=0)
    error(M_CANT_WRITE_LOG);
  }
  return(0);
 }
 if(!skip_size_check)
  old_size=count_total_size();
 if(!archivers[target_type].hidden_supported)
  reset_attrs();
 if(update_with_backups&&repack)
 {
  if(file_exists(bak_name)&&!no_file_activity)
   if(file_unlink(bak_name))
    error(M_CANT_UNLINK, bak_name);
  if(!no_file_activity)
   if(rename_with_check(full_name, bak_name))
   {
    msg_cprintf(H_HL|H_NFMT, M_SKIP_CANT_RENAME, full_name, bak_name);
    return(REARJ_ERL_RENAME);
   }
  if(!no_file_activity)
   msg_cprintf(H_HL|H_NFMT, M_BACKED_UP, full_name, bak_name);
 }
 sprintf(cmd_buffer, archivers[target_type].pack_cmd, tmp_name);
 msg_cprintf(H_HL|H_NFMT, M_EXECUTING, cmd_buffer);
 exec_rc=exec_exe(cmd_buffer);
 if(exec_rc!=0)
 {
  if(update_with_backups&&repack)
  {
   if(file_exists(full_name)&&!no_file_activity)
    if(file_unlink(full_name))
     error(M_CANT_UNLINK, full_name);
   if(!no_file_activity)
    if(rename_with_check(bak_name, full_name))
     error(M_CANTRENAME, bak_name, full_name);
  }
  if(exec_rc==-1)
   msg_cprintf(H_HL|H_NFMT, M_SKIP_P_EXE_MISSING, full_name);
  else
  {
   /* ASR fix for 2.42.05 -- unlink empty .tar.gz archives */
   if(archivers[target_type].manual_deletion)
    unlink(tmp_name);
   msg_cprintf(H_HL|H_NFMT, M_SKIP_PACK_ERR, full_name, exec_rc);
  }
  return(REARJ_ERL_PACK);
 }
 if(file_chdir(work_dir))
  error(M_CANT_CHDIR, work_dir);
 if(!file_exists(tmp_name))
 {
  if(update_with_backups&&repack)
  {
   if(file_exists(full_name)&&!no_file_activity)
    if(file_unlink(full_name))
     error(M_CANT_UNLINK, full_name);
   if(!no_file_activity)
    if(rename_with_check(bak_name, full_name))
     error(M_CANTRENAME, bak_name, full_name);
  }
  msg_cprintf(H_HL|H_NFMT, M_SKIP_NOT_PACKED, full_name);
  return(REARJ_ERL_PACK);
 }
 new_fsize=file_getfsize(tmp_name);
 if(skip_larger_output&&old_fsize<new_fsize)
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIP_LARGER, full_name);
  if(!no_file_activity)
   if(file_unlink(tmp_name))
    error(M_CANT_UNLINK, tmp_name);
  if(update_with_backups||!repack||no_file_activity)
   return(REARJ_ERL_OVERGROW);
  else
  {
   if(rename_with_check(bak_name, full_name))
    return(REARJ_ERL_OVERGROW);
   else
    error(M_CANTRENAME, bak_name, full_name);
  }
 }
 if(!skip_size_check)
 {
  msg_cprintf(H_HL|H_NFMT, M_VERIFYING_SIZE, old_count, old_size);
  unlink_all(tmp_dir);
  if(file_chdir(tmp_dir))
   error(M_CANT_CHDIR, tmp_dir);
  sprintf(cmd_buffer, archivers[target_type].unpack_cmd, tmp_name);
  msg_cprintf(H_HL|H_NFMT, M_EXECUTING, cmd_buffer);
  exec_exe(cmd_buffer);
  new_count=count_files();
  new_size=count_total_size();
  msg_cprintf(H_HL|H_NFMT, M_FOUND_SIZE, new_count, new_size);
  if(old_count!=new_count)
  {
   msg_cprintf(H_HL|H_NFMT, M_SKIP_COUNT_MISMATCH, full_name);
   if(!no_file_activity)
    if(file_unlink(tmp_name))
     error(M_CANT_UNLINK, tmp_name);
   if(update_with_backups&&repack&&!no_file_activity)
    if(rename_with_check(bak_name, full_name))
     error(M_CANTRENAME, bak_name, full_name);
   return(REARJ_ERL_COUNT);
  }
  if(old_size!=new_size)
  {
   msg_cprintf(H_HL|H_NFMT, M_SKIP_SIZE_MISMATCH, full_name);
   if(!no_file_activity)
    if(file_unlink(tmp_name))
     error(M_CANT_UNLINK, tmp_name);
   if(update_with_backups&&repack&&!no_file_activity)
    if(rename_with_check(bak_name, full_name))
     error(M_CANTRENAME, bak_name, full_name);
   return(REARJ_ERL_SIZE);
  }
  msg_cprintf(H_HL, M_SIZE_VERIFIED);
  if(file_chdir(work_dir))
   error(M_CANT_CHDIR, work_dir);
 }
 if(cnv_diskette_archives)
 {
  if(file_getfree(full_name)+old_fsize<new_fsize)
  {
   msg_cprintf(H_HL|H_NFMT, M_SKIP_DISK_FULL, full_name);
   if(!no_file_activity)
    if(file_unlink(tmp_name))
     error(M_CANT_UNLINK, tmp_name);
   if(update_with_backups&&repack&&!no_file_activity)
    if(rename_with_check(bak_name, full_name))
     error(M_CANTRENAME, bak_name, full_name);
   return(REARJ_ERL_DISK_FULL);
  }
 }
 if(delete_original_archives)
 {
  if(!repack)
  {
   msg_cprintf(H_HL|H_NFMT, M_DELETING_2, full_name);
   if(!no_file_activity)
    if(file_unlink(full_name))
     error(M_CANT_UNLINK, full_name);
  }
  else if(cnv_diskette_archives&&update_with_backups)
  {
   msg_cprintf(H_HL|H_NFMT, M_DELETING_2, bak_name);
   if(!no_file_activity)
    if(file_unlink(bak_name))
     error(M_CANT_UNLINK, bak_name);
  }
 }
 if(cnv_diskette_archives)
 {
  if(!no_file_activity)
  {
   if(file_copy_v(cnv_name, target_name))
    error(M_CANT_COPY, cnv_name, target_name);
  }
  if(!no_file_activity)
   if(file_unlink(cnv_name))
    error(M_CANT_UNLINK, cnv_name);
 }
 if(delete_original_archives&&!cnv_diskette_archives&&update_with_backups&&repack)
 {
  msg_cprintf(H_HL|H_NFMT, M_DELETING_2, bak_name);
  if(!no_file_activity)
   if(file_unlink(bak_name))
    error(M_CANT_UNLINK, bak_name);
 }
 if(!skip_timestamping)
  file_setftime(target_name, ts_native(&old_ftime, OS));
 if(testing_mode&&!delete_original_archives)
 {
  if(update_with_backups&&repack)
  {
   if(file_exists(full_name))
    if(file_unlink(full_name))
     error(M_CANT_UNLINK, full_name);
   msg_cprintf(H_HL|H_NFMT, M_RENAMING, bak_name, full_name);
   if(!no_file_activity)
   {
    if(rename_with_check(bak_name, full_name))
     error(M_CANTRENAME, bak_name, full_name);
   }
  }
  else if(!repack)
  {
   msg_cprintf(H_HL|H_NFMT, M_DELETING_2, target_name);
   if(!no_file_activity)
    if(file_unlink(target_name))
     error(M_CANT_UNLINK, target_name);
  }
 }
 gain=(long)(old_fsize-new_fsize);
 msg_cprintf(H_HL|H_NFMT, M_OLD_SIZE, old_fsize);
 msg_cprintf(H_HL|H_NFMT, M_NEW_SIZE, new_fsize);
 msg_cprintf(H_HL|H_NFMT, M_SAVINGS_SIZE, gain);
 printf(lf);
 total_old_fsize+=old_fsize;
 total_new_fsize+=new_fsize;
 total_files++;
 if(logging_enabled)
 {
  arj_gettime(&log_ts);
  if(fprintf(logstream, M_LOGENTRY_CONV, timeseq, archivers[target_type].suffix, old_fsize, new_fsize, gain, full_name)<=0)
   error(M_CANT_WRITE_LOG);
 }
 return(0);
}

/* Adds a new file to the exclusion filelist */

static void submit_exclusion(char *name)
{
 char tmp_name[CCHMAXPATH];
 FILE *stream;

 if(name[0]=='!')
 {
  name++;
  if(name[0]=='\0')
   error(M_LISTFILE_MISSING);
  if((stream=file_open(name, m_r))==NULL)
   error(M_CANTOPEN, stream);
  while(fgets(tmp_name, sizeof(tmp_name), stream)!=NULL)
  {
   tokenize_lf(tmp_name);
   alltrim(tmp_name);
   if(tmp_name[0]!='\0')
   {
    if(wild_list(&flist_exclusion, tmp_name, 0, 0, 0, NULL))
     break;
   }
  }
  fclose(stream);
 }
 else
  wild_list(&flist_exclusion, name, 0, 0, 0, NULL);
}

/* Sets up REARJ */

static void analyze_rearj_sw(char *arg)
{
 char sw;
 char *swptr;

 swptr=arg+1;
 sw=toupper(*swptr);
 swptr++;
 if(sw=='D'&&*swptr=='\0')
  delete_original_archives=1;
 else if(sw=='E'&&*swptr=='\0')
  internal_archives_only=1;
 else if(sw=='F'&&*swptr=='\0')
  cnv_diskette_archives=1;
 else if(sw=='H'&&*swptr=='\0')
  help_issued=1;
 else if(sw=='O'&&*swptr=='\0')
  overwrite_existing=1;
 else if(sw=='P'&&*swptr=='\0')
  skip_lfn=1;
 else if(sw=='Q'&&*swptr=='\0')
  conversion_query=1;
 else if(sw=='R'&&*swptr=='\0')
  recurse_subdirs=1;
 else if(sw=='S'&&*swptr=='\0')
  skip_size_check=1;
 else if(sw=='V'&&*swptr=='\0')
  run_extract_cmd=1;
 else if(sw=='Z'&&*swptr=='\0')
  no_file_activity=1;
 else if(sw=='A')
 {
  if(*swptr!='\0')
  {
   case_path(swptr);
   acc_nested_suffixes=swptr;
  }
  convert_nested_archives=1;
 }
 else if(sw=='B'&&*swptr!='\0')
 {
  run_preunpack_cmd=1;
  preunpack_cmd_text=swptr;
 }
 else if(sw=='C'&&*swptr!='\0')
 {
  run_precount_cmd=1;
  precount_cmd_text=swptr;
 }
 else if(sw=='I')
 {
  if(*swptr!='\0')
  {
   case_path(swptr);
   exe_name=swptr;
  }
  chk_integrity=1;
 }
 else if(sw=='F'&&*swptr!='\0')
 {
  default_suffix=-1;
  case_path(swptr);
  suffix_override=swptr;
 }
 else if(sw=='L')
 {
  if(*swptr!='\0')
  {
   case_path(swptr);
   log_name=swptr;
  }
  logging_enabled=1;
 }
 else if(sw=='T'&&*swptr!='\0')
 {
  target_type=-1;
  case_path(swptr);
  target_suffix=swptr;
 }
 else if(sw=='U')
 {
  if(*swptr!='\0')
  {
   case_path(swptr);
   backup_extension=swptr;
  }
  update_with_backups=1;
 }
 else if(sw=='W'&&*swptr!='\0')
 {
  case_path(swptr);
  tmp_dir=swptr;
  work_directory_assigned=1;
 }
 else if(sw=='X'&&*swptr!='\0')
  submit_exclusion(swptr);
 else if(sw=='G'&&*swptr=='\0')
  skip_packing=1;
 else if(sw=='J'&&*swptr=='\0')
  skip_larger_output=1;
 else if(sw=='K'&&*swptr=='\0')
  skip_timestamping=1;
 else if(sw=='+'&&*swptr=='\0')
  skip_rearj_sw=1;
 else if(sw=='M')
 {
  pick_older=1;
  timestr_older=swptr;
 }
 else if(sw=='N')
 {
  pick_newer=1;
  timestr_newer=swptr;
 }
 else if(sw=='Y')
 {
  testing_mode=1;
  testing_marker=swptr;
 }
 else
  error(M_INVALID_SWITCH, arg);
}

/* Parses REARJ.CFG */

static void parse_rearj_cfg()
{
 #if COMPILER==BCC
  char *cfg_path;
 #else
  char cfg_path[CCHMAXPATH];
 #endif
 char tmp_line[200];
 FILE *stream;
 int i, fakesuffix;

 #if TARGET!=UNIX
  #if COMPILER==BCC
   if((cfg_path=searchpath(cfg_name))==NULL)
    error(M_CANT_FIND_CONFIG, cfg_name);
  #else
   _searchenv(cfg_name, "PATH", cfg_path);
   if(cfg_path[0]=='\0')
    error(M_CANT_FIND_CONFIG, cfg_name);
  #endif
 #else
  /* Attempt search in home directory first, then in /etc. */
  sprintf(cfg_path, "%s/.%s", getenv("HOME"), cfg_name);
  if((stream=file_open(cfg_path, m_r))!=NULL)
   fclose(stream);
  else
   sprintf(cfg_path, "/etc/%s", cfg_name);
 #endif
 if((stream=file_open(cfg_path, m_r))==NULL)
  error(M_CANTOPEN, cfg_path);
 msg_cprintf(H_HL|H_NFMT, M_USING_CONFIG, cfg_path);
 if(fgets(tmp_line, sizeof(tmp_line), stream)==NULL)
  total_suffixes=0;
 else
 {
  rewind(stream);
  for(i=0; i<MAX_SUFFIXES; i++)
  {
   /* ASR fix for 2.43, 24/01/2003 - the option strings may be placed before
      ANY extension command. */
   do
   {
    /* Extension */
    do
    {
     if(fgets(tmp_line, sizeof(tmp_line), stream)==NULL)
      goto no_more_exts;
     archivers[i].hidden_supported=0;
     archivers[i].subdirs_supported=0;
     archivers[i].manual_deletion=0;     /* ASR fix */
     tokenize_lf(tmp_line);
     alltrim(tmp_line);
    } while (tmp_line[0]=='\0');
    fakesuffix=1;
#ifdef COLOR_OUTPUT
    if(!strnicmp(tmp_line, "COLORS ", 7))
    {
     if(parse_colors(tmp_line+7))
      error(M_INVALID_PARAM_STR, tmp_line);
    }
    else
#endif
    if(!strnicmp(tmp_line, "VIRUS ", 6))
    {
     if((extr_cmd_text=strdup(tmp_line+6))==NULL)
      error(M_OUT_OF_MEMORY);
     if(strchr(extr_cmd_text, PATHSEP_DEFAULT)==NULL)
     {
      msg_cprintf(0, M_NO_ANTIVIRUS_PATH);
      msg_cprintf(0, M_IGNORED_FOR_COMP);
      arj_delay(4);
     }
    }
    else
     fakesuffix=0;
   } while(fakesuffix);
   if(strlen(tmp_line)>MAX_SUFFIX)
    error(M_INVALID_SUFFIX, tmp_line);
   if((archivers[i].suffix=strdup(tmp_line))==NULL)
    error(M_OUT_OF_MEMORY);
   /* Pack command */
   if(fgets(tmp_line, sizeof(tmp_line), stream)==NULL)
    error(M_MISSING_PACK_CMD, archivers[i].suffix);
   tokenize_lf(tmp_line);
   alltrim(tmp_line);
   if(strlen(tmp_line)==0)
    error(M_INVALID_PACK_CMD, tmp_line);
   if(strstr(tmp_line, strform)==NULL&&strstr(tmp_line, u_strform)==NULL)
    error(M_NO_PACK_STRFORM, tmp_line);
   if((archivers[i].pack_cmd=strdup(tmp_line))==NULL)
    error(M_OUT_OF_MEMORY);
   /* Unpack command */
   if(fgets(tmp_line, sizeof(tmp_line), stream)==NULL)
    error(M_MISSING_UNPACK_CMD, archivers[i].suffix);
   tokenize_lf(tmp_line);
   alltrim(tmp_line);
   if(strlen(tmp_line)==0)
    error(M_INVALID_UNPACK_CMD, tmp_line);
   if(strstr(tmp_line, strform)==NULL&&strstr(tmp_line, u_strform)==NULL)
    error(M_NO_UNPACK_STRFORM, tmp_line);
   if((archivers[i].unpack_cmd=strdup(tmp_line))==NULL)
    error(M_OUT_OF_MEMORY);
   /* Option record */
   if(fgets(tmp_line, sizeof(tmp_line), stream)==NULL)
    error(M_MISSING_OPTIONS, archivers[i].suffix);
   tokenize_lf(tmp_line);
   alltrim(tmp_line);
   if(strpbrk(tmp_line, "Aa")!=NULL)
    archivers[i].hidden_supported=1;
   if(strpbrk(tmp_line, "Dd")!=NULL)
    archivers[i].subdirs_supported=1;
   /* ASR fix for v 2.42.05 (.tar.gz): */
   if(strpbrk(tmp_line, "Tt")!=NULL)
    archivers[i].manual_deletion=1;
  }
no_more_exts:
  total_suffixes=i;
 }
 fclose(stream);
}

/* atexit routine */

static void final_cleanup(void)
{
 if(!cleanup_initiated)
 {
  cleanup_initiated=1;
  if(tmpdir_malloced)
   release_dir(tmp_dir);                /* ASR fix 14/11/2000 */
  if(work_dir[0]!='\0')
   file_chdir(work_dir);
  if(tmp_dir!=NULL)
  {
   if(clear_tmp_dir)
    unlink_all(tmp_dir);
   if(!work_directory_assigned)
    file_rmdir(tmp_dir);
   if(tmpdir_malloced)
   {
    free(tmp_dir);                      /* malloc'ed */
    tmpdir_malloced=0;
   }
  }
 }
#ifdef COLOR_OUTPUT
 scrn_reset();
#endif
}

/* Ctrl+C handler */

static void ctrlc_handler(SIGHDLPARAMS)
{
 /* Check if we are able to honor the request. If we aren't, raise the
    signal again and make a speedy getaway. */
 if(ctrlc_busy)
  raise(SIGINT);
 else
 {
  ctrlc_initiated=1;
  signal(SIGINT, NULL);                 /* Restore default Ctrl+C handler */
  msg_cprintf(H_SIG, M_BREAK_SIGNALED);
  exit(REARJ_ERL_WARNING);
 }
}

/* Main routine */

int main(int argc, char **argv)
{
 int cnv_rc, exit_code;
 static char rearj_exe[CCHMAXPATH];
 int switchar;
 int arg;
 char *aptr=NULL;
 unsigned int i;
 FILE_COUNT cur_file;
 char tmp_name[CCHMAXPATH], src_name[CCHMAXPATH];
 char *fullpath;
 long total_gain;
 char *env_ptr, *env_dup, *env_tail;
 struct timestamp timestamp;
 time_t start_time, end_time;
 unsigned long time_diff;

#ifdef COLOR_OUTPUT
 no_colors=redirected=!is_tty(stdout);
#endif
 msg_cprintf(0, M_REARJ_BANNER, build_date);
 #ifdef TZ_VAR
  tzset();
 #endif
 build_crc32_table();
 ctrlc_busy=0;
 lfn_supported=LFN_NOT_SUPPORTED;
 convert_nested_archives=0;
 run_precount_cmd=0;
 run_preunpack_cmd=0;
 recurse_subdirs=0;
 help_issued=0;
 no_file_activity=0;
 delete_original_archives=0;
 skip_larger_output=0;
 cnv_diskette_archives=0;
 run_extract_cmd=0;
 skip_rearj_sw=0;
 logging_enabled=0;
 internal_archives_only=0;
 pick_older=0;
 pick_newer=0;
 conversion_query=0;
 chk_integrity=0;
 overwrite_existing=0;
 skip_lfn=0;
 skip_packing=0;
 skip_timestamping=0;
 skip_size_check=0;
 work_directory_assigned=0;
 testing_mode=0;
 update_with_backups=0;
 clear_tmp_dir=0;
 skip_count=0;
 target_type=0;
 total_old_fsize=total_new_fsize=0L;
 total_files=0;
 ts_store(&ts_older, OS_SPECIAL, 0L);
 ts_newer=ts_older;
 ctrlc_initiated=0;
 is_registered=0;
 exit_code=REARJ_ERL_SUCCESS;
 log_name=rearj_log;
 default_suffix=-1;
 backup_extension=backup_ext;
 #ifndef SKIP_GET_EXE_NAME
  get_exe_name(rearj_exe);
 #else
  get_exe_name(rearj_exe, argv[0]);
 #endif
 exe_name=rearj_exe;
 target_suffix=NULL;
 suffix_override=NULL;
 extract_cmd_text=NULL;
 precount_cmd_text=NULL;
 preunpack_cmd_text=NULL;
 tmp_dir=NULL;
 testing_marker=NULL;
 acc_nested_suffixes=NULL;
 work_dir[0]='\0';
 timestr_older=timestr_newer=nullstr;
 flist_init(&flist_exclusion, EXCL_FLIST_SIZE, 0, 0);
 atexit(final_cleanup);
 parse_reg_key();
 detect_lfns();
 is_registered=reg_validation(regdata+REG_KEY1_SHIFT, regdata+REG_KEY2_SHIFT, regdata+REG_NAME_SHIFT, regdata+REG_HDR_SHIFT);
 if(!is_registered&&!msg_strcmp((FMSG *)regdata+REG_KEY2_SHIFT, M_REG_TYPE))
  msg_cprintf(0, M_REGISTERED_TO, regdata+REG_NAME_SHIFT);
 limit=20;
 total_suffixes=0;
 if(signal(SIGINT, ctrlc_handler)==SIG_ERR)
  error(M_SIGNAL_FAILED);
 limit=0;
 if(regdata[REG_NAME_SHIFT]=='\0')
  is_registered=1;
 if(!reg_validation(single_spc, single_spc, single_spc, regdata+REG_HDR_SHIFT))
  is_registered=2;
 n_args=0;
 switchar=get_sw_char();
 for(arg=1; arg<argc; arg++)
 {
  aptr=argv[arg];
  if(aptr[0]==switchar&&aptr[1]=='+'&&aptr[2]=='\0')
   skip_rearj_sw=0;
 }
 if((env_ptr=getenv(rearj_sw))!=NULL)
 {
  env_dup=strdup(env_ptr);
  msg_cprintf(H_HL|H_NFMT, M_USING_REARJ_SW, env_dup);
  for(env_ptr=env_dup; *env_ptr!='\0'; env_ptr++)
   if(*env_ptr==' ')
    *env_ptr='\0';                       /* Tokenize by spaces */
  env_tail=env_ptr;
  env_ptr=env_dup;
  while(env_ptr<env_tail)
  {
   while(*env_ptr=='\0')
    env_ptr++;
   if(env_ptr<env_tail)
   {
    if(switchar=='-')
     name_to_hdr(env_ptr);
    if(*env_ptr==switchar)
     analyze_rearj_sw(aptr);
    while(*env_ptr!='\0'&&env_ptr<env_tail)
     env_ptr++;
   }
  }
 }
 for(arg=1; arg<argc; arg++)
 {
  aptr=argv[arg];
  if(switchar=='-')
   name_to_hdr(aptr);
  if(aptr[0]==switchar)
   analyze_rearj_sw(aptr);
  else
  {
   if(n_args>=MAX_ARGS)
    error(M_ARGTABLE_OVERFLOW);
   arg_ptr[n_args++]=aptr;
  }
 }
 if(skip_lfn)
  lfn_supported=LFN_NOT_SUPPORTED;
 if(chk_integrity)
  exit(check_integrity(rearj_exe));
 if(help_issued||n_args==0)
 {
  msg_cprintf(0, strform, M_REARJ_COMMANDS);
  msg_cprintf(0, strform, M_REARJ_RCODES);
  exit(REARJ_ERL_SUCCESS);
 }
 if(delete_original_archives&&testing_mode)
  error(M_YD_CMD_CONFLICT);
 if(testing_mode&&testing_marker!=NULL&&!logging_enabled)
  error(M_LY_CMD);
 parse_rearj_cfg();
 if(run_extract_cmd&&extract_cmd_text==NULL)
  error(M_NO_V_CMD, cfg_name);
 if(suffix_override!=NULL)
 {
  default_suffix=-1;
  for(i=0; i<total_suffixes; i++)
  {
   if(!strcmp_os(suffix_override, archivers[i].suffix))
    default_suffix=i;
  }
  if(default_suffix<0)
   error(M_INVALID_F_SUFFIX, suffix_override);
 }
 if(target_suffix!=NULL)
 {
  target_type=-1;
  for(i=limit; i<total_suffixes; i++)
  {
   if(!strcmp_os(target_suffix, archivers[i].suffix))
    target_type=i;
  }
  if(target_type<0)
   error(M_INVALID_T_SUFFIX, target_suffix);
 }
 if(pick_older||pick_newer)
 {
  if(timestr_older[0]!='\0')
   convert_strtime(&ts_older, timestr_older);
  if(timestr_newer[0]!='\0')
   convert_strtime(&ts_newer, timestr_newer);
  if(timestr_older[0]=='\0'||timestr_newer[0]=='\0')
  {
   arj_getdate(&x_date);
   make_timestamp(&timestamp, x_date.da_year, x_date.da_mon, x_date.da_day,
                  0, 0, 0);
   if(timestr_newer[0]=='\0')
    ts_newer=timestamp;
   if(timestr_older[0]=='\0')
    ts_older=timestamp;
  }
 }
 if(file_getcwd(work_dir)==NULL)
  error(M_GETCWD_FAILED);
 if(no_file_activity)
  msg_cprintf(0, M_SIMULATION_MODE);
 flist_init(&flist_main, LARGE_FLIST_SIZE, n_args>1, 1);
 for(i=limit; i<n_args; i++)
 {
  flush_kbd();
  if(arg_ptr[i][0]=='!')
  {
   if(arg_ptr[i][1]=='\0')
    error(M_NO_LISTFILE);
   if((liststream=file_open(arg_ptr[i]+1, m_r))==NULL)
    error(M_CANTOPEN, arg_ptr[i]+1);
   while(fgets(name_fetch, CCHMAXPATH, liststream)!=NULL)
   {
    tokenize_lf(name_fetch);
    alltrim(name_fetch);
    if(name_fetch[0]!='\0')
    {
     strcpy(tmp_name, name_fetch);
     if(wild_list(&flist_main, tmp_name, 0, 1, recurse_subdirs, NULL))
      break;
    }
   }
   fclose(liststream);
  }
  else
  {
   strcpy(tmp_name, arg_ptr[i]);
   if(wild_list(&flist_main, tmp_name, 0, 1, recurse_subdirs, NULL))
    break;
  }
 }
 if(flist_main.files==0)
 {
  msg_cprintf(0, internal_archives_only?M_NO_FILES_INT:M_NO_FILES);
  exit(internal_archives_only?REARJ_ERL_SUCCESS:REARJ_ERL_WARNING);
 }
 time(&start_time);
 if(logging_enabled)
 {
  if((logstream=file_open(log_name, m_a))==NULL)
   error(M_CANTOPEN, log_name);
  arj_gettime(&log_ts);
  if(testing_marker!=NULL)
   if(fprintf(logstream, M_LOGENTRY_MARKER, timeseq, archivers[target_type].suffix, testing_marker)<=0)
    error(M_CANT_WRITE_LOG);
  if(fprintf(logstream, M_LOGENTRY_HEADER, timeseq, archivers[target_type].suffix)<=0)
   error(M_CANT_WRITE_LOG);
 }
 if(cnv_diskette_archives&&count_files()>0)
  msg_cprintf(0, M_CWD_MUST_BE_EMPTY);
 if(tmp_dir==NULL)
 {
  /* BUGBUG: this comes from a NetBSD patch. Originally a check for NO_MKDTEMP
     was suggested, but where are we expected to define it under DOS? --
     ASR fix 25/01/2004 */
#ifdef HAVE_MKDTEMP
  tmp_dir=mkdtemp("/tmp/arj.XXXXXX"); /* BUGBUG: hardcoded location? */
#else
  tmp_dir=tmpnam(NULL);
  if(file_mkdir(tmp_dir))
   error(M_CANT_MKDIR, tmp_dir);
#endif
 }
 else
 {
  if(file_chdir(tmp_dir))
   error(M_CANT_CHDIR, tmp_dir);
  if(count_files()>0)
   error(M_WORK_DIR_NOT_EMPTY, tmp_dir);
  if(file_chdir(work_dir))
   error(M_CANT_CHDIR, work_dir);
 }
 if((fullpath=(char *)malloc(CCHMAXPATH))==NULL)
  error(M_OUT_OF_MEMORY);
 if(truename(fullpath, tmp_dir))
  error(M_CANT_GET_FULL_PATH);
 tmp_dir=fullpath;
 clear_tmp_dir=1;
 tmpdir_malloced=1;                     /* Introduced by ASR */
 for(cur_file=0; cur_file<flist_main.files; cur_file++)
 {
  flush_kbd();
  if(fetch_keystrokes())
  {
   msg_cprintf(H_PROMPT, M_OK_TO_QUIT);
   if(query_action())
   {
    msg_cprintf(H_OPER, M_QUITTING);
    exit(REARJ_ERL_WARNING);
   }
  }
  retrieve_entry(src_name, &flist_main, cur_file);
  ts_store(&timestamp, OS, file_getftime(src_name));
  if((!pick_newer||!ts_valid(ts_newer)||ts_cmp(&timestamp, &ts_newer)>=0)&&
     (!pick_older||!ts_valid(ts_older)||ts_cmp(&timestamp, &ts_older)<0))
  {
   cnv_rc=convert_archive(src_name);
   if(cnv_rc!=REARJ_ERL_SUCCESS)
   {
    skip_count++;
    log_as_skipped(src_name, cnv_rc);
    if(exit_code==REARJ_ERL_SUCCESS&&(!internal_archives_only||cnv_rc!=REARJ_ERL_UNCONFIGURED))
     exit_code=cnv_rc;
   }
   release_dir(tmp_dir);                /* ASR fix 14/11/2000 */
   if(file_chdir(work_dir))
    error(M_CANT_CHDIR, work_dir);
   unlink_all(tmp_dir);
   if(file_rmdir(tmp_dir))
    msg_cprintf(H_ERR, M_CANT_RMDIR, tmp_dir);
   if(file_mkdir(tmp_dir))
    error(M_CANT_MKDIR, tmp_dir);
  }
 }
 if(!work_directory_assigned)
 {
  if(file_rmdir(tmp_dir))
   msg_cprintf(H_ERR, M_CANT_RMDIR, tmp_dir);
 }
 if(tmpdir_malloced)
 {
  free(tmp_dir);
  tmpdir_malloced=0;
 }
 tmp_dir=NULL;
 time(&end_time);
 time_diff=sub_time(end_time, start_time);
 total_gain=(long)(total_old_fsize-total_new_fsize);
 msg_cprintf(H_HL|H_NFMT, M_TOTAL_SECONDS, time_diff);
 msg_cprintf(H_HL|H_NFMT, M_TOTAL_CONVERTED, total_files);
 msg_cprintf(H_HL|H_NFMT, M_TOTAL_SKIPPED, skip_count);
 msg_cprintf(H_HL|H_NFMT, M_OLD_SIZE, total_old_fsize);
 msg_cprintf(H_HL|H_NFMT, M_NEW_SIZE, total_new_fsize);
 msg_cprintf(H_HL|H_NFMT, M_SAVINGS_SIZE, total_gain);
 if(logging_enabled)
 {
  arj_gettime(&log_ts);
  if(fprintf(logstream, M_LOGENTRY_FOOTER, timeseq, archivers[target_type].suffix, total_old_fsize, total_new_fsize, total_gain, time_diff)<=0)
   error(M_CANT_WRITE_LOG);
  fclose(logstream);
 }
 flist_cleanup_proc(&flist_main);
 flist_cleanup_proc(&flist_exclusion);
 return((skip_count>0)?exit_code:REARJ_ERL_SUCCESS);
}
