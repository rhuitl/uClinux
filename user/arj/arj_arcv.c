/*
 * $Id: arj_arcv.c,v 1.15 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Archive management routines  are stored here (all these have  nothing to do
 * neither with commands nor with the "user" part).
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

#define MAX_COMMENT_LINES         25    /* As stated in the documentation */

#define SECURED_MODE            0x78    /* file_mode of ARJ SECURITY headers */

/* Ways of processing for the extended header structure */

#define EHUF_WRITE            0x0001    /* Write the header */
#define EHUF_COMMIT           0x0002    /* Advance the pointer(s) */
#define EHUF_SETFLAGS         0x0004    /* Set the volume flag */

/*
 * Local variables
 */

static char *tmp_comment=NULL;          /* Temporary comment storage */
static char *tmp_hptr;                  /* Pointer to parts of header */
static char arjdisp_default[]="arjdisp" EXE_EXTENSION;  /* External display module */
#if SFX_LEVEL>=ARJSFXV
static unsigned char ea_pwd_modifier;   /* For garbled EAs */
static char arjprot_id;                 /* Identifies ARJ-PROTECT block in the
                                           main header */
#endif

/* A table of permissions for binary/text files */

#if SFX_LEVEL>=ARJ
static char *read_perms[]={m_rb, m_r};  /* For encoding only */
#endif
#if SFX_LEVEL>=ARJSFXV
static char *sim_perms[]={m_rbp, m_rp};
#endif
static char *write_perms[]={m_wb, m_w};

/* Index file IDs */

#if SFX_LEVEL>=ARJ
static char idxid_fault[]="?";
#endif

/*
 * A set of macros and functions to read the header
 */

/* These macros read and write a byte from the header */

#define setup_hget(ptr) (tmp_hptr=(ptr))
#define setup_hput(ptr) (tmp_hptr=(ptr))

#define hget_byte() (*(tmp_hptr++)&0xFF)
#define hput_byte(c) (*(tmp_hptr++)=(char) (c))

/* Reads two bytes from the header, incrementing the pointer */

static unsigned int hget_word()
{
 unsigned int result;

 result=mget_word(tmp_hptr);
 tmp_hptr+=sizeof(short);
 return result;
}

/* Reads four bytes from the header, incrementing the pointer */

static unsigned long hget_longword()
{
 unsigned long result;

 result=mget_dword(tmp_hptr);
 tmp_hptr+=sizeof(unsigned long);
 return result;
}

#if SFX_LEVEL>=ARJ

/* Writes two bytes to the header, incrementing the pointer */

static void hput_word(unsigned int w)
{
 mput_word(w,tmp_hptr); 
 tmp_hptr+=sizeof(unsigned short);
}

/* Writes four bytes to the header, incrementing the pointer */

static void hput_longword(unsigned long l)
{
 mput_dword(l,tmp_hptr);
 tmp_hptr+=sizeof(unsigned long);
}

/* Calculates and stores the basic header size */

static void calc_basic_hdr_size()
{
 basic_hdr_size=(unsigned int)first_hdr_size+strlen(hdr_filename)+1+
                strlen(hdr_comment)+1;
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Calculates and stores the offset of comment within a preallocated header */

static void calc_comment_offset()
{
 hdr_comment=&header[(int)first_hdr_size+strlen(hdr_filename)+1];
}

#endif

#if SFX_LEVEL>=ARJ

/* Allocates near memory for a temporary comment image, and copies the comment
   to this area. */

static void replicate_comment()
{
 tmp_comment=malloc_msg(COMMENT_MAX);
 far_strcpy((char FAR *)tmp_comment, comment);
}

/* Removes the temporary comment from memory, copying its contents to original
   comment storage area (the one in the FAR memory). */

static void dump_tmp_comment()
{
 if(tmp_comment!=NULL)
 {
  far_strcpy(comment, (char FAR *)tmp_comment);
  free(tmp_comment);
 }
}

/* Returns 1 if the given type is a file type, not a comment */

static int is_file_type(int t)
{
 return((t==ARJT_BINARY||t==ARJT_TEXT||t==ARJT_DIR||file_type==ARJT_UXSPECIAL||t==ARJT_LABEL)?1:0);
}

#endif

/* Finds archive header, returning its offset within file, or -1 if it can't
   be located. search_all is used to search through the entire file. */

long find_header(int search_all, FILE *stream)
{
 long end_pos;
 long tmp_pos;
 int id;
 
 tmp_pos=ftell(stream);
 #if SFX_LEVEL>=ARJSFXV
  if(archive_size==0L)
  {
   fseek(stream, 0L, SEEK_END);
   archive_size=ftell(stream)-2L;
   #if SFX_LEVEL<=ARJSFXV
    fseek(stream, tmp_pos, SEEK_SET);
   #endif
  }
  end_pos=archive_size;
  if(!search_all)
  {
   if(end_pos>=tmp_pos+HSLIMIT_ARJ)
    end_pos=tmp_pos+HSLIMIT_ARJ;
  }
 while(tmp_pos<end_pos)
 #else
 while(tmp_pos<HSLIMIT_ARJSFX)
 #endif
 {
  fseek(stream, tmp_pos, SEEK_SET);
  id=fget_byte(stream);
  #if SFX_LEVEL>=ARJSFXV
  while(tmp_pos<end_pos)
  #else
  while(tmp_pos<HSLIMIT_ARJSFX)
  #endif
  {
   if(id==HEADER_ID_LO)
   {
    if((id=fget_byte(stream))==HEADER_ID_HI)
     break;
   }
   else
    id=fget_byte(stream);
   tmp_pos++;
  }
  #if SFX_LEVEL>=ARJSFXV
   if(tmp_pos>=end_pos)
    return(-1);
  #endif
  if((basic_hdr_size=fget_word(stream))<=HEADERSIZE_MAX)
  {
   crc32term=CRC_MASK;
   fread_crc(header, basic_hdr_size, stream);
  #if SFX_LEVEL>=ARJ
   if(fget_longword(stream)==(crc32term^CRC_MASK)||ignore_crc_errors==ICE_CRC)
  #else
   if(fget_longword(stream)==(crc32term^CRC_MASK))
  #endif
   {
    fseek(stream, tmp_pos, SEEK_SET);
    return(tmp_pos);
   }
  }
  tmp_pos++;
 }
 return(-1);
}

#if SFX_LEVEL>=ARJ

/* Displays a header error */

static void display_hdr_error_proc(FMSG *errmsg, char *name, unsigned int l)
{
 #ifdef DEBUG
  debug_report(dbg_cur_file, l, 'V');
 #endif
 if(!ignore_archive_errors)
  error(errmsg, name);
 msg_cprintf(0, errmsg, name);
 nputlf();
}

#define display_hdr_error(errmsg, name) display_hdr_error_proc(errmsg, name, __LINE__)

#else

#define display_hdr_error(errmsg, dptr) error(errmsg, dptr)

#endif

/* Checks size of compressed files for abnormal effects (e.g. size<0) */

static int check_file_size()
{
 return((long)origsize<0||(long)compsize<0);
}

/* Reads an archive or file header (<name> is archive filename just for user
   interface, and first, when == 0, specifies that the archive header is being
   read). Returns 0 if the end of archive has been reached. */

#if SFX_LEVEL>=ARJSFXV
int read_header(int first, FILE *stream, char *name)
#else
int read_header(int first)
#define stream aistream
#endif
{
 unsigned short header_id;
 #if SFX_LEVEL>=ARJSFXV
  char id;                              /* Extended header identifier */
  char is_continued;
  struct ext_hdr FAR *tmp_eh;
  unsigned int remainder, fetch_size;
  char FAR *dptr;
  char transfer_buf[64];
 #endif

 #if SFX_LEVEL>=ARJSFXV
  flush_kbd();
  if(ignore_crc_errors!=ICE_NONE)
  {
   if(ignore_crc_errors==ICE_FORMAT)    /* Allow malformed header signatures */
   {
    cur_header_pos=ftell(stream);
    if((header_id=fget_word(stream))==HEADER_ID)
    {
     if((basic_hdr_size=fget_word(stream))==0)
      return(0);
    }
    fseek(stream, cur_header_pos, SEEK_SET);
   }
   if(find_header(1, stream)<0L)
   {
    display_hdr_error(M_BAD_HEADER, NULL);
    return(0);
   }
  }
  cur_header_pos=ftell(stream);
 #endif
 /* Strictly check the header ID */
 if((header_id=fget_word(stream))!=HEADER_ID)
 {
 #if SFX_LEVEL>=ARJSFXV
  if(first!=0)
   display_hdr_error(M_NOT_ARJ_ARCHIVE, name);
  else
 #endif
   display_hdr_error(M_BAD_HEADER, NULL);
  return(0);
 }
 if((basic_hdr_size=fget_word(stream))==0)
  return(0);
 if(basic_hdr_size>HEADERSIZE_MAX)
 {
  display_hdr_error(M_BAD_HEADER, NULL);
  return(0);
 }
 crc32term=CRC_MASK;
 fread_crc(header, basic_hdr_size, stream);
 if((header_crc=fget_longword(stream))!=(crc32term^CRC_MASK))
 {
  display_hdr_error(M_HEADER_CRC_ERROR, NULL);
  #if SFX_LEVEL>=ARJSFXV
   return(0);
  #endif
 }
 setup_hget(header);
 first_hdr_size=hget_byte();
 arj_nbr=hget_byte();
 arj_x_nbr=hget_byte();
 host_os=hget_byte();
 arj_flags=hget_byte();
 method=hget_byte();
 file_type=hget_byte();
 password_modifier=hget_byte();
 ts_store(&ftime_stamp, host_os, hget_longword());
 compsize=hget_longword();
 origsize=hget_longword();
 file_crc=hget_longword();
 entry_pos=hget_word();
 fm_store(&file_mode, host_os, hget_word());
 #if SFX_LEVEL>=ARJSFXV
  /* Before v 2.50, we could only read host data here. With the introduction of
     chapter archives, chapter numbers are stored in this field. NOTE: it will
     be wise to check that the compressor's version (arj_nbr) is >= 7 ... */
  ext_flags=hget_byte();
  chapter_number=hget_byte();
  #if SFX_LEVEL>=ARJ
   if(modify_command&&ts_cmp(&ftime_stamp, &ftime_max)>0&&is_file_type(file_type))
    ftime_max=ftime_stamp;
  #else
   if(ts_cmp(&ftime_stamp, &ftime_max)>0&&file_type!=ARJT_COMMENT)
    ftime_max=ftime_stamp;
  #endif
  resume_position=0L;
  continued_prevvolume=0;
  /* v 2.62+ - reset ext. timestamps */
  ts_store(&atime_stamp, OS_SPECIAL, 0L);
  if(first)
  {
   arjprot_id=0;
   #if SFX_LEVEL>=ARJ
    prot_blocks=0;
   #endif
   if(first_hdr_size>=FIRST_HDR_SIZE_V)
   {
    #if SFX_LEVEL>=ARJ
     prot_blocks=hget_byte();
    #else
     hget_byte();
    #endif
    arjprot_id=hget_byte();
    hget_word();
    if(arjprot_id&SFXSTUB_FLAG)
     use_sfxstub=1;
   }
  }
  else
  {
   if(first_hdr_size<R9_HDR_SIZE)
   {
    if(arj_flags&EXTFILE_FLAG)
    {
     resume_position=hget_longword();
     continued_prevvolume=1;
     mvfile_type=file_type;
    }
   }
   else                                  /* v 2.62+ - resume position is stored
                                             anyway, atime/ctime follows it. */
   {
    resume_position=hget_longword();
    if(arj_flags&EXTFILE_FLAG)
    {
     continued_prevvolume=1;
     mvfile_type=file_type;
    }
    ts_store(&atime_stamp, host_os, hget_longword());
    ts_store(&ctime_stamp, host_os, hget_longword());
    hget_longword();                     /* Reserved in revision 9 headers */
   }
  }
 #endif
 if(check_file_size())
  display_hdr_error(M_BAD_HEADER, NULL);
 #if SFX_LEVEL>=ARJSFXV
  file_garbled=(arj_flags&GARBLED_FLAG)?1:0;
  garble_ftime=ts_native(&ftime_stamp, host_os);
 #endif
 hdr_filename=&header[first_hdr_size];
 /* To conserve space, the calc_comment_offset() is placed in-line */
 #if SFX_LEVEL>=ARJSFXV
  calc_comment_offset();
 #else
  hdr_comment=&header[(int)first_hdr_size+strlen(hdr_filename)+1];
 #endif
 #if SFX_LEVEL>=ARJSFXV
  far_strcpyn((char FAR *)filename, (char FAR *)hdr_filename, FILENAME_MAX);
  far_strcpyn(comment, (char FAR *)hdr_comment, COMMENT_MAX);
 #else
  strncpy(filename, hdr_filename, FILENAME_MAX);
  strncpy(comment, hdr_comment, COMMENT_MAX);
 #endif
 if(first==0&&lfn_supported==LFN_SUPPORTED&&dual_name)
 {
  #if SFX_LEVEL>=ARJSFXV
   far_strcpyn((char FAR *)filename, (char FAR *)hdr_comment, FILENAME_MAX);
   far_strcpyn(comment, (char FAR *)hdr_filename, COMMENT_MAX);
  #else
   strncpy(filename, hdr_comment, FILENAME_MAX);
   strncpy(comment, hdr_filename, COMMENT_MAX);
  #endif
 }
 filename[FILENAME_MAX-1]='\0';
 comment[COMMENT_MAX-1]='\0';
#if SFX_LEVEL>=ARJSFXV
 if(!test_host_os((int)host_os)&&file_type==ARJT_TEXT)
#else
 if(!test_host_os((int)host_os))
#endif
  to_7bit(filename);
 if(arj_flags&PATHSYM_FLAG)
  name_to_hdr(filename);
 if(test_host_os((int)host_os))
  #if SFX_LEVEL>=ARJSFXV
   entry_pos=split_name(filename, NULL, NULL);
  #else
   entry_pos=split_name(filename);
  #endif
 #if SFX_LEVEL<=ARJSFX
  list_adapted_name=filename+entry_pos;
 #endif
 #if SFX_LEVEL>=ARJ
  /* Convert the comment to 7 bits if the host OS is unknown to us */
  if(!test_host_os(host_os))
  {
   replicate_comment();
   to_7bit(tmp_comment);
   dump_tmp_comment();
  }
 #elif SFX_LEVEL==ARJSFX
  if(!test_host_os(host_os))
   to_7bit(comment);                    /* The advantage of NEAR memory... */
 #endif
 #if SFX_LEVEL>=ARJ
  /* This was a stub initially, and, anyway, is no longer applicable
     -- ASR 16/02/2001 */
  /* ftime_stamp=import_timestamp(ftime_stamp); */
 #endif
 #if SFX_LEVEL<=ARJSFX
  file_garbled=(arj_flags&GARBLED_FLAG)?1:0;
 #endif
 if(first!=0)
 {
  #if SFX_LEVEL>=ARJ
   if(arj_flags&GARBLED_FLAG)
    encryption_applied=1;
  #endif
  #if SFX_LEVEL>=ARJSFXV
   continued_nextvolume=(arj_flags&VOLUME_FLAG)?1:0;
  #endif
  if(arj_flags&SECURED_FLAG)
  {
   security_state=ARJSEC_SECURED;
   #if SFX_LEVEL>=ARJ
    secured_size=origsize;
   #endif
   arjsec_offset=file_crc;
  }
  #if SFX_LEVEL>=ARJSFXV
   ext_hdr_flags=ext_flags&0x0F;        /* Mask only the currently supported
                                           values */
  #endif
  if(arj_flags&DUAL_NAME_FLAG)
   dual_name=1;
  #if SFX_LEVEL>=ARJSFXV
   if(arj_flags&ANSICP_FLAG)
    ansi_codepage=1;
   #if SFX_LEVEL>=ARJ
    if(arj_flags&PROT_FLAG)
     arjprot_tail=1;
    /* Chapter-archive specific processing */
    if(first==1&&chapter_number>0)
    {
     if(add_command&&current_chapter<=CHAPTERS_MAX)
     {
      chapter_number++;
      comment_entries++;
     }
     if(!first_vol_passed)
      total_chapters=chapter_number;
     else
      chapter_number=total_chapters;
     if(total_chapters>CHAPTERS_MAX)
      error(M_TOO_MANY_CHAPTERS, CHAPTERS_MAX);
    }
   #endif
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  else
  {
   if(arj_flags&VOLUME_FLAG)
    #if SFX_LEVEL>=ARJ
     volume_flag_set=force_volume_flag=1;
    #else
     volume_flag_set=1;
    #endif
   else
    volume_flag_set=0;
  }
 #endif
 #if SFX_LEVEL>=ARJ
  if(file_type==ARJT_CHAPTER&&chapter_number>recent_chapter)
   recent_chapter=chapter_number;
  /* ARJSFX/ARJSFXV archives have some limitations, check it here */
  if(create_sfx!=SFXCRT_NONE||(sfx_desc_word!=0&&modify_command))
  {
   if(method==4)
    error(M_INVALID_METHOD_SFX);
   if(total_chapters>0)
    error(M_CHAPTER_SFX_CREATION);
   if(!multivolume_option&&file_type==ARJT_LABEL)
    error(M_NO_LABELS_IN_SFX);
   if(!win32_platform&&create_sfx&&!multivolume_option&&
      ext_hdr_flags>ENCRYPT_GOST256L)
    error(M_WRONG_ENC_VERSION, ext_hdr_flags);
   /* ARJSFXJR archives have yet more limitations that need to be checked */
   if(create_sfx==SFXCRT_SFXJR||sfx_desc_word==SFXDESC_SFXJR)
   {
#if TARGET==UNIX
    if(file_type==ARJT_TEXT)
#else
    if(file_type==ARJT_TEXT||lfn_supported!=LFN_NOT_SUPPORTED)
#endif
     error(M_TEXTMODE_LFN_SFXJR);

    #if defined(HAVE_EAS)
     if(ea_supported)
      error(M_TEXTMODE_LFN_SFXJR);
    #endif
    /* Check for systems that are hostile to ARJSFXJR */
    #if TARGET==DOS
     if(host_os!=OS)
      error(M_TEXTMODE_LFN_SFXJR);
    #elif TARGET!=UNIX
     if(!test_host_os(host_os))
      error(M_TEXTMODE_LFN_SFXJR);
    #endif
    if(arj_flags&GARBLED_FLAG)
     error(M_NO_GARBLE_IN_SFXJR);
   }
  }
 #endif
 #if SFX_LEVEL>=ARJSFXV
  /* Reset the extended header buffers for noncontinued files */
  if(!(arj_flags&EXTFILE_FLAG)&&cur_header_pos!=main_hdr_offset)
  {
   if(eh!=NULL)
   {
    eh_release(eh);
    eh=NULL;
    valid_ext_hdr=0;
   }
   ea_pwd_modifier=password_modifier;
  }
 #endif
 /* Process extended headers, if any */
 while((header_id=fget_word(stream))!=0)
 {
  #if SFX_LEVEL>=ARJSFXV
   crc32term=CRC_MASK;
   if(fread(&id, 1, 1, stream)==0)
    error(M_CANTREAD);
   crc32_for_block(&id, 1);
   valid_ext_hdr=1;
   /* Skip the extended headers if the file is continued from the previous
      volume and we haven't caught the beginning */
   if((arj_flags&EXTFILE_FLAG)&&eh==NULL)
   {
    fseek(stream, (long)header_id+3L, SEEK_CUR);
    valid_ext_hdr=0;
   }
   else
   {
    /* Perform early allocation of the extended header block */
    if(eh==NULL)
     eh=eh_alloc();
    /* Get the continuation flag */
    if(fread(&is_continued, 1, 1, stream)==0)
     error(M_CANTREAD);
    crc32_for_block(&is_continued, 1);
    /* Collect the scattered data */
    remainder=header_id-2;
    tmp_eh=eh_append(eh, id, NULL, remainder);
    dptr=tmp_eh->raw+(tmp_eh->size-remainder);
    tmp_eh->flags=is_continued?EH_PROCESSING:EH_UNPROCESSED;
    while(remainder>0)
    {
     fetch_size=min(remainder, sizeof(transfer_buf));
     if(fread(transfer_buf, 1, fetch_size, stream)!=fetch_size)
      error(M_CANTREAD);
     far_memmove(dptr, transfer_buf, fetch_size);
     crc32_for_block(transfer_buf, fetch_size);
     remainder-=fetch_size;
     dptr+=fetch_size;
    }
    if(fget_longword(stream)!=(crc32term^CRC_MASK))
    {
     if(ignore_crc_errors!=ICE_CRC)
      error(M_BAD_HEADER);
     else
     {
      eh_release(eh);
      eh=NULL;
     }
    }
   }
  #else
   fseek(stream, (long)header_id+4L, SEEK_CUR);
  #endif
 }
 return(1);
}
#if SFX_LEVEL<=ARJSFX
#undef stream
#endif

#if SFX_LEVEL>=ARJ

/* Fill general purpose header fields */

static void fill_general_hdr()
{
 arj_nbr=ARJ_VERSION;
 arj_x_nbr=ARJ_X_VERSION;
 if(file_type==ARJT_DIR)
  arj_x_nbr=ARJ_XD_VERSION;
 else if(file_type==ARJT_UXSPECIAL)
  arj_x_nbr=ARJ_XU_VERSION;
 #if TARGET==DOS
  host_os=OS;
 #else
  host_os=(dos_host==CHO_USE_DOS)?OS_DOS:OS;
 #endif
 /* If LFNs are supported, stamp Win95 or WinNT/Win32 OS code */
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
  {
   host_os=OS_WIN95;
   if(win32_platform)
    if(test_for_winnt())
     host_os=OS_WINNT;                  /* Same as OS_WIN32 */
  }
 #endif
}

/* Fills the basic header */

void create_header(int first)
{
 setup_hput(header);
 hput_byte(first_hdr_size);
 hput_byte(arj_nbr);
 hput_byte(arj_x_nbr);
 if(first&&dos_host==CHO_COMMENT)
  host_os=OS_DOS;
 hput_byte(host_os);
 hput_byte(arj_flags);
 hput_byte((char)method);
 hput_byte((char)file_type);
 hput_byte((!ts_valid(secondary_ftime))?password_modifier:0);
 if(ts_valid(secondary_ftime))
 {
  hput_longword(ts_native(&secondary_ftime, OS));
  garble_ftime=ts_native(&secondary_ftime, OS);
 }
 else
 {
  garble_ftime=ts_native(&ftime_stamp, host_os);
  hput_longword(garble_ftime);
 }
 hput_longword(compsize);
 hput_longword(origsize);
 hput_longword(file_crc);
 hput_word(entry_pos);
 hput_word(fm_native(&file_mode, host_os));
 hput_byte(ext_flags);
 hput_byte(chapter_number);
 if(first)
 {
  if(first_hdr_size>=FIRST_HDR_SIZE_V)
  {
   hput_byte((char)prot_blocks);
   hput_byte(arjprot_id);
   hput_word(0);
  }
 }
 else
 {
  if(first_hdr_size<R9_HDR_SIZE)
  {
   if(arj_flags&EXTFILE_FLAG)
    hput_longword(resume_position);
  }
  else
  {
   hput_longword(resume_position);
   hput_longword(ts_native(&atime_stamp, host_os));
   hput_longword(ts_native(&ctime_stamp, host_os));
   hput_longword(0L);
  }
 }
}

/* Walks through the extended header structure, writing the header, advancing
   the pointers and updating the flags if necessary */

static void proc_ext_hdr(unsigned int action)
{
 char transfer_buf[64];
 char FAR *dptr;
 struct ext_hdr FAR *p_eh;
 unsigned int remainder, fetch_size;
 char id, cont_id;
 long cur_capacity;
 unsigned long rem_size;

 cur_capacity=ext_hdr_capacity;
 p_eh=eh;
 while(cur_capacity>0&&(p_eh=eh_find_pending(p_eh))!=NULL)
 {
  rem_size=p_eh->size-p_eh->cur_offset;
  if((unsigned long)cur_capacity+2<=rem_size)
  {
   if(action&EHUF_COMMIT)
   {
    p_eh->flags=EH_PROCESSING;
    p_eh->cur_offset+=ext_hdr_capacity;
   }
   remainder=min(cur_capacity, rem_size);
   cont_id=1;
   cur_capacity=0;
  }
  else
  {
   if(action&EHUF_COMMIT)
    p_eh->flags=EH_FINALIZED;
   remainder=rem_size;                  /* ASR fix 15/05/2003 */
   /* Take out the ID/length/CRC32 and the data */
   cur_capacity-=rem_size+EXT_HDR_OVERHEAD;
   cont_id=0;
  }
  if(action&EHUF_WRITE)
  {
   fput_word(remainder+2, aostream);
   crc32term=CRC_MASK;
   id=p_eh->tag;
   fwrite_crc(&id, 1, aostream);
   fwrite_crc(&cont_id, 1, aostream);
   dptr=p_eh->raw+p_eh->cur_offset;
   while(remainder>0)
   {
    fetch_size=min(sizeof(transfer_buf), remainder);
    far_memmove((char FAR *)transfer_buf, dptr, fetch_size);
    fwrite_crc(transfer_buf, fetch_size, aostream);
    dptr+=fetch_size;
    remainder-=fetch_size;
   }
   fput_dword(crc32term^CRC_MASK, aostream);
  }
  p_eh=p_eh->next;
 }
 if(multivolume_option&&p_eh!=NULL&&cur_capacity<=0&&(action&EHUF_SETFLAGS))
  volume_flag_set=1;
 if(action&EHUF_COMMIT)
  ext_hdr_capacity=cur_capacity;
}

/* Writes the archive header to the aostream, calculating its CRC */

void write_header()
{
 unsigned long hdr_offset;

 hdr_offset=ftell(aostream);
 if(ts_cmp(&ftime_stamp, &ftime_max)>0&&is_file_type(file_type))
  ftime_max=ftime_stamp;
 fput_word(HEADER_ID, aostream);
 fput_word(basic_hdr_size, aostream);
 if(fflush(aostream))
  error(M_DISK_FULL);
 if(hdr_offset>last_hdr_offset)
  last_hdr_offset=hdr_offset;
 if(file_type!=ARJT_COMMENT&&chapter_number>max_chapter)
  max_chapter=chapter_number;
 crc32term=CRC_MASK;
 fwrite_crc(header, basic_hdr_size, aostream);
 fput_dword(header_crc=crc32term^CRC_MASK, aostream);
 /* Store a portion or the entire extended header */
 if(eh!=NULL&&hdr_offset!=main_hdr_offset)
  proc_ext_hdr(EHUF_WRITE|EHUF_SETFLAGS);
 fput_word(0, aostream);
}

/* Renames a file in archive. Returns 1 if a header update occured, 0 if not
   (no filename entered) */

int rename_file()
{
 msg_cprintf(H_HL|H_NFMT, M_CURRENT_FILENAME, filename);
 msg_cprintf(0, M_ENTER_NEW_FILENAME);
 read_line(filename, FILENAME_MAX);
 alltrim(filename);
 if(filename[0]=='\0')
  return(0);
 far_strcpyn(comment, (char FAR *)hdr_comment, COMMENT_MAX);
 strcpy(hdr_filename, filename);
 case_path(hdr_filename);
 entry_pos=split_name(hdr_filename, NULL, NULL);
 if(translate_path(hdr_filename))
  arj_flags|=PATHSYM_FLAG;
 else
  arj_flags&=~PATHSYM_FLAG;
 calc_comment_offset();
 far_strcpyn((char FAR *)hdr_comment, comment, COMMENT_MAX);
 create_header(0);
 calc_basic_hdr_size();
 return(1);
}

/* Reads a comment from the given file and stores it in the buffer. Supplying
   a null filename to it will strip the comment (note that null filename is
   NUL in DOS and /dev/null under UNIX) */

static void read_comment(char *buffer, char *name)
{
 FILE *stream;
 int llen;                              /* Length of last read line */

 if(!strcmp_os(buffer, dev_null))
  return;
 stream=file_open_noarch(name, m_r);
 while(fgets(buffer, COMMENT_MAX, stream)!=NULL)
 {
  if((llen=strlen(buffer))+strlen(tmp_comment)+4>=COMMENT_MAX)
   break;
  strcat(tmp_comment, buffer);
 }
 fclose(stream);
}

/* A routine to supply comments */

int supply_comment(char *cmtname, char *name)
{
 char *tmp_cmtline;
 int maxlines;
 int curline;

 tmp_cmtline=malloc_msg(COMMENT_MAX+1);
 replicate_comment();
 msg_cprintf(H_HL|H_NFMT, M_CURRENT_COMMENT, name);
 display_comment(comment);
 /* ASR enhancement -- 09/01/2001 */
 if(disable_comment_series&&first_vol_passed)
 {
  comment[0]='\0';
  calc_basic_hdr_size();
  return(1);
 }
 /* If the filename given is blank, enter the comment manually */
 if(cmtname[0]=='\0')
 {
  maxlines=MAX_COMMENT_LINES;
  msg_cprintf(H_HL|H_NFMT, M_ENTER_COMMENT, maxlines, name);
  for(curline=0; curline<maxlines; curline++)
  {
   msg_cprintf(0, (FMSG *)le_prompt, curline+1);
   read_line(tmp_cmtline, INPUT_LENGTH);
   msg_strcpy(strcpy_buf, M_COMMENT_TERMINATOR);
   if(!stricmp(strcpy_buf, tmp_cmtline))
    break;
   if(curline==0)
   {
    tmp_comment[0]='\0';
    if(tmp_cmtline[0]==listchar)
    {
     if(translate_unix_paths)
      unix_path_to_dos(tmp_cmtline+1);
     read_comment(tmp_cmtline, tmp_cmtline+1);
    }
    else
    {
     strcat(tmp_comment, tmp_cmtline);
     strcat(tmp_comment, lf);
    }
   }
   else
   {
    strcat(tmp_comment, tmp_cmtline);
    strcat(tmp_comment, lf);
   }
  }
 }
 else
 {
  tmp_comment[0]='\0';
  read_comment(tmp_cmtline, cmtname);
  curline=1;
 }
 dump_tmp_comment();
 free(tmp_cmtline);
 if(curline>0)
 {
  msg_strcpy(strcpy_buf, M_EMPTY_COMMENT);
  /* Strip blank comments */
  if(!far_strcmp(comment, (char FAR *)strcpy_buf))
   comment[0]='\0';
  far_strcpyn((char FAR *)hdr_comment, comment, COMMENT_MAX);
  calc_basic_hdr_size();
  return(1);
 }
 else
  return(0);
}

/* Fills the basic archive header with needed information */

void fill_archive_header()
{
 first_hdr_size=FIRST_HDR_SIZE_V;
 cur_time_stamp(&ftime_stamp);
 compsize=ts_native(&ftime_stamp, host_os);
 if(ts_valid(secondary_ftime))
  compsize=ts_native(&secondary_ftime, host_os);
 file_type=ARJT_COMMENT;
 method=0;
 entry_pos=0;
 origsize=0L;
 file_crc=0L;
 fm_store(&file_mode, OS_DOS, 0);
 host_data=0;
 ext_flags=0;
 chapter_number=0;
 if(chapter_mode!=0)
 {
  if(total_chapters==0)
   chapter_number=total_chapters=1;
  else
   chapter_number=total_chapters;
 }
 else
 {
  if(total_chapters!=0)
   chapter_number=total_chapters;
 }
 arj_flags=0;
 if(multivolume_option)
  arj_flags|=VOLUME_FLAG;
 if(add_command&&lfn_supported!=LFN_NOT_SUPPORTED&&(lfn_mode==LFN_DUAL_EXT||lfn_mode==LFN_DUAL))
  arj_flags|=DUAL_NAME_FLAG;
 if(add_command&&use_ansi_cp)
  arj_flags|=ANSICP_FLAG;
 arjprot_id=use_sfxstub?SFXSTUB_FLAG:0;
 password_modifier=(char)ts_native(&ftime_stamp, OS_SPECIAL);
 ext_hdr_flags=0;
 if(garble_enabled)
 {
  arj_flags|=GARBLED_FLAG;
  encryption_applied=1;
  ext_hdr_flags=ENCRYPT_STD;
  if(gost_cipher==GOST256)
   ext_hdr_flags=ENCRYPT_UNK;
  else if(gost_cipher==GOST40)
   ext_hdr_flags=ENCRYPT_GOST40;
 }
 hdr_filename=&header[first_hdr_size];
 split_name(archive_name, NULL, hdr_filename);
 if(translate_path(hdr_filename))
  arj_flags|=PATHSYM_FLAG;
 calc_comment_offset();
 hdr_comment[0]='\0';
 fill_general_hdr();
 create_header(1);
 calc_basic_hdr_size();
}

/* Final header pass: occurs at update of multivolume archives and those
   containing ARJ SECURITY. The operation variable specifies the action
   (one of FP_*) to be made. */

void final_header(int operation)
{
 unsigned long tmp_resume_position;
 int tmp_multivolume;                   /* Indicates that the file is continued
                                           on the next volume */
 int tmp_cont_prev;                     /* Indicates that the file is continued
                                           from the previous volume */
 unsigned long cur_pos;
 int cur_ext_hdr_flags;
 int tmp_prot_blocks;

 tmp_prot_blocks=prot_blocks;
 tmp_resume_position=resume_position;
 tmp_cont_prev=continued_prevvolume;
 tmp_multivolume=mvfile_type;
 cur_ext_hdr_flags=ext_hdr_flags;
 cur_pos=ftell(aostream);
 fseek(aostream, main_hdr_offset, SEEK_SET);
 read_header(2, aostream, archive_name);
 fseek(aostream, main_hdr_offset, SEEK_SET);
 if(operation==FP_SECURITY&&is_registered)
 {
  origsize=secured_size;
  file_crc=arjsec_offset;
  arj_flags|=SECURED_FLAG;
  method=2;
  fm_store(&file_mode, OS_SPECIAL, SECURED_MODE);
 }
 else if(operation==FP_PROT)
 {
  arj_flags|=PROT_FLAG;
  prot_blocks=tmp_prot_blocks;
  /* ASR fix - the original (v 3.02) checks for ==0 only */
  if(file_crc==0L||file_crc>arjsec_offset||(arjsec_offset-file_crc)>=CACHE_SIZE)
   file_crc=arjsec_offset;
 }
 else if(operation==FP_VOLUME)
  arj_flags&=~VOLUME_FLAG;
 else if(operation==FP_CHAPTER)
  chapter_number=max_chapter;
 else if(operation==FP_GARBLE)
 {
  arj_flags|=GARBLED_FLAG;
  ext_flags=(ext_flags&0xF0)|(cur_ext_hdr_flags&0x0F);
 }
 create_header(1);
 write_header();
 fseek(aostream, cur_pos, SEEK_SET);
 prot_blocks=tmp_prot_blocks;
 resume_position=tmp_resume_position;
 continued_prevvolume=tmp_cont_prev;
 mvfile_type=tmp_multivolume;
 comment[0]='\0';                       /* ASR fix - the original is somewhere
                                           else */
}

#endif

/* Skips over the compressed data in the input file */

void skip_compdata()
{
 #if SFX_LEVEL>=ARJSFXV
  if(compsize!=0L)
   file_seek(aistream, compsize, SEEK_CUR);
 #else
  fseek(aistream, compsize, SEEK_CUR);
 #endif
}

/* Skips over the compressed data, prompting the user */

void skip_file()
{
 #if SFX_LEVEL>=ARJSFXV
  msg_cprintf(H_HL|H_NFMT, M_SKIPPED, filename);
 #else
  msg_cprintf(H_HL|H_NFMT, M_SKIPPED, filename);
 #endif
 skip_compdata();
}

/* Displays ARJ$DISP screen */

void arjdisp_scrn(unsigned long bytes)
{
 char *arjdisp_name;
 #if SFX_LEVEL<=ARJSFX
  char cmd_buf[CCHMAXPATH];
 #endif

 #if SFX_LEVEL>=ARJSFXV
 ctrlc_not_busy=0;
 arjdisp_name=arjdisp_ptr;
 if(arjdisp_name[0]=='\0')
  arjdisp_name=arjdisp_default;
 #else
  arjdisp_name=arjdisp_default;
 #endif
 if(strcmp_os(filename, arjdisp_name))
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_sprintf(misc_buf, M_ARJDISP_INVOCATION, arjdisp_name, archive_name, filename, uncompsize, bytes, compsize, cmd_verb);
   system_cmd(misc_buf);
  #else
   msg_sprintf(cmd_buf, M_ARJDISP_INVOCATION, arjdisp_name, archive_name, filename, uncompsize, bytes, compsize, cmd_verb);
   system_cmd(cmd_buf);
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
 ctrlc_not_busy=1;
 #endif
}

#if SFX_LEVEL>=ARJ

/* Returns CRC-32 ofthe given file */

static unsigned long crc32_for_file(char *name)
{
 FILE *stream;
 char *buffer;
 int block_size;

 crc32term=CRC_MASK;
 if((stream=file_open(name, m_rb))!=NULL)
 {
  buffer=malloc_msg(CACHE_SIZE);
  while((block_size=fread(buffer, 1, CACHE_SIZE, stream))!=0)
   crc32_for_block(buffer, block_size);
  free(buffer);
  fclose(stream);
 }
 return(crc32term^CRC_MASK);
}

/* Issues various actions on currently processed file in archive */

void special_processing(int action, FILE *stream)
{
 int garble_task;
 struct timestamp gtime;
 char *pbuf;
 unsigned long cur_pos;
 int count;
 char *tmp_name;

 garble_task=0;                         /* Initally, no garble post-processing
                                           is considered. */
 switch(action)
 {
  case CFA_UNMARK:
   msg_cprintf(H_HL|H_NFMT, M_UNMARKING, filename);
   if((int)chapter_number!=total_chapters)
    error(M_CHAPTER_ERROR, 1);
   chapter_number--;
   create_header(0);
   break;
  case CFA_MARK:
   msg_cprintf(H_HL|H_NFMT, M_MARKING, filename);
   if((int)chapter_number!=total_chapters)
    error(M_CHAPTER_ERROR, 1);
   ext_flags=(unsigned char)total_chapters;
   create_header(0);
   break;
  case CFA_MARK_INCREMENT:
   msg_cprintf(H_HL|H_NFMT, M_MARKING, filename);
   if((int)chapter_number+1!=total_chapters)
    error(M_CHAPTER_ERROR, 1);
   chapter_number=(unsigned char)total_chapters;
   create_header(0);
   total_files++;
   if(host_os==OS_WIN95||host_os==OS_WINNT)
   {
    total_longnames++;
    if(volume_flag_set)
     split_longnames++;
   }
   break;
  case CFA_REMPATH:
   msg_cprintf(H_HL|H_NFMT, M_REMOVING_PATH, filename);
   far_strcpyn(comment, (char FAR *)hdr_comment, COMMENT_MAX);
   tmp_name=malloc_str(hdr_filename);
   split_name(tmp_name, NULL, hdr_filename);
   free(tmp_name);
   entry_pos=0;
   arj_flags&=~PATHSYM_FLAG;
   calc_comment_offset();
   far_strcpyn((char FAR *)hdr_comment, comment, COMMENT_MAX);
   if(dual_name)
   {
    tmp_name=malloc_str(hdr_comment);
    split_name(tmp_name, NULL, hdr_comment);
    free(tmp_name);
   }
   create_header(0);
   calc_basic_hdr_size();
   total_files++;
   break;
  case CFA_MARK_EXT:
   msg_cprintf(H_HL|H_NFMT, M_MARKING, filename);
   if(ext_flags==0)
    ext_flags=(unsigned char)total_chapters;
   if(chapter_number==0)
    chapter_number=(unsigned char)total_chapters;
   create_header(0);
   total_files++;
   break;
  case CFA_UNMARK_EXT:
   msg_cprintf(H_HL|H_NFMT, M_UNMARKING, filename);
   ext_flags=0;
   chapter_number=0;
   create_header(0);
   total_files++;
   break;
  case CFA_GARBLE:
   if(!(arj_flags&GARBLED_FLAG))
   {
    msg_cprintf(H_HL|H_NFMT, M_GARBLING, filename);
    arj_flags|=GARBLED_FLAG;
    cur_time_stamp(&gtime);
    password_modifier=ts_native(&gtime, OS);
    garble_task=1;
    create_header(0);
    total_files++;
   }
   break;
  case CFA_UNGARBLE:
   if(arj_flags&GARBLED_FLAG)
   {
    msg_cprintf(H_HL|H_NFMT, M_UNGARBLING, filename);
    arj_flags&=~GARBLED_FLAG;
    garble_task=2;
    create_header(0);
    total_files++;
   }
   break;
 }
 if(arj_flags&GARBLED_FLAG)
  encryption_id=ENCID_GARBLE;
 write_header();
 if(garble_task)
  garble_init(password_modifier);
 pbuf=(char *)malloc_msg(PROC_BLOCK_SIZE);
 cur_pos=ftell(stream);
 count=min(CACHE_SIZE-(cur_pos%CACHE_SIZE), compsize);
 while(compsize>0L)
 {
  if(fread(pbuf, 1, count, stream)!=count)
   error(M_CANTREAD);
  if(garble_task==1)
   garble_encode_stub(pbuf, count);
  else if(garble_task==2)
   garble_decode_stub(pbuf, count);
  if(!no_file_activity)
   file_write(pbuf, 1, count, aostream);
  compsize-=(unsigned long)count;
  count=min(PROC_BLOCK_SIZE, compsize);
 }
 free(pbuf);
}

/* Prints an "Adding..." message */

static void addition_msg(int is_update, int is_replace, char *filespec)
{
 /* -hdx will turn off these messages */
 if(!debug_enabled||strchr(debug_opt, 'x')==NULL)
 {
  if(is_update)
   msg_cprintf(H_HL, M_UPDATING);
  else if(is_replace)
   msg_cprintf(H_HL, M_REPLACING);
  else
   msg_cprintf(H_HL, M_ADDING);
  if(verbose_display==VERBOSE_STD)
  {
   if(file_type==ARJT_BINARY)
    msg_cprintf(0, M_BINARY_FILE);
   else if(file_type==ARJT_TEXT)
    msg_cprintf(0, M_TEXT_FILE);
   else if(file_type==ARJT_DIR)
    msg_cprintf(0, M_DIRECTORY);
   else if(file_type==ARJT_UXSPECIAL)
    msg_cprintf(0, M_UXSPECIAL_FILE);
  }
  if(continued_prevvolume&&eh_find_pending(eh)==NULL)
   msg_cprintf(H_HL|H_NFMT, M_AT_POSITION, format_filename(filespec), resume_position);
  else
   msg_cprintf(0, (FMSG *)strform, format_filename(filespec));
  if(!verbose_display)
   msg_cprintf(0, (FMSG *)vd_space);
  else
  {
   nputlf();
   if(method==0)
    msg_cprintf(0, M_STORING);
   else
    msg_cprintf(H_HL|H_NFMT, M_COMPRESSING, method);
   msg_cprintf(H_HL|H_NFMT, M_N_BYTES, uncompsize);
  }
 }
}

/* Initializes global variables and performs general set-up before packing a
   file. */

void init_packing(unsigned long offset, int is_mv)
{
 unpackable=0;
 volume_flag_set=0;
 ext_voldata=0;
 compsize=origsize=0L;
 if(garble_enabled)
  garble_init(password_modifier);
 crc32term=CRC_MASK;
 if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
 {
  if(!is_mv||resume_position>0)
   smart_seek(resume_position, encstream);
 }
 if(!is_mv&!no_file_activity)
  fseek(aostream, offset, SEEK_SET);
}

/* Stores or compresses a single file */

static void pack_file_proc(unsigned long offset)
{
 if(method==1||method==2||method==3)
  encode_stub(method);
 else if(method==4)
  encode_f_stub();
 else if(method==9)
  hollow_encode();
 if(unpackable)                         /* Fall back to method #0 */
 {
  if(verbose_display==VERBOSE_STD)
  {
   msg_cprintf(0, (FMSG *)"       \r");
   msg_cprintf(0, M_STORING);
   msg_cprintf(H_HL|H_NFMT, M_N_BYTES, uncompsize);
  }
  method=0;
  init_packing(offset, 0);
 }
 if(method==0)
  store();
 display_indicator(uncompsize);
}

/* Opens the file for encoding */

static int open_input_file()
{
 int e;                                 /* Error indicator */

 if((encstream=file_open(filename, read_perms[file_type%2]))!=NULL)
  return(0);
 error_report();
 msg_cprintf(H_ERR, M_CANTOPEN, filename);
 nputlf();
 e=1;
 if(no_inarch)
 {
  if((ignore_open_errors==IAE_ACCESS&&errno==EACCES)||
     (ignore_open_errors==IAE_NOTFOUND&&errno==ENOENT)||
     (ignore_open_errors==IAE_ALL&&(errno==EACCES||errno==ENOENT)))
  e=0;
 }
 if(e)
  errors++;
 write_index_entry(idxid_fault);
 return(1);
}

/* Packs a single file, involving all neccessary checks. Returns 1 if it got
   packed, 0 if not, -1 in case of an error. */

int pack_file(int is_update, int is_replace)
{
 struct timestamp ftime, atime, ctime, cur_time;
 unsigned long fsize;
 int volume_file;                       /* 1 if file spans across volumes */
 int needs_skip;                        /* 1 if the file needs to be skipped */
 int err_id;
 ATTRIB attrib;
 int fb;
 unsigned int total_chars, nd_chars;
 int textf=0;                           /* 1 if the file seems to be text */
 int fetch_size;
 unsigned long cur_pos=0;               /* Current position in output file */
 int lfn;
 unsigned long data_pos=0;
 unsigned long st_ticks=0;              /* Start time (used for profiling) */
 unsigned int bck_method;
 int ratio;
 char timetext[20];
 char FAR *raw_eh;
 struct mempack mempack;
 int lfn_xlated;
 char ea_res[FILENAME_MAX];
 int res_len=0;
 char FAR *ea_blk;
 struct ext_hdr FAR *p_eh;

 if(is_replace&&new_files_only)
  return(0);
 if(!match_attrib(&properties))
 {
  error(M_SELECTION_ERROR);
  return(-1);
 }
 ts_store(&ftime, OS, properties.ftime);
 ts_store(&atime, OS, properties.atime);
 ts_store(&ctime, OS, properties.ctime);
 if(is_update&&!skip_ts_check)
 {
  fsize=properties.fsize;
  volume_file=arj_flags&VOLUME_FLAG||arj_flags&EXTFILE_FLAG;
  needs_skip=0;
  if(update_criteria==UC_NEW_OR_CRC||freshen_criteria==FC_CRC)
  {
   if(!volume_file&&fsize==origsize)
   {
    if(crc32_for_file(filename)==file_crc)
     needs_skip=1;
   }
  }
  else if(update_criteria==UC_NEW_OR_DIFFERENT||freshen_criteria==FC_DIFFERENT)
  {
   if(!volume_file&&!ts_cmp(&ftime_stamp, &ftime)&&fsize==origsize)
    needs_skip=1;
  }
  else if(update_criteria==UC_NEW_OR_OLDER||freshen_criteria==FC_OLDER)
  {
   if(ts_cmp(&ftime, &ftime_stamp)>=0)
    needs_skip=1;
  }
  else if(update_criteria==UC_NEW_OR_NEWER||freshen_criteria==FC_EXISTING)
  {
   if(ts_cmp(&ftime, &ftime_stamp)<=0)
    needs_skip=1;
  }
  if(needs_skip)
  {
   if(verbose_display)
   {
    msg_cprintf(H_HL|H_NFMT, M_NO_CHANGE, format_filename(filename));
   }
   special_processing((total_chapters!=0)?CFA_MARK_INCREMENT:CFA_NONE, aistream);
   return(1);
  }
 }
 if(query_for_each_file)
 {
  msg_sprintf(misc_buf, is_update?M_QUERY_UPDATE:M_QUERY_ADD, filename);
  if(!query_action(REPLY_YES, QUERY_ARCH_OP, (char FAR *)misc_buf))
   return(0);
 }
 if(is_replace)
 {
  if(total_chapters>0)
   special_processing(CFA_NONE, aistream);
  else
   skip_compdata();
  if(multivolume_option)
  {
   total_files++;
   return(2);
  }
 }
 else
 {
  file_type=ARJT_BINARY;
  first_hdr_size=continued_prevvolume?FIRST_HDR_SIZE_V:STD_HDR_SIZE;
  if(lfn_supported!=LFN_NOT_SUPPORTED&&!skip_time_attrs)
   first_hdr_size=R9_HDR_SIZE;
  hdr_filename=&header[first_hdr_size];
  hdr_filename[0]='\0';
  calc_comment_offset();
  hdr_comment[0]='\0';
 }
 method=custom_method?method_specifier:1;
 uncompsize=properties.fsize;
 attrib=properties.attrib;
 if(clear_archive_bit)
  attrib&=~FATTR_RDONLY;
 garble_ftime=ts_native(&ftime, OS);
 if(type_override)
 {
  file_type=primary_file_type;
  if(*swptr_t!='\0')
   if(search_for_extension(filename, swptr_t))
    file_type=secondary_file_type;
 }
 if(continued_prevvolume&&mvfile_type>=0)
  file_type=mvfile_type;
 if(!is_filename_valid(filename))
  error(M_CANTOPEN, filename);
 if(properties.type==ARJT_DIR)
  file_type=ARJT_DIR;
 else if(properties.type==ARJT_UXSPECIAL)
  file_type=ARJT_UXSPECIAL;
 volume_flag_set=0;
 user_wants_fail=0;
 err_id=0;
 if(hollow_mode!=HM_NO_CRC)
 {
  if(file_type==ARJT_DIR||file_type==ARJT_UXSPECIAL)
   method=0;
  else if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
  {
   if(open_input_file())
    return(0);
   current_bufsiz=jh_enabled?user_bufsiz:BUFSIZ_DEFAULT;
   if(file_type==ARJT_TEXT)
   {
    nd_chars=0;
    textf=1;
    fetch_size=CACHE_SIZE;
    total_chars=0;
    while((fb=fgetc(encstream))!=EOF)
    {
     if(fb<TEXT_LCHAR||fb>TEXT_UCHAR)
      nd_chars++;
     total_chars++;
     if(total_chars>=fetch_size)
      break;
    }
    if(total_chars>0)
     rewind(encstream);
    /* Select files that meet size requirements... */
    if(type_override<FT_TEXT_FORCED&&uncompsize>=(unsigned long)MIN_TEXT_SIZE&&
       total_chars<fetch_size&&(unsigned long)total_chars*5L<uncompsize*4L)
     textf=0;
    /* ...or meet character composition requirements */
    if(type_override<FT_TEXT_FORCED&&total_chars/5<=nd_chars)
     textf=0;
    if((type_override==FT_BINARY||type_override==FT_TEXT_FORCED)&&nd_chars!=0)
     textf=0;
   }
   if(file_type==ARJT_TEXT&&type_override!=FT_NO_OVERRIDE&&resume_position==0L)
   {
    if(!textf)
     file_type=ARJT_BINARY;
    if(file_type==ARJT_BINARY)
    {
     file_close(encstream);
     encstream=NULL;
     if(open_input_file())
      return(0);
    }
   }
   if(uncompsize>0L)
    uncompsize-=resume_position;
  }
 }
 if(store_by_suffix)
  if(search_for_extension(filename, archive_suffixes))
   method=0;
 if(properties.fsize==0L)
  method=0;
 if(hollow_mode==HM_CRC)
  method=9;
 else if(hollow_mode==HM_NO_CRC)
  method=8;
 if(!no_file_activity)
  cur_pos=ftell(aostream);
 cur_time_stamp(&cur_time);
 password_modifier=(char)ts_native(&cur_time, OS);
 arj_flags=0;
 far_strcpyn(comment, (char FAR *)hdr_comment, COMMENT_MAX);
 if(continued_prevvolume&&first_hdr_size<FIRST_HDR_SIZE_V)
 {
  first_hdr_size=FIRST_HDR_SIZE_V;
  hdr_filename=&header[first_hdr_size];
 }
 if(fix_longnames)
 {
  res_len=(exclude_paths==EP_BASEDIR&&resolve_longname(ea_res, target_dir))?
          strlen(ea_res):strlen(target_dir);
  lfn_xlated=resolve_longname(ea_res, filename);
 }
 else
 {
  res_len=strlen(target_dir);
  lfn_xlated=0;
 }
 if(exclude_paths==EP_BASEDIR)
  default_case_path(hdr_filename, (lfn_xlated?ea_res:filename)+res_len);
 else if(exclude_paths==EP_PATH)
  split_name(lfn_xlated?ea_res:filename, NULL, hdr_filename);
 else
  default_case_path(hdr_filename, lfn_xlated?ea_res:filename);
 /* Collect data for extended headers: EAs and maybe more */
 if(!continued_prevvolume)
 {
  /* Flush headers from the previous file */
  if(eh!=NULL)
   eh_release(eh);
  eh=eh_alloc();
  /* For the UNIX special files, collect and store their properties */
  if(file_type==ARJT_UXSPECIAL)
  {
   if(query_uxspecial(&raw_eh, filename, &properties))
   {
    msg_cprintf(H_ERR, M_CANT_QUERY_UXSPEC);
    return(0);
   }
   eh_append(eh, UXSPECIAL_ID, raw_eh, get_uxspecial_size(raw_eh));
   farfree(raw_eh);
  }
  /* Query the file owner */
  if(do_chown&&!query_owner(&raw_eh, filename, do_chown))
  {
   eh_append(eh, (do_chown==OWNSTG_ID)?OWNER_ID_NUM:OWNER_ID, raw_eh, get_owner_size(raw_eh));
   farfree(raw_eh);
  }
  /* Pick extended attributes, if any */
  if(ea_supported&&!hollow_mode)
  {
   ea_size=0;
   if(query_ea(&raw_eh, filename, lfn_xlated))
    return(0);
   if(get_num_eas(raw_eh)==0)
    farfree(raw_eh);
   else
   {
    ea_size=get_eablk_size(raw_eh);
    ea_blk=(char FAR *)farmalloc_msg(ea_size+3+MEMPACK_OVERHEAD);
    mempack.comp=ea_blk+3;
    mempack.orig=raw_eh;
    mempack.origsize=ea_size;
    ea_blk[1]=(unsigned char)(ea_size%256U);
    ea_blk[2]=(unsigned char)(ea_size/256U);
    mempack.method=custom_method?method_specifier:1;
    pack_mem(&mempack);
    ea_blk[0]=(char)mempack.method;
    farfree(raw_eh);
    eh_append(eh, EA_ID, ea_blk, mempack.compsize+3);
    farfree(ea_blk);
   }
  }
 }
 /* Prepare for flushing the extended headers */
 if(eh!=NULL)
 {
  ext_hdr_capacity=multivolume_option?get_volfree(LONG_MAX):LONG_MAX;
  if(ext_hdr_capacity==0)
   ext_hdr_capacity=1;
 }
 entry_pos=split_name(hdr_filename, NULL, NULL);
 if(translate_path(hdr_filename))
  arj_flags|=PATHSYM_FLAG;
 calc_comment_offset();
 far_strcpyn((char FAR *)hdr_comment, comment, COMMENT_MAX);
 lfn=0;
 #if TARGET==DOS
  if(lfn_supported==LFN_SUPPORTED&&dual_name)
  {
   far_strcpyn(comment, (char FAR *)hdr_filename, FILENAME_MAX);
   get_canonical_shortname(hdr_comment+FILENAME_MAX, filename);
   if(exclude_paths==EP_PATH)
    split_name(hdr_comment+FILENAME_MAX, NULL, hdr_filename);
   else
    default_case_path(hdr_filename, hdr_comment+FILENAME_MAX);
   calc_comment_offset();
   far_strcpyn((char FAR *)hdr_comment, comment, FILENAME_MAX);
   entry_pos=split_name(hdr_filename, NULL, NULL);
   if(translate_path(hdr_filename))
    arj_flags|=PATHSYM_FLAG;
  }
  else if(lfn_supported==LFN_COMP&&dual_name)
  {
   get_canonical_longname(hdr_comment+FILENAME_MAX, filename);
   if(!file_exists(hdr_comment+FILENAME_MAX))
   {
    errors++;
    error_report();
    msg_cprintf(H_ERR, M_CANTOPEN, hdr_comment+FILENAME_MAX);
    nputlf();
    write_index_entry(idxid_fault);
    return(0);
   }
   if(exclude_paths==EP_PATH)
    split_name(hdr_comment+FILENAME_MAX, NULL, hdr_comment);
   else
    default_case_path(hdr_comment, hdr_comment+FILENAME_MAX);
  }
  if(lfn_supported==LFN_SUPPORTED&&lfn_mode!=LFN_ALL)
  {
   if(win32_platform)
   {
    get_canonical_shortname(hdr_comment, filename);
    if(!strcmp(filename, hdr_comment))
     lfn=1;
   }
   else
   {
    get_canonical_longname(hdr_comment, filename);
    get_canonical_shortname(hdr_comment+FILENAME_MAX, filename);
    if(!strcmp(hdr_comment+FILENAME_MAX, hdr_comment))
     lfn=1;
   }
   far_strcpyn((char FAR *)hdr_comment, comment, FILENAME_MAX);
  }
 #endif
 calc_basic_hdr_size();
 if(garble_enabled)
  arj_flags|=GARBLED_FLAG;
 if(continued_prevvolume)
  arj_flags|=EXTFILE_FLAG;
 write_header();
 if(!no_file_activity)
  data_pos=ftell(aostream);
 addition_msg(is_update, is_replace, lfn_xlated?ea_res:filename);
 init_packing(data_pos, 1);
 if(debug_enabled&&strchr(debug_opt, 't')!=NULL)
  st_ticks=get_ticks();
 if(method==8)
 {
  compsize=0L;
  crc32term=CRC_MASK;
  origsize=properties.fsize;
 }
 else if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
 {
  if(file_type==ARJT_TEXT)
  {
   bck_method=method;
   pack_file_proc(data_pos);
   if(type_override<FT_TEXT_FORCED&&uncompsize>=MIN_TEXT_SIZE&&origsize*5L<uncompsize*4L)
   {
    msg_cprintf(H_HL|H_NFMT, M_REARCHIVING, filename);
    file_type=ARJT_BINARY;
    file_close(encstream);
    encstream=0L;
    if(open_input_file())
     return(0);
    method=bck_method;
    addition_msg(is_update, is_replace, lfn_xlated?ea_res:filename);
    init_packing(data_pos, 0);
   }
  }
  if(file_type==ARJT_BINARY)
   pack_file_proc(data_pos);
 }
 if(eh!=NULL)
  proc_ext_hdr(EHUF_SETFLAGS);
 if(verbose_display==VERBOSE_STD)
  msg_cprintf(H_HL|H_NFMT, M_N_BYTES, compsize);
 if(debug_enabled&&strchr(debug_opt, 't')!=NULL)
  msg_cprintf(H_HL|H_NFMT, M_N_TICKS, st_ticks=get_ticks()-st_ticks);
 if(method!=8&&(file_type==ARJT_BINARY||file_type==ARJT_TEXT))
 {
  if(ferror(encstream))
  {
   err_id=1;
   errors++;
   nputlf();
   error_report();
   msg_cprintf(H_ERR, M_CANTREAD);
   nputlf();
   write_index_entry(idxid_fault);
  }
  else
   fclose(encstream);
 }
 encstream=NULL;
 if(!no_file_activity)
  data_pos=ftell(aostream);
 file_crc=crc32term^CRC_MASK;
 if(volume_flag_set)
  arj_flags|=VOLUME_FLAG;
 fm_store(&file_mode, host_os, (unsigned int)attrib);
 ftime_stamp=ftime;
 atime_stamp=atime;
 ctime_stamp=ctime;
 host_data=0;
 ext_flags=chapter_number=total_chapters;
 fill_general_hdr();
 #if TARGET==DOS
  if(dual_name||lfn)
  {
   host_os=OS;
   strupper(filename);
   strupper(hdr_filename);
  }
 #endif
 if(lowercase_names)
  strlower(hdr_filename);
 create_header(0);
 if(!no_file_activity)
  fseek(aostream, cur_pos, SEEK_SET);
 far_strcpy(tmp_filename, (char FAR *)filename);
 if(whole_files_in_mv&&volume_flag_set&&total_files>0)
 {
  if(!no_file_activity)
   file_chsize(aostream, cur_pos);
  msg_cprintf(H_HL, M_FSTAT_1);
  comment_entries++;
  origsize=0L;
  resume_position=0L;
  continued_prevvolume=0;
  return(1);
 }
 write_header();
 if(!no_file_activity)
  fseek(aostream, data_pos, SEEK_SET);
 if(volume_flag_set)
 {
  resume_position+=origsize;
  continued_prevvolume=1;
  mvfile_type=file_type;
 }
 else
 {
  resume_position=0L;
  continued_prevvolume=0;
 }
 total_uncompressed+=origsize;
 total_compressed+=compsize;
 ratio=calc_percentage(compsize, origsize);
 if(!debug_enabled||strchr(debug_opt, 'x')==NULL)
 {
  msg_cprintf(H_HL, M_FSTAT_2, ratio/10, ratio%10);
  #if defined(HAVE_EAS)
   if(ea_supported&&!volume_flag_set&&ea_size!=0)
    msg_cprintf(H_HL, M_EA_STATS_STG, ea_size);
  #endif
  if(file_type==ARJT_UXSPECIAL&&eh_lookup(eh, UXSPECIAL_ID)!=NULL)
  {
   raw_eh=eh_lookup(eh, UXSPECIAL_ID)->raw;
   uxspecial_stats(raw_eh, UXSTATS_SHORT);
  }
  msg_cprintf(0, lf);
 }
 if(err_id==0&&user_wants_fail)
 {
  errors++;
  error_report();
  write_index_entry(idxid_fault);
 }
 if(create_index)
 {
  if(detailed_index)
  {
   timestamp_to_str(timetext, &ftime_stamp);
   if(msg_fprintf(idxstream, M_IDX_FIELD, timetext, origsize, compsize, ratio/1000, ratio%1000, filename)<0)
    error(M_DISK_FULL);
  }
  else
  {
   if(msg_fprintf(idxstream, M_FILENAME_FORM, filename)<0)
    error(M_DISK_FULL);
  }
 }
 total_files++;
 if(host_os==OS_WIN95||host_os==OS_WINNT)
  total_longnames++;
 if(eh!=NULL)
  proc_ext_hdr(EHUF_COMMIT);
 return(1);
}

/* Packs a file, with statistics update */

int pack_file_stub(int is_update, int is_replace)
{
 int rc;

 rc=pack_file(is_update, is_replace);
 if(rc==1)
  total_written+=origsize;
 else 
 {
  total_size-=origsize;  
  if(rc==-1)
   rc=0;
 }
 return(rc);
}

/* Inserts a chapter mark into the archive */

int create_chapter_mark()
{
 if(multivolume_option&&get_volfree(MULTIVOLUME_INCREMENT)<MULTIVOLUME_INCREMENT)
 {
  volume_flag_set=1;
  comment_entries++;
  return(1);
 }
 file_type=5;
 msg_sprintf(filename, M_CHAPMARK_FORMAT, total_chapters);
 first_hdr_size=FIRST_HDR_SIZE;
 hdr_filename=&header[first_hdr_size];
 far_strcpyn((char FAR *)hdr_filename, (char FAR *)filename, FILENAME_MAX);
 calc_comment_offset();
 hdr_comment[0]='\0';
 msg_cprintf(H_HL, M_ADDING);
 if(verbose_display==VERBOSE_STD)
  msg_cprintf(0, M_CHAPTER);
 msg_cprintf(H_HL|H_NFMT, M_LIST_FORM, format_filename(filename));
 calc_basic_hdr_size();
 arj_flags=0;
 entry_pos=0;
 cur_time_stamp(&ftime_stamp);
 password_modifier=(char)ts_native(&ftime_stamp, OS);
 compsize=origsize=0L;
 volume_flag_set=0;
 file_crc=0L;
 fm_store(&file_mode, OS_DOS, 0);
 host_data=0;
 if(eh!=NULL)
 {
  eh_release(eh);
  eh=NULL;
 }
 ext_flags=chapter_number=total_chapters;
 fill_general_hdr();
 create_header(0);
 write_header();
 write_index_entry(nullstr);
 msg_cprintf(H_HL, M_NO_RATIO);
 total_files++;
 return(1);
}

/* Stores volume label in the archive */

#ifdef HAVE_VOL_LABELS
int store_label()
{
 ATTRIB tmp_attr;
 unsigned long vftime_native;
 
 fm_store(&file_mode, OS_DOS, 0);
 if(file_getlabel(filename, label_drive, (ATTRIB *)&tmp_attr, &vftime_native))
 {
  msg_cprintf(H_ERR, M_CANT_QUERY_LABEL);
  errors++;
  write_index_entry(idxid_fault);
  return(0);
 }
 ts_store(&ftime_stamp, OS, vftime_native);
 fm_store(&file_mode, host_os, tmp_attr);
 if(filename[0]=='\0')
  return(0);
 if(multivolume_option&&get_volfree(MULTIVOLUME_INCREMENT)<MULTIVOLUME_INCREMENT)
 {
  volume_flag_set=1;
  comment_entries++;
  return(1);
 }
 file_type=ARJT_LABEL;
 first_hdr_size=FIRST_HDR_SIZE;
 hdr_filename=&header[first_hdr_size];
 far_strcpyn((char FAR *)hdr_filename, (char FAR *)filename, FILENAME_MAX);
 calc_comment_offset();
 hdr_comment[0]='\0';
 msg_cprintf(H_HL, M_ADDING);
 if(verbose_display==VERBOSE_STD)
  msg_cprintf(0, M_LABEL_FILE);
 msg_cprintf(H_HL|H_NFMT, M_LIST_FORM, format_filename(filename));
 calc_basic_hdr_size();
 arj_flags=0;
 entry_pos=0;
 password_modifier=0;
 compsize=origsize=0L;
 volume_flag_set=0;
 file_crc=0L;
 host_data=0;
 ext_flags=chapter_number=total_chapters;
 if(eh!=NULL)
 {
  eh_release(eh);
  eh=NULL;
 }
 fill_general_hdr();
 create_header(0);
 write_header();
 write_index_entry(nullstr);
 msg_cprintf(H_HL, M_NO_RATIO);
 total_files++;
 return(1);
}
#endif

/* Joins an archive to another archive */

FILE_COUNT copy_archive()
{
 char name[FILENAME_MAX];
 FILE_COUNT rc;                       	/* (returned) File count */
 FILE_COUNT i;
 FILE *arc;
 char enc_type;

 rc=0;
 for(i=0; i<flist_main.files; i++)
 {
  flist_retrieve(name, NULL, &flist_main, i);
  arc=file_open_noarch(name, m_rb);
  msg_cprintf(H_HL|H_NFMT, M_PROCESSING_ARCHIVE, name);
  if(find_header(0, arc)<0L)
  {
   msg_cprintf(H_HL|H_NFMT, M_NOT_ARJ_ARCHIVE, name);
   nputlf();
   errors++;
   cfa_store(i, FLFLAG_SKIPPED);
  }
  else
  {
   read_header(0, arc, name);
   if((arj_flags&DUAL_NAME_FLAG&&!dual_name)||(!(arj_flags&DUAL_NAME_FLAG)&&dual_name))
    error(M_CANT_COMBINE_DUAL);
   if((arj_flags&ANSICP_FLAG&&!ansi_codepage)||(!(arj_flags&ANSICP_FLAG)&&ansi_codepage))
    error(M_ARCHIVE_CP_MISMATCH);
   enc_type=ext_flags&0x0F;
   if(ext_hdr_flags!=ENCRYPT_OLD&&enc_type!=ENCRYPT_OLD&&ext_hdr_flags!=enc_type)
    error(M_WRONG_ENC_VERSION, (int)enc_type);
   if(arj_nbr>=ARJ_NEWCRYPT_VERSION&&ext_hdr_flags==0&&enc_type!=ENCRYPT_OLD)
   {
    encryption_id=ENCID_GARBLE;
    ext_hdr_flags=enc_type;
   }
   while(read_header(0, arc, name))
   {
    msg_cprintf(H_HL, M_ADDING);
    msg_cprintf(H_HL|H_NFMT, M_FILENAME_FORM, filename);
    write_index_entry(nullstr);
    special_processing(CFA_NONE, arc);
    rc++;
   }
   cfa_store(i, FLFLAG_PROCESSED);
  }
  fclose(arc);
 }
 return(rc);
}

#endif

/* Inserts base directory into filespec */

void add_base_dir(char *name)
{
 #if SFX_LEVEL>=ARJ
  char *tmp;
 #else
  char tmp[FILENAME_MAX];
 #endif

 if(target_dir[0]!='\0')
 {
  #if SFX_LEVEL>=ARJ
   tmp=malloc_str(name);
   strcpy(name, target_dir);
   strcat(name, tmp);
   free(tmp);
  #else
   strcpy(tmp, name);
   strcpy(name, target_dir);
   strcat(name, tmp);
  #endif
 }
}

/* Checks if the file can be unpacked */

static int test_unpack_condition(char *name)
{
 int answer;                            /* Reply to overwrite/append queries */
 int fr;
 struct timestamp ftime;
 unsigned long fsize;
 int volume_file;
 unsigned long append_pos;
 #if SFX_LEVEL>=ARJSFXV
  char *fname;                          /* Formatted name */
  char arc_time[22], disk_time[22];
  struct file_properties properties;
 #endif

 #if SFX_LEVEL>=ARJSFXV
  fname=format_filename(name);
 #endif
 if(!file_exists(name))
 {
  #if SFX_LEVEL>=ARJSFXV
   if(freshen_criteria!=FC_NONE||continued_prevvolume)
   {
    #if SFX_LEVEL>=ARJ
     if(continued_prevvolume&&start_at_ext_pos&&ext_pos!=0L)
     {
      answer=yes_on_all_queries||skip_append_query;
      if(answer==0)
      {
       msg_cprintf(H_HL|H_NFMT, M_NOT_EXISTS, fname);
       answer=query_action(REPLY_YES, QUERY_APPEND, M_QUERY_CONTINUE);
       if(answer==1)
       {
        resume_position=0L;
        continued_prevvolume=0;
        create_subdir_tree(name, yes_on_all_queries, file_type);
        return(0);
       }
      }
     }
    #endif
    msg_cprintf(H_HL|H_NFMT, M_NOT_EXISTS, fname);
    return(1);
   }
   create_subdir_tree(name, yes_on_all_queries, file_type);
   return(0);
  #else
   if(freshen_criteria!=FC_NONE)
   {
    msg_cprintf(H_HL|H_NFMT, M_NOT_EXISTS, name);
    return(1);
   }
   else
   {
    create_subdir_tree(name, file_type);
    return(0);
   }
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  fr=file_find(name, &properties);
  if(fr||(properties.type!=ARJT_DIR&&
          properties.type!=ARJT_BINARY&&
          properties.type!=ARJT_UXSPECIAL))
  {
   msg_cprintf(H_ERR, M_CANTOPEN, name);
   msg_cprintf(0, (FMSG *)", ");
   return(2);
  }
 #endif
 if(new_files_only)
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(H_HL|H_NFMT, M_EXISTS, name);
  #else
   msg_cprintf(H_HL|H_NFMT, M_EXISTS, name);
  #endif
  return(1);
 }
 #if SFX_LEVEL>=ARJSFXV
  ts_store(&ftime, OS, properties.ftime);
 #else
  ts_store(&ftime, OS, file_getftime(name));
 #endif
 if(!skip_ts_check)
 {
  #if SFX_LEVEL>=ARJ
   fsize=properties.fsize;
   volume_file=0;
   if(arj_flags&VOLUME_FLAG||arj_flags&EXTFILE_FLAG)
   {
    fsize=origsize;
    volume_file=1;
   }
   if(update_criteria==UC_NEW_OR_CRC||freshen_criteria==FC_CRC)
   {
    if(!volume_file&&fsize==origsize)
    {
     if(crc32_for_file(filename)==file_crc)
     {
      msg_cprintf(H_HL|H_NFMT, M_IS_SAME, fname);
      return(1);
     }
    }
   }
   else if(update_criteria==UC_NEW_OR_DIFFERENT||freshen_criteria==FC_DIFFERENT)
   {
    if(!ts_cmp(&ftime_stamp, &ftime)&&fsize==origsize)
    {
     msg_cprintf(H_HL|H_NFMT, M_IS_SAME, fname);
     return(1);
    }
   }
   else if(update_criteria==UC_NEW_OR_OLDER||freshen_criteria==FC_OLDER)
   {
    if(ts_cmp(&ftime, &ftime_stamp)<=0)
    {
     msg_cprintf(H_HL|H_NFMT, M_IS_SAME_OR_OLDER, fname);
     return(1);
    }
   }
   else if(update_criteria==UC_NEW_OR_NEWER||freshen_criteria==FC_EXISTING)
   {
    if(ts_cmp(&ftime, &ftime_stamp)>=0)
    {
     msg_cprintf(H_HL|H_NFMT, M_IS_SAME_OR_NEWER, fname);
     return(1);
    }
   }
  #else
   if(update_criteria!=UC_NONE&&freshen_criteria!=FC_NONE)
   {
    if(ts_cmp(&ftime, &ftime_stamp)>=0)
    {
     #if SFX_LEVEL>=ARJSFXV
      msg_cprintf(H_HL|H_NFMT, M_IS_SAME_OR_NEWER, fname);
     #else
      msg_cprintf(H_HL|H_NFMT, M_IS_SAME_OR_NEWER, name);
     #endif
     return(1);
    }
   }
  #endif
 }
 #if SFX_LEVEL>=ARJSFXV
  if(yes_on_all_queries&&!skip_ts_check&&continued_prevvolume&&
     (file_type==ARJT_TEXT||file_type==ARJT_BINARY)&&!ts_cmp(&ftime_stamp, &ftime)&&
     eh_find_pending(eh)!=NULL)
  {
   msg_cprintf(H_HL|H_NFMT, M_IS_NOT_SAME_DATE, fname);
   return(2);
  }
 #endif
 #if SFX_LEVEL>=ARJ
  if(serialize_exts!=EXT_NO_SERIALIZE)
   return(find_num_ext(name, serialize_exts)?2:0);
  if(arcmail_sw)
   return(find_arcmail_name(name)?2:0);
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(yes_on_all_queries)
   return(0);
 #else
  if(yes_on_all_queries||overwrite_existing)
   return(0);
 #endif
 /* Multivolume preprocessing */
 #if SFX_LEVEL>=ARJSFXV
  #if SFX_LEVEL>=ARJ
   if(continued_prevvolume||start_at_ext_pos)
  #else
   if(continued_prevvolume)
  #endif
   {
    if(skip_append_query||(file_type!=ARJT_BINARY&&file_type!=ARJT_TEXT))
     return(0);
    msg_cprintf(0, (!ts_cmp(&ftime_stamp, &ftime))?M_EXISTS:M_IS_NOT_SAME_DATE, fname);
    #if SFX_LEVEL>=ARJ
     append_pos=start_at_ext_pos?ext_pos:resume_position;
    #else
     append_pos=resume_position;
    #endif
    msg_sprintf(misc_buf, M_QUERY_APPEND, append_pos);
    return(query_action(REPLY_YES, QUERY_APPEND, (FMSG *)misc_buf)?0:-1);
   }
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(overwrite_existing
    /* ASR fix 31/03/2003: for new recursion order, skip directory overwrite
       prompt unless the user has specified "-2r". */
    #if SFX_LEVEL>=ARJ
     ||(properties.type==ARJT_DIR&&!recursion_order)
    #endif
     )
   return(0);
  timestamp_to_str(arc_time, &ftime_stamp);
  timestamp_to_str(disk_time, &ftime);
  msg_cprintf(H_HL|H_NFMT, M_ARJ_VS_DISK, origsize, arc_time+2, properties.fsize, disk_time+2);
  msg_cprintf(0, (ts_cmp(&ftime, &ftime_stamp)>=0)?M_IS_SAME_OR_NEWER:M_EXISTS, fname);
  return(query_action(REPLY_YES, QUERY_OVERWRITE, M_QUERY_OVERWRITE)?0:-1);
 #else
  msg_cprintf(0, (ts_cmp(&ftime_stamp, &ftime)>0)?M_EXISTS:M_IS_SAME_OR_NEWER, name);
  msg_cprintf(0, M_QUERY_OVERWRITE);
  return(query_action()?0:-1);
 #endif
}

#if SFX_LEVEL>=ARJSFXV

/* Queries the user about renaming the file and performs neccessary checks */

static int query_for_rename(char *name)
{
 if(!query_action(REPLY_YES, QUERY_EXTRACT_RENAME, M_QUERY_EXTRACT_RENAME))
 {
  skip_file();
  errors++;
  return(0);
 }
 if(kbd_cleanup_on_input)
  fetch_keystrokes();
 msg_cprintf(0, M_ENTER_NEW_FILENAME);
 if(read_line(name, FILENAME_MAX)==0)
 {
  skip_file();
  errors++;
  return(0);
 }
 #if SFX_LEVEL>=ARJ
  if(translate_unix_paths)
   unix_path_to_dos(name);
 #endif
 case_path(name);
 if(test_unpack_condition(name))
 {
  skip_file();
  errors++;
  return(0);
 }
 else
  return(1);
}

#endif

/* Checks if the OS and current conditions allow unpacking */

#if SFX_LEVEL>=ARJ
static int test_unpack_env(int disk_touched)
#else
static int test_unpack_env()
#endif
{
 /* The text below is NOT a typo, this check is really used in ARJSFXV
    (since headers may be damaged, and so on...) */
 #if SFX_LEVEL>=ARJSFXV
  if(arj_x_nbr>EXTR_LEVEL)
  {
   msg_cprintf(H_HL|H_NFMT, M_UNKNOWN_VERSION, (int)arj_x_nbr);
   skip_file();
   return(-1);
  }
 #endif
 if(file_garbled&&!garble_enabled)
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, M_FILE_IS_GARBLED);
  #else
   msg_cprintf(0, M_FILE_IS_GARBLED);
  #endif
  skip_file();
  return(-1);
 }
 #if SFX_LEVEL>=ARJSFXV
  #if SFX_LEVEL>=ARJ
  if((method>MAXMETHOD&&method<8)||(method==MAXMETHOD&&arj_nbr==1))
  #else
  if(method>3)
  #endif
  {                                      /* ARJ 0.xx -m4 is not supported */
   msg_cprintf(H_HL|H_NFMT, M_UNKNOWN_METHOD, (int)method);
   skip_file();
   return(-1);
  }
  #if SFX_LEVEL>=ARJ
  if(file_type!=ARJT_BINARY&&file_type!=ARJT_TEXT&&file_type!=ARJT_DIR&&
     file_type!=ARJT_COMMENT&&file_type!=ARJT_LABEL&&file_type!=ARJT_CHAPTER&&
     file_type!=ARJT_UXSPECIAL)
  #else
  if(file_type!=ARJT_BINARY&&file_type!=ARJT_TEXT&&file_type!=ARJT_DIR&&
     file_type!=ARJT_LABEL&&file_type!=ARJT_UXSPECIAL)
  #endif
  {
   msg_cprintf(H_HL|H_NFMT, M_UNKNOWN_FILE_TYPE, file_type);
   skip_file();
   return(-1);
  }
 #endif
 /* Check for ability to extract Windows 95 LFNs */
 #if TARGET==DOS
  #if SFX_LEVEL>=ARJ
  if(disk_touched&&(host_os==OS_WIN95||host_os==OS_WINNT))
  {
   if(lfn_supported==LFN_NOT_SUPPORTED&&lfn_mode<=LFN_NONE)
   {
    msg_cprintf(0, M_REQUIRES_WIN95);
    skip_file();
    return(-1);
   }
  }
  #else
  if(host_os==OS_WIN95&&lfn_supported==LFN_NOT_SUPPORTED&&!process_lfn_archive)
  {
   #if SFX_LEVEL>=ARJSFXV
    msg_cprintf(0, M_REQUIRES_WIN95);
   #else
    msg_cprintf(0, M_REQUIRES_WIN95);
   #endif
   skip_file();
   return(-1);
  }
  #endif
 #endif
 return(0);
}

/* Unpacks a single file (NOT the main extraction routine; see below) */

static void unpack_file(int action)
{
 unsigned long st_ticks=0;

 #if SFX_LEVEL>=ARJSFXV
  uncompsize=origsize;
 #endif
 /* Verbose display option is missing from ARJSFXV but is supported by
    ARJSFX */
 #if SFX_LEVEL==ARJSFX
  if(verbose_display)
   msg_cprintf(H_HL|H_NFMT, M_N_BYTES, origsize);
 #endif
 crc32term=CRC_MASK;
 #if SFX_LEVEL>=ARJSFXV
  if(debug_enabled&&strchr(debug_opt, 't')!=NULL)
   st_ticks=get_ticks();
 #endif
#if SFX_LEVEL>=ARJSFXV
 if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
#else
 if(file_type!=ARJT_DIR&&file_type!=ARJT_UXSPECIAL)
#endif
 {
  #if SFX_LEVEL>=ARJ
   if(hollow_mode==HM_CRC||method==9)
    hollow_decode(action);
   else if(method!=8&&test_archive_crc!=TC_ATTRIBUTES)
   {
    if(method==0)
     unstore(action);
    else if(method>=1&&method<=3)
     decode(action);
    else if(method==4)
     decode_f(action);
   }
  #else
   #if SFX_LEVEL<=ARJSFX
    garble_init(password_modifier);
    uncompsize=origsize;
   #endif
   if(method==0)
    unstore(action);
   else
    decode(action);
  #endif
 }
 display_indicator(uncompsize);
 #if SFX_LEVEL>=ARJSFXV
  skip_compdata();
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(debug_enabled)
  {
   #if SFX_LEVEL>=ARJ
    if(strchr(debug_opt, 'k')!=NULL)
     compsize=0L;
   #endif
   if(strchr(debug_opt, 't')!=NULL)
    msg_cprintf(H_HL|H_NFMT, M_N_TICKS, st_ticks=get_ticks()-st_ticks);
  }
 #endif
 #if SFX_LEVEL<=ARJSFX
  if((crc32term^CRC_MASK)==file_crc)
   msg_cprintf(0, M_OK);
  else
  {
   msg_cprintf(H_ALERT, M_CRC_ERROR);
   errors++;
  }
 #endif
}

/* Test/search routine */

#if SFX_LEVEL>=ARJ
int unpack_validation(int cmd)
#else
int unpack_validation()
#endif
{
 int action;
 #if SFX_LEVEL>=ARJSFXV
  int found;                            /* 1 if the file is present */
  int errflag;
  int nf_error;                         /* Non-fatal error */
  int pattern;                          /* Current search pattern */
 #endif
 #if SFX_LEVEL>=ARJ
  struct file_properties properties;
 #endif

 #if SFX_LEVEL>=ARJ
  found=1;
  errflag=nf_error=0;
  pattern_found=0;
  identical_filedata=1;
  if(test_unpack_env(0))
   return(0);
 #else
  if(test_unpack_env())
   return(0);
 #endif
 #if SFX_LEVEL>=ARJ
  if(cmd==ARJ_CMD_WHERE)
  {
   action=BOP_SEARCH;
   msg_sprintf(misc_buf, M_SEARCHING, filename);
   if(search_mode==SEARCH_DEFAULT||search_mode==SEARCH_SHOW_NAMES)
    alltrim(misc_buf);
   if(search_mode<=SEARCH_BRIEF)
   {
    msg_cprintf(0, (FMSG *)strform, misc_buf);
    if(search_mode==SEARCH_DEFAULT)
     msg_cprintf(0, (FMSG *)lf);
    if(search_mode==SEARCH_BRIEF)
     msg_cprintf(0, (FMSG *)cr);
   }
   for(pattern=0; pattern<SEARCH_STR_MAX; search_occurences[pattern++]=0);
   reserve_size=0;
  }
  else
  {
   action=BOP_NONE;
   msg_cprintf(H_HL|H_NFMT, M_TESTING, format_filename(filename));
   if(!verbose_display)
    msg_cprintf(0, (FMSG *)vd_space);
   else
   {
    nputlf();
    msg_cprintf(H_HL|H_NFMT, M_N_BYTES, origsize);
   }
   if(test_archive_crc>=TC_CRC_AND_CONTENTS)
   {
    if(test_archive_crc==TC_CRC_AND_CONTENTS||total_chapters==0||((unsigned int)ext_flags<=total_chapters&&(unsigned int)chapter_number>=total_chapters))
    {
     if(test_archive_crc!=TC_ADDED_FILES||flist_is_in_archive(&flist_main, filename))
     {
      if(test_archive_crc!=TC_ADDED_FILES||total_chapters==0||(unsigned int)chapter_number==total_chapters)
      {
       if(method==8||test_archive_crc==TC_ATTRIBUTES)
       {
        action=BOP_COMPARE;
        if(file_find(filename, &properties))
         found=0;
       }
       else
       {
        if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
        {
         action=BOP_COMPARE;
         if((tstream=file_open(filename, read_perms[file_type%2]))==NULL)
         {
          action=BOP_NONE;
          found=0;
          errflag=1;
          if((ignore_open_errors==IAE_ACCESS&&errno==EACCES)||
             (ignore_open_errors==IAE_NOTFOUND&&errno==ENOENT)||
             (ignore_open_errors==IAE_ALL&&(errno==EACCES||errno==ENOENT)))
           errflag=0;
         }
         else
          smart_seek(resume_position, tstream);
        }
        else if(file_type==ARJT_DIR)
        {
         if(!is_directory(filename))
         {
          errflag=1;
          found=0;
         }
        }
       }
      }
     }
    }
   }
  }
 #else
  action=BOP_NONE;
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(H_HL|H_NFMT, M_TESTING, format_filename(filename));
   msg_cprintf(0, (FMSG *)vd_space);
  #else
   msg_cprintf(H_HL|H_NFMT, M_TESTING, filename);
  #endif
 #endif
 atstream=NULL;
 #if SFX_LEVEL>=ARJSFXV
  if(file_garbled)
   garble_init(password_modifier);
 #endif
 unpack_file(action);
 #if SFX_LEVEL>=ARJ
  if(!found)
  {
   msg_cprintf(0, M_NOT_FOUND);
   if(errflag)
   {
    if(errorlevel==ARJ_ERL_SUCCESS)
     errorlevel=ARJ_ERL_CRC_ERROR;
    errors++;
   }
   nf_error=1;
  }
  if(action==BOP_COMPARE&&(method==8||test_archive_crc==TC_ATTRIBUTES))
  {
   compsize=0L;
   crc32term=file_crc^CRC_MASK;
   if(ts_native(&ftime_stamp, OS)==properties.ftime&&origsize==properties.fsize)
    msg_cprintf(0, M_MATCHED);
   else
   {
    if(verbose_display)
    {
     if(ts_native(&ftime_stamp, OS)!=properties.ftime)
      msg_cprintf(0, M_BY_DATE);
     if(origsize!=properties.fsize)
      msg_cprintf(0, M_BY_SIZE);
    }
    msg_cprintf(0, M_NOT_MATCHED);
    if(errorlevel==ARJ_ERL_SUCCESS)
     errorlevel=ARJ_ERL_CRC_ERROR;
    errors++;
    nf_error=1;
   }
  }
  else if(action==BOP_COMPARE)
  {
   if(verbose_display)
   {
    file_find(filename, &properties);
    if(ts_native(&ftime_stamp, OS)!=properties.ftime)
     msg_cprintf(0, M_BY_DATE);
    if(origsize!=properties.fsize)
     msg_cprintf(0, M_BY_SIZE);
   }
   if(identical_filedata&&!volume_flag_set&&fgetc(tstream)==EOF)
    msg_cprintf(0, M_MATCHED);
   else if(identical_filedata&&volume_flag_set)
    msg_cprintf(0, M_MATCHED);
   else
   {
    if(verbose_display)
     msg_cprintf(0, M_BY_DATA);
    msg_cprintf(0, M_NOT_MATCHED);
    if(errorlevel==ARJ_ERL_SUCCESS)
     errorlevel=ARJ_ERL_CRC_ERROR;
    errors++;
    nf_error=1;
   }
   fclose(tstream);
  }
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(file_crc==(crc32term^CRC_MASK)&&compsize==0L)
  {
   #if SFX_LEVEL>=ARJ
    if(cmd!=ARJ_CMD_WHERE)
     msg_cprintf(0, M_OK);
   #else
    msg_cprintf(0, M_OK);
   #endif
  }
  else
  {
   msg_cprintf(H_ALERT, M_CRC_ERROR);
   if(errorlevel==ARJ_ERL_SUCCESS)
    errorlevel=ARJ_ERL_CRC_ERROR;
   errors++;
   #if SFX_LEVEL>=ARJ
    nf_error=1;
   #endif
  }
 #endif
 #if SFX_LEVEL>=ARJ
  if(cmd==ARJ_CMD_WHERE)
  {
   for(pattern=0; pattern<SEARCH_STR_MAX; pattern++)
   {
    if(search_occurences[pattern]>0)
    {
     nf_error=1;
     msg_cprintf(H_OPER, M_FOUND_N_OCCURENCES, search_occurences[pattern], search_str[pattern]);
    }
   }
  }
  if(nf_error)
   write_index_entry(idxid_fault);
  return(((pattern_found&&extm_mode==EXTM_MATCHING)||(!pattern_found&&extm_mode==EXTM_MISMATCHING))?2:1);
 #endif
 #if SFX_LEVEL<=ARJSFXV
  return(1);
 #endif
}

#if SFX_LEVEL>=ARJ

/* Checks filename upon extraction */

static int extract_fn_proc()
{
 char tmp_name[FILENAME_MAX], efn[FILENAME_MAX];
 int entry;

 skip_compdata();
 strcpy(tmp_name, filename);
 entry=entry_pos;
 if(subdir_extraction)
 {
  strcpy(efn, target_dir);
  default_case_path(efn+strlen(efn), tmp_name+(exclude_paths?left_trim:0));
 }
 else
 {
  strcpy(efn, target_dir);
  strcat(efn, tmp_name+entry);
 }
 if(!file_exists(efn))
 {
  msg_cprintf(H_HL|H_NFMT, M_SKIPPED, efn);
  errors++;
  write_index_entry(idxid_fault);
  return(0);
 }
 if(show_filenames_only||!strcmp_os(filename, efn))
  msg_cprintf(H_HL|H_NFMT, M_RESTORING_PROPERTIES, efn);
 else
 {
  msg_cprintf(H_HL|H_NFMT, M_RESTORING_PROPERTIES, format_filename(filename));
  msg_cprintf(H_HL|H_NFMT, M_TO, format_filename(efn));
 }
 if(!test_host_os((int)host_os)&&file_type==ARJT_BINARY)
  msg_cprintf(0, M_FOREIGN_BINARY);
 nputlf();
 if(test_host_os((int)host_os)&&(hollow_mode==HM_RESTORE_ATTRS||hollow_mode==HM_RESTORE_ALL))
  dos_chmod(efn, file_mode.native);
 if(hollow_mode==HM_RESTORE_DATES||hollow_mode==HM_RESTORE_ALL)
 {
  file_setftime(efn, ts_native(&ftime_stamp, OS));
  if(lfn_supported!=LFN_NOT_SUPPORTED&&ts_valid(atime_stamp))
  {
   file_setctime(efn, ts_native(&ctime_stamp, OS));
   file_setatime(efn, ts_native(&atime_stamp, OS));
  }
 }
 return(1);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Allocates memory for and unpacks extended attributes */

char FAR *unpack_ea(struct ext_hdr FAR *eh)
{
 char FAR *raw_eh;
 struct mempack mempack;
 unsigned char p_modifier;
 char FAR *ea_blk;

 p_modifier=password_modifier;
 password_modifier=ea_pwd_modifier;
 ea_blk=eh->raw;
 mempack.origsize=(unsigned int)((unsigned char)ea_blk[2])*256U+(unsigned char)ea_blk[1];
 raw_eh=(char FAR *)farmalloc_msg(mempack.origsize);
 mempack.compsize=eh->size-3;
 mempack.method=ea_blk[0];
 mempack.comp=ea_blk+3;
 mempack.orig=raw_eh;
 unpack_mem(&mempack);
 password_modifier=p_modifier;
 return(raw_eh);
}

#endif

/* Unpacks a single file */

#if SFX_LEVEL>=ARJ
int unpack_file_proc(int to_console, FILE_COUNT num)
#else
int unpack_file_proc()
#endif
{
 #if SFX_LEVEL>=ARJSFXV
 int action;                            /* Passed to the decoding routines */
 int disk_touched;                      /* Indicates if the output is directed
                                           to a file, not to console */
 char *fname;                           /* Formatted filename */
 unsigned long tmp_compsize;
 unsigned long cur_pos;
 unsigned long alloc_size;              /* Size of file rounded up to the next
                                           allocation unit boundary */
 struct ext_hdr FAR *p_eh;
 int uxspec_rc;
 #endif
 char tmp_name[FILENAME_MAX];
 char FAR *raw_eh;
 #if SFX_LEVEL>=ARJSFXV
 char out_name[FILENAME_MAX];
 int tmp_entry, out_entry;
 char subdir[8];
 int dir_num;
 int trim;
 unsigned long tmp_crc;
 #endif

 #if SFX_LEVEL>=ARJ
  action=BOP_NONE;
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(!handle_labels&&file_type==ARJT_LABEL)
  {
   skip_compdata();
   return(0);
  }
 #endif
 #if SFX_LEVEL>=ARJ
  disk_touched=!to_console;
  if(!debug_enabled||strchr(debug_opt, 'x')==NULL)
  {
   if(hollow_mode>HM_NO_CRC)
    return(extract_fn_proc());
   if(method==8||method==9||test_unpack_env(disk_touched))
   {
    errors++;
    write_index_entry(idxid_fault);
    return(0);
   }
  }
 #else
  if(test_unpack_env())
  {
   #if SFX_LEVEL>=ARJSFXV
    errors++;
   #endif
   return(0);
  }
 #endif
#if SFX_LEVEL>=ARJ
 if(file_type==ARJT_CHAPTER)
 {
  fname=format_filename(filename);
  msg_cprintf(H_HL|H_NFMT, M_EXTRACTING, fname);
  msg_cprintf(0, (FMSG *)vd_space);
  msg_cprintf(0, M_OK);
 }
 else
 {
#endif
  #if SFX_LEVEL>=ARJ
   if(extm_mode!=EXTM_NONE)
   {
    tmp_compsize=compsize;
    cur_pos=ftell(aistream);
    if(unpack_validation(ARJ_CMD_WHERE)!=2)
     return(0);
    fseek(aistream, cur_pos, SEEK_SET);
    compsize=tmp_compsize;
   }
  #endif
  #if SFX_LEVEL>=ARJSFXV
   if(chk_free_space)
   {
    alloc_size=((origsize+(unsigned long)alloc_unit_size-1L)/(unsigned long)alloc_unit_size)*(unsigned long)alloc_unit_size;
    if(file_getfree(target_dir)<minfree+alloc_size)
    {
     #if SFX_LEVEL>=ARJ
      msg_cprintf(0, M_NOT_ENOUGH_SPACE);
     #else
      msg_sprintf(misc_buf, M_NOT_ENOUGH_SPACE, filename);
      if(!query_action(REPLY_YES, QUERY_CRITICAL, (FMSG *)misc_buf))
       exit(ARJSFX_ERL_ERROR);
     #endif
     skip_file();
     errors++;
     #if SFX_LEVEL>=ARJ
      write_index_entry(idxid_fault);
     #endif
     return(0);
    }
   }
  #endif
  #if SFX_LEVEL>=ARJSFXV
  #if SFX_LEVEL>=ARJ
   if(execute_cmd&&file_type!=ARJT_BINARY&&file_type!=ARJT_TEXT)
    return(0);
   strcpy(tmp_name, filename);
   tmp_entry=entry_pos;
   if(to_console)
   {
    if(comment_display==CMTD_PCMD)
     action=BOP_DISPLAY;
    atstream=stdout;
    file_settype(atstream, file_type);
    if(!help_issued)
     msg_cprintf(H_NFMT, M_EXTRACTING_1_TO_2, format_filename(filename), "STDOUT");
   }
   else
   {
  #endif
    if(file_type==ARJT_LABEL)
    {
     #ifdef HAVE_DRIVES
      #if SFX_LEVEL>=ARJ
       msg_cprintf(H_HL|H_NFMT, M_EXTRACTING, fname=format_filename(filename));
      #else
       msg_cprintf(H_HL|H_NFMT, M_EXTRACTING, format_filename(filename));
      #endif
      msg_cprintf(0, (FMSG *)vd_space);
      if(!file_setlabel(filename, label_drive, file_mode.native, ts_native(&ftime_stamp, OS)))
      {
       msg_cprintf(0, M_OK);
       return(1);
      }
      else
      {
       msg_cprintf(0, M_SET_LABEL_ERROR);
       errors++;
       #if SFX_LEVEL>=ARJ
        write_index_entry(idxid_fault);
       #endif
       return(0);
      }
     #else
      skip_file();
     #endif
    }
    #if SFX_LEVEL>=ARJ
     if((host_os==OS_WIN95||host_os==OS_WINNT)&&lfn_mode==LFN_DUAL_EXT)
     {
      msg_sprintf(tmp_name, M_WIN95_LFN_TRANSL, (int)(num%1000));
      tmp_entry=split_name(tmp_name, NULL, NULL);
     }
     subdir[0]='\0';
     if(current_chapter!=chapter_to_process)
     {
      dir_num=(int)max(ext_flags, current_chapter);
      sprintf(subdir, "%03d%c", dir_num, PATHSEP_DEFAULT);
     }
    #endif
    if(extract_to_file)
     strcpy(out_name, extraction_filename);
    else
    {
     if(lowercase_names)
     {
      #if SFX_LEVEL>=ARJ
       strlower(tmp_name);
      #else
       strlower(filename);
      #endif
     }
    #if SFX_LEVEL>=ARJ
     if(subdir_extraction)
    #else
     if(!subdir_extraction)
    #endif
     {
      strcpy(out_name, (target_dir[0]=='\0')?nullstr:target_dir);
      #if SFX_LEVEL>=ARJ
       strcat(out_name, subdir);
       out_entry=strlen(out_name);
       trim=exclude_paths?left_trim:0;
       default_case_path(out_name+out_entry, tmp_name+trim);
      #else
       strcat(out_name, filename);
      #endif
     }
     else
     {
      strcpy(out_name, target_dir);
      #if SFX_LEVEL>=ARJ
       strcat(out_name, subdir);
       strcat(out_name, tmp_name+tmp_entry);
      #else
       strcat(out_name, filename+entry_pos);
      #endif
     }
    }
    if(continued_prevvolume&&ofstream!=NULL)
    {
     crc32term=CRC_MASK;
     crc32_for_string(filename+entry_pos);
     if(crc32term!=volume_crc)
      error(M_INVALID_MV_SEQ);
     far_strcpy((char FAR *)tmp_tmp_filename, tmp_filename);
     atstream=ofstream;
     ofstream=NULL;
     tmp_filename[0]='\0';
    }
    else
    {
     disk_touched=test_unpack_condition(out_name);
     if(disk_touched)
     {
      if(disk_touched==1||disk_touched==2||skip_rename_prompt)
      {
       if(disk_touched==2)
        errors++;
       skip_file();
       #if SFX_LEVEL>=ARJ
        write_index_entry(idxid_fault);
       #endif
       return(0);
      }
      else
      {
       if(!query_for_rename(out_name))
       {
        #if SFX_LEVEL>=ARJ
         write_index_entry(idxid_fault);
        #endif
        return(0);
       }
      }
     }
     if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
     {
cycle:;
      #if SFX_LEVEL>=ARJ
       if(clear_archive_bit)
        dos_chmod(out_name, STD_FATTR_NOARCH);
      #else
       if(overwrite_ro)
        dos_chmod(out_name, STD_FATTR_NOARCH);
      #endif
      #if SFX_LEVEL>=ARJ
       atstream=file_open(out_name, (continued_prevvolume||ext_pos>0L)?sim_perms[file_type%2]:write_perms[file_type%2]);
      #else
       atstream=file_open(out_name, continued_prevvolume?sim_perms[file_type%2]:write_perms[file_type%2]);
      #endif
      if(atstream!=NULL&&!extract_to_file&&is_file(atstream))
      {
       file_close(atstream);
       atstream=NULL;
      }
      if(atstream==NULL)
      {
       #if SFX_LEVEL>=ARJ
        error_report();
       #endif
       msg_cprintf(H_ERR, M_CANTOPEN, out_name);
       nputlf();
       if(yes_on_all_queries||skip_rename_prompt)
       {
        skip_file();
        errors++;
        #if SFX_LEVEL>=ARJ
         write_index_entry(idxid_fault);
        #endif
        return(0);
       }
       if(!query_for_rename(out_name))
       {
        #if SFX_LEVEL>=ARJ
         write_index_entry(idxid_fault);
        #endif
        return(0);
       }
       else
        goto cycle;
      }
      #if SFX_LEVEL>=ARJ
       if(start_at_ext_pos)
       {
        fseek(atstream, 0L, SEEK_END);
        if(ftell(atstream)>ext_pos)
         fseek(atstream, ext_pos, SEEK_SET);
       }
       else
        smart_seek(resume_position, atstream);
      #else
       smart_seek(resume_position, atstream);
      #endif
     }
     strcpy(tmp_tmp_filename, out_name);
    }
    if(show_filenames_only||!strcmp_os(filename, tmp_tmp_filename))
     msg_cprintf(H_HL|H_NFMT, M_EXTRACTING, format_filename(filename));
    else
    {
     strcpy(out_name, format_filename(tmp_tmp_filename));
     msg_cprintf(H_HL|H_NFMT, M_EXTRACTING_1_TO_2, format_filename(filename), out_name);
    }
   #if SFX_LEVEL>=ARJ
    if((continued_prevvolume||start_at_ext_pos)&&eh_find_pending(eh)==NULL)
   #elif SFX_LEVEL>=ARJSFXV
    if(continued_prevvolume&&eh_find_pending(eh)==NULL)
   #else
    if(continued_prevvolume)
   #endif
     msg_cprintf(H_HL|H_NFMT, M_AT_POSITION_N, ftell(atstream));
  #if SFX_LEVEL>=ARJ
   }
  #endif
  #endif
 /* For ARJSFX, use a simplified algorithm... */
  #if SFX_LEVEL==ARJSFX
   if(test_unpack_env())
    return(0);
   strcpy(tmp_name, target_dir);
   strcat(tmp_name, test_mode?filename:list_adapted_name);
   if(test_unpack_condition(tmp_name))
   {
    skip_file();
    return(0);
   }
   strcpy(tmp_tmp_filename, tmp_name);
   if(file_type!=ARJT_DIR&&file_type!=ARJT_UXSPECIAL)
   {
    if((atstream=file_open(tmp_tmp_filename, write_perms[file_type%2]))==NULL)
    {
     msg_cprintf(H_ERR, M_CANTOPEN, tmp_tmp_filename);
     fputc(LF, stdout);
     skip_file();
     errors++;
     return(0);
    }
   }
   if(strcmp_os(filename, tmp_tmp_filename))
    msg_cprintf(H_HL|H_NFMT, M_EXTRACTING_1_TO_2, filename, tmp_tmp_filename);
   else
    msg_cprintf(H_HL|H_NFMT, M_EXTRACTING, filename);
   if(verbose_display)
   {
    if(file_type==ARJT_BINARY&&!test_host_os(host_os))
     msg_cprintf(0, M_FOREIGN_BINARY);
    else
     fputc(LF, stdout);
    msg_cprintf(0, method==0?M_UNSTORING:M_UNCOMPRESSING);
   }
   unpack_file(BOP_NONE);
   if(file_type!=ARJT_DIR&&file_type!=ARJT_UXSPECIAL)
    fclose(atstream);
   file_setftime(tmp_tmp_filename, ts_native(&ftime_stamp, OS));
   if(test_host_os(host_os))
    dos_chmod(tmp_tmp_filename, file_mode.native);
   atstream=NULL;
  #endif
  /* ...and the rest may be safely omitted for ARJSFX modules */
  #if SFX_LEVEL>=ARJSFXV
   if(!test_host_os((int)host_os)&&file_type==ARJT_BINARY)
    msg_cprintf(0, M_FOREIGN_BINARY);
   #if SFX_LEVEL>=ARJ
    if(!verbose_display)
     msg_cprintf(0, (FMSG *)vd_space);
    else
    {
     nputlf();
     if(method==0)
      msg_cprintf(0, M_UNSTORING);
     else
      msg_cprintf(H_HL|H_NFMT, M_UNCOMPRESSING, method);
     msg_cprintf(H_HL|H_NFMT, M_N_BYTES, origsize);
    }
   #else
    msg_cprintf(0, (FMSG *)vd_space);
   #endif
   if(file_garbled)
    garble_init(password_modifier);
   #if SFX_LEVEL<=ARJSFXV
    action=BOP_NONE;
   #endif
   if(print_with_more)
    action=BOP_LIST;
   unpack_file(action);
   tmp_crc=crc32term^CRC_MASK;
  #if SFX_LEVEL>=ARJ
   if(to_console)
   {
    file_settype(atstream, ARJT_TEXT);
    /* This way, pipe redirections can't be tracked under UNIX, e.g.
       "arj p test.arj myfile>newfile" will not set the timestamp of
       newfile to the one of test.arj->myfile. */
#if TARGET!=UNIX    
    file_setftime_on_stream(atstream, ts_native(&ftime_stamp, OS));
#endif    
    atstream=NULL;
   }
   else
   {
  #endif
    if(volume_flag_set)
    {
     ofstream=atstream;
     atstream=NULL;
     crc32term=CRC_MASK;
     crc_for_string(filename+entry_pos);
     volume_crc=crc32term;
     far_strcpy(tmp_filename, (char FAR *)tmp_tmp_filename);
     volume_ftime=ftime_stamp;
     msg_cprintf(0, M_CONTINUED_NEXTVOL);
    }
    else
    {
     if(file_type==ARJT_BINARY||file_type==ARJT_TEXT)
     {
      fclose(atstream);
      atstream=NULL;
     }
     /* Process the extended header information */
     if(valid_ext_hdr)
     {
     /* Create UNIX special files if able to */
     #if TARGET==UNIX
      if(file_type==ARJT_UXSPECIAL&&(p_eh=eh_lookup(eh, UXSPECIAL_ID))!=NULL)
      {
       raw_eh=p_eh->raw;                /* No unpacking, etc. (for now) */
       if((uxspec_rc=set_uxspecial(raw_eh, tmp_tmp_filename))!=0)
       {
        switch(uxspec_rc)
        {
#if TARGET==UNIX         
         case UXSPEC_RC_FOREIGN_OS:
          msg_cprintf(H_ALERT, M_FOREIGN_SYSTEM);
          break;
         case UXSPEC_RC_NOLINK:
          msg_cprintf(H_ALERT, M_NO_LINKING);
          break;
 #if SFX_LEVEL>=ARJ          
         case UXSPEC_RC_SUPPRESSED:
          msg_cprintf(H_ALERT, M_UXSPEC_SUPPRESSED);
          break;          
 #endif
#endif          
         default:
          msg_cprintf(H_ERR, M_CANT_SET_UXSPECIAL);
          break;
        }
        if(errorlevel==ARJ_ERL_SUCCESS)
         errorlevel=ARJ_ERL_WARNING;
       }
       else
        uxspecial_stats(raw_eh, UXSTATS_SHORT);
      }
     #else
      if(file_type==ARJT_UXSPECIAL)
      {
       msg_cprintf(H_ALERT, M_UXSPECIAL_UNSUPP);
       msg_cprintf(0, (FMSG *)vd_space);
      }
     #endif
     /* Restore the file owner */
     #if TARGET==UNIX
      if(((p_eh=eh_lookup(eh, OWNER_ID))!=NULL||
          (p_eh=eh_lookup(eh, OWNER_ID_NUM))!=NULL)
     #if SFX_LEVEL>=ARJ
         &&do_chown
     #endif
         )
      {
       raw_eh=p_eh->raw;                /* No unpacking, etc. (for now) */
       if(set_owner(raw_eh, tmp_tmp_filename, (p_eh->tag==OWNER_ID)))
       {
        msg_cprintf(H_ERR, M_CANT_CHOWN);
        if(errorlevel==ARJ_ERL_SUCCESS)
         errorlevel=ARJ_ERL_WARNING;
       }
      }
     #endif
     /* Deflate and store the extended attributes */
     #ifdef HAVE_EAS
      if(ea_supported&&(p_eh=eh_lookup(eh, EA_ID))!=NULL)
      {
       raw_eh=unpack_ea(p_eh);
       if(set_ea(raw_eh, tmp_tmp_filename))
       {
        msg_cprintf(H_ALERT, M_CANT_SET_EA);
        if(errorlevel==ARJ_ERL_SUCCESS)
         errorlevel=ARJ_ERL_WARNING;
       }
       else
       {
        ea_size=get_ea_size(tmp_tmp_filename);
        if(ea_size>0)
        {
         msg_cprintf(H_HL, M_EA_STATS_STG, ea_size);
         msg_cprintf(0, (FMSG *)vd_space);
        }
       }
       farfree(raw_eh);
      }
     #endif
     }
     /* Set the timestamps, since the file won't be affected by any
        modifications anymore */
     file_setftime(tmp_tmp_filename, ts_native(&ftime_stamp, OS));
     if(lfn_supported!=LFN_NOT_SUPPORTED&&ts_valid(atime_stamp))
     {
      file_setctime(tmp_tmp_filename, ts_native(&ctime_stamp, OS));
      file_setatime(tmp_tmp_filename, ts_native(&atime_stamp, OS));
     }
     /* Finalize by restoring the attirbutes */
     if(test_host_os(host_os)&&!execute_cmd)
     {
      #if SFX_LEVEL>=ARJ
       if(filter_fa_arch<=FAA_RESTORE_CLEAR)
        dos_chmod(tmp_tmp_filename, file_mode.native);
       if(filter_fa_arch==FAA_RESTORE_CLEAR||filter_fa_arch==FAA_EXCL_CLEAR)
        dos_clear_arch_attr(tmp_tmp_filename);
      #else
       dos_chmod(tmp_tmp_filename, file_mode.native);
      #endif
     }
    }
  #if SFX_LEVEL>=ARJ
   }
  #endif
   if(tmp_crc==file_crc&&compsize==0L)
   {
    #if SFX_LEVEL>=ARJ
     if(!help_issued)
     {
      msg_cprintf(0, M_OK);
      write_index_entry(((host_os==OS_WIN95||host_os==OS_WINNT)&&lfn_mode==LFN_DUAL_EXT)?tmp_name:nullstr);
     }
    #else
     msg_cprintf(0, M_OK);
    #endif
   }
   else
   {
    if(!print_with_more)
    {
     msg_cprintf(H_ALERT, M_CRC_ERROR);
     if(errorlevel==ARJ_ERL_SUCCESS)
      errorlevel=ARJ_ERL_CRC_ERROR;
     errors++;
     if(!ignore_crc_errors)
     {
      file_unlink(tmp_tmp_filename);
      tmp_tmp_filename[0]='\0';
      return(0);
     }
    #if SFX_LEVEL>=ARJ
     else
      write_index_entry(idxid_fault);
    #endif
    }
   }
   #if SFX_LEVEL>=ARJ
    if(execute_cmd)
    {
     exec_cmd(cmd_to_exec);
     file_unlink(tmp_tmp_filename);
    }
   #endif
 #endif
  tmp_tmp_filename[0]='\0';
#if SFX_LEVEL>=ARJ
 }
#endif
 return(1);
}

/* Looks for the requested file in the filelist */

#if SFX_LEVEL>=ARJ
FILE_COUNT flist_lookup(FILE_COUNT tag)
#else
FILE_COUNT flist_lookup()
#endif
{
 char tmp_name[FILENAME_MAX];
 FILE_COUNT i;
 int tmp_entry;
 #if SFX_LEVEL>=ARJSFXV
  int flag;
  char *nptr;
  int lp_entry, st_entry;
  char lp_name[FILENAME_MAX], st_name[FILENAME_MAX];
  FILE_COUNT num, ubound;               /* For by-number tagging */
  int n_st, n_tmp;
 #endif

 #if SFX_LEVEL>=ARJ
  if(add_command&&total_chapters!=0&&chapter_number<total_chapters-1)
   return(0);
  if(add_command&&exclude_paths==EP_BASEDIR)
  {
   default_case_path(lp_name, target_dir);
   lp_entry=strlen(lp_name);
  }
  else
   lp_entry=0;
 #endif
 /* In ARJSFXV and ARJ, there is a filelist capability. In ARJSFX, we'll have
    to retrieve command-line arguments */
 #if SFX_LEVEL>=ARJSFXV
  for(i=0; i<flist_main.files; i++)
  {
   flag=cfa_get(i);
  #if SFX_LEVEL>=ARJ
   if((!add_command||flag==FLFLAG_TO_PROCESS)&&
      (!order_command||flag==FLFLAG_TO_PROCESS)&&
      (flag==FLFLAG_TO_PROCESS||flag==FLFLAG_PROCESSED))
  #else
   if(flag==FLFLAG_TO_PROCESS||flag==FLFLAG_PROCESSED)
  #endif
   {
    #if SFX_LEVEL>=ARJ
     flist_retrieve(tmp_name, NULL, &flist_main, i);
    #else
     retrieve_entry(tmp_name, &flist_main, i);
    #endif
   #if SFX_LEVEL>=ARJ
    if(add_command)
    {
     if(debug_enabled&&strchr(debug_opt, 'y')!=NULL)
     {
      strcpy(lp_name, tmp_name);
      strcpy(st_name, filename);
     }
     else
     {
      default_case_path(lp_name, tmp_name);
      default_case_path(st_name, filename);
     }
     tmp_entry=split_name(lp_name, NULL, NULL);
     st_entry=split_name(st_name, NULL, NULL);
     if(exclude_paths==EP_PATH)
     {
      if(match_wildcard(st_name, lp_name+tmp_entry))
       return(i+1);
     }
     else if(tmp_entry-lp_entry==st_entry)
     {
      if(!strncmp_os(st_name, lp_name+lp_entry, st_entry))
      {
       if(match_wildcard(st_name+st_entry, lp_name+tmp_entry))
        return(i+1);
      }
     }
    }
    else
    {
   #endif
    #if SFX_LEVEL>=ARJ
     if(debug_enabled&&strchr(debug_opt, 'y')!=NULL)
     {
      default_case_path(lp_name, tmp_name);
      default_case_path(st_name, filename);
     }
     else
     {
    #endif
      strcpy(lp_name, tmp_name);
      strcpy(st_name, filename);
    #if SFX_LEVEL>=ARJ
     }
    #endif
     tmp_entry=split_name(lp_name, NULL, NULL);
     st_entry=split_name(st_name, NULL, NULL);
    #if SFX_LEVEL>=ARJ
     if(select_by_number)
     {
      nptr=tmp_name;
      num=(unsigned int)strtoul(nptr, &nptr, 10);
      if(num==tag)
       return(i+1);
      if(*nptr=='-')
      {
       nptr++;
       ubound=(unsigned int)strtoul(nptr, &nptr, 10);
       if(ubound==0)
        ubound=EXT_FILELIST_CAPACITY;
       if(num<=tag&&tag<=ubound)
        return(i+1);
      }
     }
     else
     {
      if(total_chapters!=0)
      {
       if(current_chapter==RESERVED_CHAPTER&&(int)ext_flags==total_chapters&&(int)chapter_number==total_chapters)
        return(0);
       if(current_chapter==0&&(int)ext_flags<=total_chapters&&(int)chapter_number<total_chapters)
        return(0);
       if(current_chapter!=0&&current_chapter<=CHAPTERS_MAX&&((int)ext_flags>chapter_to_process||(int)chapter_number<current_chapter))
        return(0);
      }
    #endif
      if(fnm_matching==FMM_SUBDIRS)
      {
       if(!strncmp_os(lp_name, st_name, tmp_entry))
       {
        n_st=tmp_entry;
        n_tmp=0;
        while(st_name[n_st]!='\0'&&st_name[n_st]!=PATHSEP_DEFAULT)
         tmp_name[n_tmp++]=st_name[n_st++];
        tmp_name[n_tmp]='\0';
        if(match_wildcard(tmp_name, lp_name+tmp_entry))
         return(i+1);
       }
      }
      else if(fnm_matching!=FMM_STD||tmp_entry!=0)
      {
       if(tmp_entry==entry_pos)
       {
        if(!strncmp_os(lp_name, st_name, st_entry))
        {
         if(match_wildcard(st_name+st_entry, lp_name+tmp_entry))
          return(i+1);
        }
       }
      }
      else
      {
       if(match_wildcard(st_name+st_entry, lp_name+tmp_entry))
        return(i+1);
      }
    #if SFX_LEVEL>=ARJ
     }
    #endif
   #if SFX_LEVEL>=ARJ
    }
   #endif
   }
  }
 #else
  for(i=0; i<sflist_args; i++)
  {
   strcpy(tmp_name, sflist[i]);
   tmp_entry=split_name(tmp_name);
   if(fnm_matching!=FMM_STD||tmp_entry!=0)
   {
    if(tmp_entry==entry_pos&&!strncmp_os(tmp_name, filename, tmp_entry))
    {
     if(match_wildcard(list_adapted_name, tmp_name+tmp_entry))
      return(i+1);
    }
   }
   else
   {
    if(match_wildcard(list_adapted_name, tmp_name+tmp_entry))
     return(i+1);
   }
  }
 #endif
 return(0);
}

#if SFX_LEVEL>=ARJ

/* Deletes a file from the archive */

int arcv_delete(FILE_COUNT num)
{
 char del_action;
 unsigned long cur_pos;

 if(query_for_each_file)
 {
  msg_sprintf(misc_buf, M_QUERY_DELETE, filename);
  if(!query_action(REPLY_YES, QUERY_ARCH_OP, (char FAR *)misc_buf))
   return(0);
 }
 if(file_type==ARJT_CHAPTER&&chapter_number!=0&&chapter_mode!=CHAP_NONE&&current_chapter<=CHAPTERS_MAX)
  return(0);
 del_action=1;
 if(delete_processed==DP_EXTRACT)
 {
  cur_pos=(unsigned long)ftell(aistream);
  if(!unpack_file_proc(0, num))
  {
   fseek(aistream, cur_pos, SEEK_SET);
   return(0);
  }
 }
 else
 {
  if(!destfile_extr_validation())
   return(0);
  if(total_chapters!=0&&current_chapter==RESERVED_CHAPTER&&(int)chapter_number==total_chapters)
  {
   special_processing(CFA_MARK, aistream);
   del_action=0;
  }
  else
  {
   if((total_chapters!=0&&current_chapter==RESERVED_CHAPTER&&(int)chapter_number<total_chapters)||
      (total_chapters!=0&&current_chapter==1&&chapter_to_process==RESERVED_CHAPTER)||
      (total_chapters==0||chapter_number<=ext_flags))
    skip_compdata();
   else
   {
    special_processing(CFA_UNMARK, aistream);
    del_action=0;
   }
  }
  write_index_entry(nullstr);
 }
 if(del_action)
  msg_cprintf(H_HL|H_NFMT, M_DELETING, filename);
 total_files++;
 return(1);
}

/* Removes the temporary archive */

void tmp_archive_cleanup()
{
 if(tmp_archive_name!=NULL)
 {
  if(!no_file_activity&&aostream!=NULL)
  {
   file_close(aostream);
   aostream=NULL;
   if(file_unlink(tmp_archive_name))
    error(M_CANT_DELETE, tmp_archive_name);
  }
  aostream=NULL;
  tmp_archive_name[0]='\0';
 }
}

/* Performs general cleanup when the archive is being closed */

void archive_cleanup()
{
 int tmp_display_totals;
 unsigned long tmp_resume_position;
 int tmp_continued_prevvolume;
 int tmp_mvfile_type;
 FILE *tmp_aistream;
 struct ext_hdr FAR *b_eh;

 if(errors!=0)
  error(M_FOUND_N_ERRORS, errors);
 fflush(aostream);
 if(ferror(aostream))
  error(M_DISK_FULL);
 if(file_is_removable(tmp_archive_name))
  reset_drive(tmp_archive_name);        /* Floppy disk cache will be flushed */
 b_eh=eh;
 eh=NULL;
 if(create_index)
 {
  if(msg_fprintf(idxstream, M_TESTING, archive_name)<0)
   error(M_DISK_FULL);
  if(fprintf(idxstream, lf)<0)
   error(M_DISK_FULL);
 }
 cmd_verb=ARJ_CMD_TEST;
 tmp_display_totals=display_totals;
 tmp_resume_position=resume_position;
 tmp_continued_prevvolume=continued_prevvolume;
 tmp_mvfile_type=mvfile_type;
 display_totals=0;
 tmp_aistream=aistream;
 aistream=aostream;                     /* Reverse the operation */
 rewind(aistream);
 find_header(0, aistream);
 read_header(2, aistream, archive_name);
 while(read_header(0, aistream, archive_name))
  unpack_validation(ARJ_CMD_TEST);
 aostream=aistream;
 aistream=tmp_aistream;
 resume_position=tmp_resume_position;
 continued_prevvolume=tmp_continued_prevvolume;
 mvfile_type=tmp_mvfile_type;
 display_totals=tmp_display_totals;
 eh=b_eh;
 if(errors>0)
  error(M_FOUND_N_ERRORS, errors);
}

#endif
