/*
 * $Id: arj_file.h,v 1.3 2003/04/27 20:54:41 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ARJ_FILE.C are declared here.
 *
 */

#ifndef ARJ_FILE_INCLUDED
#define ARJ_FILE_INCLUDED

/* Writes a block to the output file and verifies if all has been written */

#define file_write(block, el, len, stream) \
{                                          \
 if(fwrite(block, el, len, stream)!=len)   \
  error(M_DISK_FULL);                      \
}

/* Prototypes */

int file_close(FILE *stream);
FILE *file_open_noarch(char *name, char *mode);
FILE *file_create(char *name, char *mode);
int fget_byte(FILE *stream);
unsigned int fget_word(FILE *stream);
unsigned long fget_longword(FILE *stream);
int fread_crc(char *buffer, int count, FILE *stream);
void fwrite_crc(char *buffer, int count, FILE *stream);
int extraction_stub(char *block, int block_len, int action);
void decode_start_stub();
void decode_end_stub();
char *find_tmp_filename(char *name_format);
int find_num_ext(char *name, int mode);
int find_arcmail_name(char *name);
void query_cmd();
#if SFX_LEVEL>=ARJSFXV
int query_action(int def, int qtype, FMSG *query);
#else
int query_action();
#endif
int pause();
void nputlf();
int delete_files(char *name);
#if SFX_LEVEL>=ARJSFXV
void display_comment(char FAR *cmt);
#else
void display_comment(char *cmt);
#endif
void display_indicator(long bytes);
#ifdef REARJ
int rename_with_check(char *oldname, char *newname);
#else
void rename_with_check(char *oldname, char *newname);
#endif
int delete_processed_files(struct flist_root *root);
void fput_byte(int c, FILE *stream);
void fput_word(unsigned int w, FILE *stream);
void fput_dword(unsigned long l, FILE *stream);
void flush_compdata();
void init_putbits();
void shutdown_putbits();
int group_clear_arch(struct flist_root *root);

#endif

