/*
 * $Id: arj_arcv.h,v 1.1.1.1 2002/03/28 00:01:38 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ARJ_ARCV.C are declared here.
 *
 */

#ifndef ARJ_ARCV_INCLUDED
#define ARJ_ARCV_INCLUDED

/* Header sizes */

#define STD_HDR_SIZE              30    /* Size of standard header */
#define R9_HDR_SIZE               46    /* Minimum size of header that holds
                                           DTA/DTC */
/* Prototypes */

long find_header(int search_all, FILE *stream);
#if SFX_LEVEL>=ARJSFXV
int read_header(int first, FILE *stream, char *name);
#else
int read_header(int first);
#endif
void create_header(int first);
void write_header();
int rename_file();
int supply_comment(char *cmtname, char *name);
void fill_archive_header();
void final_header(int operation);
void skip_compdata();
void skip_file();
void arjdisp_scrn(unsigned long bytes);
void special_processing(int action, FILE *stream);
void init_packing(unsigned long offset, int is_mv);
int pack_file(int is_update, int is_replace);
int pack_file_stub(int is_update, int is_replace);
int create_chapter_mark();
int store_label();
FILE_COUNT copy_archive();
void add_base_dir(char *name);
#if SFX_LEVEL>=ARJ
int unpack_validation(int cmd);
#else
int unpack_validation();
#endif
char FAR *unpack_ea(struct ext_hdr FAR *eh);
#if SFX_LEVEL>=ARJ
int unpack_file_proc(int to_console, FILE_COUNT num);
#else
int unpack_file_proc();
#endif
#if SFX_LEVEL>=ARJ
FILE_COUNT flist_lookup(FILE_COUNT tag);
#else
FILE_COUNT flist_lookup();
#endif
int arcv_delete(FILE_COUNT num);
void tmp_archive_cleanup();
void archive_cleanup();

#endif

