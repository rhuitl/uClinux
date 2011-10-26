/*
 * $Id: misc.h,v 1.2 2004/02/20 23:18:59 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in MISC.C are declared here.
 *
 */

#ifndef MISC_INCLUDED
#define MISC_INCLUDED

#include "arjtypes.h"
#include "filelist.h"

/* ASCIIZ string copy macro */

#define strcpyn(dest, src, n)      \
{                                  \
 strncpy(dest, src, n-1);          \
 (dest)[n-1]='\0';                 \
}

/* Numerical variables exchange macro */

#define swap(a, b)        b^=a^=b^=a

/* Prototypes */

void unix_path_to_dos(char *path);
void *malloc_str(char *str);
void *malloc_far_str(char FAR *str);
void cur_time_stamp(struct timestamp *dest);
#if !defined(TILED)
 #define far_strchr(str, chr) strchr(str, chr)
 #define far_strcmp(str1, str2) strcmp(str1, str2)
 #define far_stricmp(str1, str2) stricmp(str1, str2)
 #define far_strcat(dest, src) strcat(dest, src)
 #define far_strcpy(dest, src) strcpy(dest, src)
 #define far_strlen(str) strlen(str)
 #define far_memset(buf, filler, size) memset(buf, filler, size)
#elif COMPILER==MSC
 #define far_strchr(str, chr) _fstrchr(str, chr)
 #define far_strcmp(str1, str2) _fstrcmp(str1, str2)
 #define far_stricmp(str1, str2) _fstricmp(str1, str2)
 #define far_strcat(dest, src) _fstrcat(dest, src)
 #define far_strcpy(dest, src) _fstrcpy(dest, src)
 #define far_strlen(str) _fstrlen(str)
 #define far_memset(buf, filler, size) _fmemset(buf, filler, size)
#else
 char FAR *far_strchr(char FAR *str, char chr);
 int far_strcmp(char FAR *str1, char FAR *str2);
 int far_stricmp(char FAR *str1, char FAR *str2);
 char FAR *far_strcat(char FAR *dest, char FAR *src);
 char FAR *far_strcpy(char FAR *dest, char FAR *src);
 unsigned int far_strlen(char FAR *str);
 void FAR *far_memset(void FAR *buf, int filler, unsigned int size);
#endif
char FAR *far_strcpyn(char FAR *dest, char FAR *src, int limit);
void to_7bit(char *str);
void strupper(char *s);
void strlower(char *s);

#if SFX_LEVEL>=ARJ
int flist_find(struct flist_root *root, char *name);
int flist_is_in_archive(struct flist_root *root, char *name);
int match_attrib(struct file_properties *properties);
void flist_cleanup(struct flist_root *root);
int flist_add(struct flist_root *root, struct flist_root *search_flist, char *name, FILE_COUNT *count, struct file_properties *properties);
void flist_init(struct flist_root *root, FILE_COUNT maxfiles, char type);
void flist_retrieve(char *dest, struct file_properties *properties, struct flist_root *root, FILE_COUNT entry);
#endif
#if SFX_LEVEL>=ARJSFXV
int flist_add_files(struct flist_root *root, struct flist_root *search_flist, char *name, int expand_wildcards, int recurse_subdirs, int file_type, FILE_COUNT *count);
#endif

/* Compact/tradidional internal filelists. For some reason, the compact
   filelist feature is not used in ARJSFXV v 2.72. This hasn't been verified
   since then and is now being dropped -- ASR 17/01/2001 */

void cfa_shutdown();
int cfa_get(FILE_COUNT num);
void cfa_store(FILE_COUNT num, int value);
int cfa_init(FILE_COUNT capacity);

void *malloc_msg(unsigned int size);
void FAR *farmalloc_msg(unsigned long size);
void FAR *farrealloc_msg(void FAR *memblock, unsigned long size);

#ifdef REARJ

char *tokenize_lf(char *str);

#endif

/* A platform-neutral far_strcmp substitution */

#ifdef CASE_SENSITIVE
 #define far_strccmp    far_stricmp
#else
 #define far_strccmp    far_strcmp
#endif

#endif
