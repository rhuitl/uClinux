/*
 * $Id: fardata.h,v 1.2 2003/02/07 17:21:12 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in FARDATA.C are declared here.
 *
 */

#ifndef FARDATA_INCLUDED
#define FARDATA_INCLUDED

/* Prototypes */

int error_proc(FMSG *errmsg, ...);

#ifdef DEBUG
 #define error dbg_dummy=debug_report(dbg_cur_file, __LINE__, 'E')||error_proc
#else
 #define error error_proc
#endif

#ifndef TILED
 #define far_memmove memmove
#endif

int msg_cprintf(int ccode, FMSG *fmt, ...);
#ifdef COLOR_OUTPUT
int parse_colors(char *opt);
#endif

#ifdef FMSG_ST

int msg_printf(FMSG *fmt, ...);
int msg_fprintf(FILE *stream, FMSG *fmt, ...);
int msg_sprintf(char *str, FMSG *fmt, ...);
#ifdef TILED
 void far_memmove(char FAR *dest, char FAR *src, int length);
#endif
void init_crc();
void crc_for_block(char *block, unsigned int length);
void crc_for_string(char *str);

#define msg_strcpy(dest, src) far_strcpy((char FAR *)dest, src)
#define msg_strcpyn far_strcpyn
#define msg_strchr far_strchr
#define msg_strcmp far_strcmp
#define msg_strcat(dest, src) far_strcat((char FAR *)dest, src)
#define malloc_fmsg(msg) malloc_far_str(msg)
#define free_fmsg free

#else

#define msg_printf printf
#if SFX_LEVEL>=ARJSFXV
#define msg_fprintf fprintf
#endif
#define msg_sprintf sprintf
#define msg_strcpy strcpy
#define msg_strcpyn strcpyn
#define msg_strchr strchr
#define msg_strcat strcat
#define msg_strcmp strcmp
#define malloc_fmsg(msg) msg
#define free_fmsg(ptr)
#define crc_for_block crc32_for_block
#define crc_for_string crc32_for_string

#endif

#endif
