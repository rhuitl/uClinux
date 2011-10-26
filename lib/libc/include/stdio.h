#ifndef __STDIO_H
#define __STDIO_H

#include <features.h>
#include <sys/types.h>

__BEGIN_DECLS

#include <stdarg.h>

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#define _IOFBF		0x00	/* full buffering */
#define _IOLBF		0x01	/* line buffering */
#define _IONBF		0x02	/* no buffering */
#define __MODE_BUF	0x03	/* Modal buffering dependent on isatty */

#define __MODE_FREEBUF	0x04	/* Buffer allocated with malloc, can free */
#define __MODE_FREEFIL	0x08	/* FILE allocated with malloc, can free */

#define __MODE_READ	0x10	/* Opened in read only */
#define __MODE_WRITE	0x20	/* Opened in write only */
#define __MODE_RDWR	0x30	/* Opened in read/write */

#define __MODE_READING	0x40	/* Buffer has pending read data */
#define __MODE_WRITING	0x80	/* Buffer has pending write data */

#define __MODE_EOF	0x100	/* EOF status */
#define __MODE_ERR	0x200	/* Error status */
#define __MODE_UNGOT	0x400	/* Buffer has been polluted by ungetc */

#define __MODE_IOTRAN	0

/* when you add or change fields here, be sure to change the initialization
 * in stdio_init and fopen */
struct __stdio_file {
  unsigned char *bufpos;   /* the next byte to write to or read from */
  unsigned char *bufread;  /* the end of data returned by last read() */
  unsigned char *bufwrite; /* highest address writable by macro */
  unsigned char *bufstart; /* the start of the buffer */
  unsigned char *bufend;   /* the end of the buffer; ie the byte after the last
                              malloc()ed byte */

  int fd; /* the file descriptor associated with the stream */
  int mode;

  char unbuf[8];	   /* The buffer for 'unbuffered' streams */

  struct __stdio_file * next;
};


#define EOF	(-1)
#ifndef NULL
#define NULL	(0)
#endif

typedef struct __stdio_file FILE;
typedef off_t fpos_t;

#define BUFSIZ	(500) /*(508) should get us a fully used kmalloc bucket */

extern FILE stdin[1];
extern FILE stdout[1];
extern FILE stderr[1];


#define putc(c, stream)	\
    (((stream)->bufpos >= (stream)->bufwrite) ? fputc((c), (stream))	\
                          : (unsigned char) (*(stream)->bufpos++ = (c))	)

#define getc(stream)	\
  (((stream)->bufpos >= (stream)->bufread) ? fgetc(stream):		\
    (*(stream)->bufpos++))

#define putchar(c) putc((c), stdout)  
#define getchar() getc(stdin)

#define ferror(fp)	(((fp)->mode&__MODE_ERR) != 0)
#define feof(fp)   	(((fp)->mode&__MODE_EOF) != 0)
#define clearerr(fp)	((fp)->mode &= ~(__MODE_EOF|__MODE_ERR),0)
#define fileno(fp)	((fp)->fd)

/* These two call malloc */
#define setlinebuf(__fp)             setvbuf((__fp), (char*)0, _IOLBF, 0)
extern int setvbuf __P((FILE*, char*, int, size_t));

/* These don't */
extern void setbuffer __P((FILE*, char*, int));
static __inline__ void setbuf(FILE *stream, char *buf) {
	return(setbuffer(stream, buf, BUFSIZ));
}

extern int fgetc __P((FILE*));
extern int fputc __P((int, FILE*));

extern int fclose __P((FILE*));
extern int fflush __P((FILE*));
extern char *fgets __P((char*, size_t, FILE*));
extern FILE *__fopen __P((__const char*, int, FILE*, __const char*));

#define fopen(__file, __mode)         __fopen((__file), -1, (FILE*)0, (__mode))
#define freopen(__file, __mode, __fp) __fopen((__file), -1, (__fp), (__mode))
#define fdopen(__file, __mode)  __fopen((char*)0, (__file), (FILE*)0, (__mode))

extern int fseek __P((FILE*, long, int));
extern long ftell __P((FILE*));
extern void rewind __P((FILE*));
extern int fgetpos __P((FILE *, fpos_t *));
extern int fsetpos __P((FILE *, fpos_t *));

extern size_t fread __P((void *, size_t, size_t, FILE *));
extern size_t fwrite __P((const void *, size_t, size_t, FILE *));
extern int fputs __P((__const char*, FILE*));
extern int puts __P((__const char*));

extern int printf __P ((__const char*, ...));
extern int fprintf __P ((FILE*, __const char*, ...));
extern int sprintf __P ((char*, __const char*, ...));

extern int vscanf __P ((__const char*, va_list));
extern int vfscanf __P ((FILE*, __const char*, va_list));
extern int vsscanf __P ((__const char*, __const char*, va_list));
extern int snprintf __P ((char *, size_t, __const char *, ...));
extern int vprintf __P ((__const char*, va_list));
extern int vfprintf __P ((FILE*, __const char*, va_list));
extern int vsprintf __P ((char*, __const char*, va_list));
extern int vsnprintf __P ((char*, size_t, __const char*, va_list));
extern int asprintf __P ((char**, __const char*, ...));
extern int vasprintf __P ((char**, __const char*, va_list));
extern int scanf __P ((__const char *format, ...));
extern int fscanf __P ((FILE*, __const char*, ...));
extern int sscanf __P ((__const char *, __const char *, ...));

extern int ungetc __P ((int c, FILE * stream));

extern FILE *popen __P((__const char *, __const char *));
extern int pclose __P ((FILE *));

extern void perror __P ((__const char *));

extern int remove __P ((__const char *));

extern int rename __P((__const char* _old, __const char* _new));

extern char *tmpnam __P ((char *));
extern char *tempnam __P ((__const char *, __const char *));

#define stdio_pending(fp) ((fp)->bufread>(fp)->bufpos)

#ifdef __USE_GNU
/* Read up to (and including) a DELIMITER from STREAM into *LINEPTR
   (and null-terminate it). *LINEPTR is a pointer returned from malloc (or
   NULL), pointing to *N characters of space.  It is realloc'd as
   necessary.  Returns the number of characters read (not including the
   null terminator), or -1 on error or EOF.  */
extern ssize_t __getdelim __P ((char **__restrict __lineptr,
				    size_t *__restrict __n, int __delimiter,
				    FILE *__restrict __stream));
extern ssize_t getdelim __P ((char **__restrict __lineptr,
				  size_t *__restrict __n, int __delimiter,
				  FILE *__restrict __stream));

/* Like `getdelim', but reads up to a newline.  */
extern ssize_t getline __P ((char **__restrict __lineptr,
				 size_t *__restrict __n,
				 FILE *__restrict __stream));
#endif

__END_DECLS

#endif /* __STDIO_H */
