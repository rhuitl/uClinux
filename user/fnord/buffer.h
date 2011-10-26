#ifndef BUFFER_H
#define BUFFER_H

#include <limits.h>
#include <unistd.h>

typedef struct buffer {
  char *x;
  unsigned int p;
  unsigned int n;
  unsigned int a;
  int fd;
  int (*op)();
} buffer;

#define BUFFER_INIT(op,fd,buf,len) { (buf), 0, 0, (len), (fd), (op) }
#define BUFFER_INIT_READ(op,fd,buf,len) BUFFER_INIT(op,fd,buf,len) /*obsolete*/
#define BUFFER_INSIZE 8192
#define BUFFER_OUTSIZE 8192

extern void buffer_init(buffer* b,int (*op)(),int fd,char* y,unsigned int ylen);

extern int buffer_flush(buffer* b);
extern int buffer_put(buffer* b,const char* x,unsigned int len);
extern int buffer_putalign(buffer* b,const char* x,unsigned int len);
extern int buffer_putflush(buffer* b,const char* x,unsigned int len);
extern int buffer_puts(buffer* b,const char* x);
extern int buffer_putsalign(buffer* b,const char* x);
extern int buffer_putsflush(buffer* b,const char* x);

extern int buffer_putspace(buffer* b);

#define buffer_PUTC(s,c) \
  ( ((s)->a != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : buffer_put((s),&(c),1) \
  )

extern int buffer_get(buffer* b,char* x,unsigned int len);
extern int buffer_bget(buffer* b,char* x,unsigned int len);
extern int buffer_feed(buffer* b);
extern int buffer_getc(buffer* b,char* x);
extern int buffer_getn(buffer* b,char* x,unsigned int len);
extern int buffer_get_token(buffer* b,char* x,unsigned int len,const char* charset,unsigned int setlen);
#define buffer_getline(b,x,len) buffer_get_token((b),(x),(len),"\n",1)

extern char *buffer_peek(buffer* b);
extern void buffer_seek(buffer* b,unsigned int len);

#define buffer_PEEK(s) ( (s)->x + (s)->p )
#define buffer_SEEK(s,len) ( (s)->p += (len) )

#define buffer_GETC(s,c) \
  ( ((s)->p < (s>->n) \
    ? ( *(c) = *buffer_PEEK(s), buffer_SEEK((s),1), 1 ) \
    : buffer_get((s),(c),1) \
  )

extern int buffer_copy(buffer* out,buffer* in);

extern int buffer_putulong(buffer *b,unsigned long l);
extern int buffer_put8long(buffer *b,unsigned long l);
extern int buffer_putxlong(buffer *b,unsigned long l);
extern int buffer_putlong(buffer *b,unsigned long l);
extern int buffer_putulonglong(buffer *b,unsigned long long l);

extern buffer *buffer_0;
extern buffer *buffer_0small;
extern buffer *buffer_1;
extern buffer *buffer_1small;
extern buffer *buffer_2;

#endif
