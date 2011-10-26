#ifndef DATABUF_DOT_H
#define DATABUF_DOT_H

typedef struct _databuf_st DataBuf;

extern DataBuf *databuf_new();
extern void databuf_dest( DataBuf * );
extern void databuf_buf_set( DataBuf *, void *, size_t  );
extern int databuf_write( DataBuf *, int  );
extern int databuf_read( DataBuf *dbuf, int fd );

#endif
