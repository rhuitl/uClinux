#ifndef _ZLIB_SUPPORT_H
#define _ZLIB_SUPPORT_H

/* Grab file.  Decompresses if that is supported.  Returns NULL on error. */
extern void *grab_file(const char *filename, unsigned long *size);
extern void *grab_fd(int fd, unsigned long *size);

/* Free it up. */
extern void release_file(void *data, unsigned long size);

#endif /* _ZLIB_SUPPORT_H */
