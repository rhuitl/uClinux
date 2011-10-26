#ifndef SSL_H
#define SSL_H

#include "sstr.h"

#ifdef DO_SSL
void ssl_init(void);
void *ssl_initfd(int fd, int type);
void ssl_shutdown(void **ssl);
int ssl_append_read(void *ssl, sstr * buf, int len);
int ssl_write(void *ssl, sstr * buf);
int ssl_parsed_reply(int code, sstr * msg);
#else
static inline void ssl_init(void)
{
};
static inline void *ssl_initfd(int fd, int type)
{
	return NULL;
};
static inline void ssl_shutdown(void **ssl)
{
};
static inline int ssl_append_read(void *s, sstr * b, int len)
{
	return -1;
};
static inline int ssl_write(void *s, sstr * b)
{
	return -1;
};
static inline int ssl_parsed_reply(int code, sstr * msg)
{
	return 0;
};
#endif

#define SSL_CTRL 0
#define SSL_DATA 1

#endif /*SSL_H */
