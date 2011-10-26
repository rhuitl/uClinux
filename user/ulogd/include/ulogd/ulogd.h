#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd, Version $Revision: 1.16 $
 *
 * userspace logging daemon for netfilter ULOG target
 * of the linux 2.4 netfilter subsystem.
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id: ulogd.h 456 2004-04-24 22:50:55Z laforge $
 */

#include <libipulog/libipulog.h>
#include <stdio.h>
#include <signal.h>	/* need this because of extension-sighandler */

/* All types with MSB = 1 make use of value.ptr
 * other types use one of the union's member */

/* types without length */
#define ULOGD_RET_NONE		0x0000

#define ULOGD_RET_INT8		0x0001
#define ULOGD_RET_INT16		0x0002
#define ULOGD_RET_INT32		0x0003
#define ULOGD_RET_INT64		0x0004

#define ULOGD_RET_UINT8		0x0011
#define ULOGD_RET_UINT16	0x0012
#define ULOGD_RET_UINT32	0x0013
#define ULOGD_RET_UINT64	0x0014

#define ULOGD_RET_BOOL		0x0050

#define ULOGD_RET_IPADDR	0x0100

/* types with length field */
#define ULOGD_RET_STRING	0x8020
#define ULOGD_RET_RAW		0x8030


/* FLAGS */
#define ULOGD_RETF_NONE		0x0000
#define ULOGD_RETF_VALID	0x0001	/* contains a valid result */
#define ULOGD_RETF_FREE		0x0002	/* ptr needs to be free()d */


/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 32

#define ULOGD_DEBUG	1	/* debugging information */
#define ULOGD_INFO	3
#define ULOGD_NOTICE	5	/* abnormal/unexpected condition */
#define ULOGD_ERROR	7	/* error condition, requires user action */
#define ULOGD_FATAL	8	/* fatal, program aborted */

extern FILE *logfile;

typedef struct ulog_iret {
	/* next interpreter return (key) in the global list */
	struct ulog_iret *next;
	/* next interpreter in linked list for current result */
	struct ulog_iret *cur_next;
	/* length of the returned value (only for lengthed types */
	u_int32_t len;
	/* type of the returned value (ULOGD_IRET_...) */
	u_int16_t type;
	/* flags (i.e. free, ...) */
	u_int16_t flags;
	/* name of this key */
	char key[ULOGD_MAX_KEYLEN];
	/* and finally the returned value */
	union {
		u_int8_t	b;
		u_int8_t	ui8;
		u_int16_t	ui16;
		u_int32_t	ui32;
		u_int64_t	ui64;
		int8_t		i8;
		int16_t		i16;
		int32_t		i32;
		int64_t		i64;
		void		*ptr;
	} value;
} ulog_iret_t;

typedef struct ulog_interpreter {
	/* next interpreter in old-style linked list */
	struct ulog_interpreter *next;
	/* name of this interpreter (predefined by plugin) */
	char name[ULOGD_MAX_KEYLEN];
	/* ID for this interpreter (dynamically assigned) */
	unsigned int id;
	/* function to call for each packet */
	ulog_iret_t* (*interp)(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt);
	/* number of keys this interpreter has */
	unsigned int key_num;
	/* keys of this particular interpreter */
	ulog_iret_t *result;
} ulog_interpreter_t;

typedef struct ulog_output {
	/* next output in the linked list */
	struct ulog_output *next;
	/* name of this ouput plugin */
	char name[ULOGD_MAX_KEYLEN];
	/* callback for initialization */
	int (*init)(void);
	/* callback for de-initialization */
	void (*fini)(void);
	/* callback function */
	int (*output)(ulog_iret_t *ret);
	/* callback function for signals (SIGHUP, ..) */
	void (*signal)(int signal);
} ulog_output_t;

/* entries of the key hash */
struct ulogd_keyh_entry {
	ulog_interpreter_t *interp;	/* interpreter for this key */
	unsigned int offset;		/* offset within interpreter */
	const char *name;		/* name of this particular key */
};

/***********************************************************************
 * PUBLIC INTERFACE 
 ***********************************************************************/

/* register a new interpreter plugin */
void register_interpreter(ulog_interpreter_t *me);

/* register a new output target */
void register_output(ulog_output_t *me);

/* allocate a new ulog_iret_t */
ulog_iret_t *alloc_ret(const u_int16_t type, const char*);

/* write a message to the daemons' logfile */
void __ulogd_log(int level, char *file, int line, const char *message, ...);
/* macro for logging including filename and line number */
#define ulogd_log(level, format, args...) \
	__ulogd_log(level, __FILE__, __LINE__, format, ## args)
/* backwards compatibility */
#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)

/* get an interpreter hash id by name */
unsigned int interh_getid(const char *name);

/* get a key id if you have the name */
unsigned int keyh_getid(const char *name);

/* get a result for a given key id */
ulog_iret_t *keyh_getres(unsigned int id);

/* the key hash itself */
extern struct ulogd_keyh_entry *ulogd_keyh;

#define IS_VALID(x)	(x.flags & ULOGD_RETF_VALID)

#define SET_VALID(x)	(x.flags |= ULOGD_RETF_VALID)

#endif /* _ULOGD_H */
