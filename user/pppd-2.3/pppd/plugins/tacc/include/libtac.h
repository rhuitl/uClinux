/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 * Portions copyright 2000 by Jean-Louis Noel <jln@stben.be>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 */

#ifndef _AUTH_TAC_H
#define _AUTH_TAC_H

#if defined(DEBUGTAC) && !defined(TACDEBUG)
#define TACDEBUG(x)	syslog x;
#else
#define TACDEBUG(x)
#endif

/* version.c */
extern int tac_ver_major;
extern int tac_ver_minor;
extern int tac_ver_patch;

/* header.c */
extern int session_id;
extern int tac_encryption;
extern char *tac_secret;

extern int tac_connect(u_long *server, int servers);
extern int tac_authen_pap_send(int fd, char *user, char *pass, char *tty);
extern char *tac_authen_pap_read(int fd);
extern HDR *_tac_req_header(u_char type);
extern void _tac_crypt(u_char *buf, HDR *th, int length);
extern u_char *_tac_md5_pad(int len, HDR *hdr);
extern void tac_add_attrib(struct tac_attrib **attr, char *name, char *value);
extern void tac_free_attrib(struct tac_attrib **attr);
extern int tac_account_send(int fd, int type, char *user, char *tty, char *rem_addr,
	 struct tac_attrib *attr);
extern char *tac_account_read(int fd);
extern void *xcalloc(size_t nmemb, size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern char *_tac_check_header(HDR *th, int type);
extern int tac_author_send(int fd, char *username, char *tty, 
	struct tac_attrib *attr);
extern void tac_author_read(int fd, struct areply *arep);

#endif

