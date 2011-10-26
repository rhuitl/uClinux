/*
 * Copyright 2004,2005,2006,2007,2008,2009 Red Hat, Inc.
 * Copyright 2004 Kungliga Tekniska Högskolan
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

 /*
  * A miniature afslog implementation.  Requires a running krb524 server or a
  * v4-capable KDC, or cells served by OpenAFS 1.2.8 or later in combination
  * with MIT Kerberos 1.2.6 or later.
  *
  * References:
  *   http://grand.central.org/numbers/pioctls.html
  *   http://www.afsig.se/afsig/space/rxgk-client-integration
  *   auth/afs_token.xg
  */

#include "../config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
 
#include KRB5_H

#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include "init.h"
#include "log.h"
#include "minikafs.h"
#include "v5.h"
#include "xstr.h"

#ifndef KRB_TICKET_GRANTING_TICKET
#ifdef KRB5_TGS_NAME
#define KRB_TICKET_GRANTING_TICKET KRB5_TGS_NAME
#else
#define KRB_TICKET_GRANTING_TICKET "krbtgt"
#endif
#endif

#define HOSTNAME_SIZE NI_MAXHOST

#define OPENAFS_AFS_IOCTL_FILE  "/proc/fs/openafs/afs_ioctl"
#define ARLA_AFS_IOCTL_FILE     "/proc/fs/nnpfs/afs_ioctl"

#ifdef sun
#ifndef __NR_afs_syscall
#define __NR_afs_syscall 65
#endif
#endif

/* Global(!) containing the path to the file/device/whatever in /proc which we
 * can use to get the effect of the AFS syscall.  If we ever need to be
 * thread-safe, we'll have to lock around accesses to this. */
static const char *minikafs_procpath = NULL;

#define VIOCTL_SYSCALL ((unsigned int) _IOW('C', 1, void *))
#define VIOCTL_FN(id)  ((unsigned int) _IOW('V', (id), struct minikafs_ioblock))
#define CIOCTL_FN(id)  ((unsigned int) _IOW('C', (id), struct minikafs_ioblock))
#define OIOCTL_FN(id)  ((unsigned int) _IOW('O', (id), struct minikafs_ioblock))
#define AIOCTL_FN(id)  ((unsigned int) _IOW('A', (id), struct minikafs_ioblock))

/* A structure specifying parameters to the VIOCTL_SYSCALL ioctl.  An array
 * would do as well, but this makes the order of items clearer. */
struct minikafs_procdata {
	long param4;
	long param3;
	long param2;
	long param1;
	long function;
};

/* A structure specifying input/output buffers to pioctl functions. */
struct minikafs_ioblock {
	char *in, *out;
	uint16_t insize, outsize;
};

/* The portion of a token which includes our own key and other bookkeeping
 * stuff.  Along with a magic blob used by rxkad, the guts of rxkad tokens. */
struct minikafs_plain_token {
	uint32_t kvno;
	char key[8];
	uint32_t uid;
	uint32_t start, end; /* must be odd (?) */
};

/* Functions called through minikafs_syscall().  Might not port to your system. */
enum minikafs_subsys {
	minikafs_subsys_pioctl = 20,
	minikafs_subsys_setpag = 21,
};

/* Subfunctions called through minikafs_pioctl(). */
enum minikafs_pioctl_fn {
	minikafs_pioctl_bogus = VIOCTL_FN(0),
	minikafs_pioctl_settoken = VIOCTL_FN(3),
	minikafs_pioctl_flush = VIOCTL_FN(6),
	minikafs_pioctl_gettoken = VIOCTL_FN(8),
	minikafs_pioctl_unlog = VIOCTL_FN(9),
	minikafs_pioctl_whereis = VIOCTL_FN(14),
	minikafs_pioctl_unpag = VIOCTL_FN(21),
	minikafs_pioctl_getcelloffile = VIOCTL_FN(30),
	minikafs_pioctl_getwscell = VIOCTL_FN(31),
	minikafs_pioctl_gettoken2 = CIOCTL_FN(7),
	minikafs_pioctl_settoken2 = CIOCTL_FN(8),
	minikafs_pioctl_getprop = CIOCTL_FN(10),
	minikafs_pioctl_setprop = CIOCTL_FN(11),
};

/* Forward declarations. */
static int minikafs_5settoken2(const char *cell, krb5_creds *creds);

/* Call AFS using an ioctl. Might not port to your system. */
static int
minikafs_ioctlcall(long function, long arg1, long arg2, long arg3, long arg4)
{
	int fd, ret, saved_errno;
	struct minikafs_procdata data;
	fd = open(minikafs_procpath, O_RDWR);
	if (fd == -1) {
		errno = EINVAL;
		return -1;
	}
	data.function = function;
	data.param1 = arg1;
	data.param2 = arg2;
	data.param3 = arg3;
	data.param4 = arg4;
	ret = ioctl(fd, VIOCTL_SYSCALL, &data);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

/* Call the AFS syscall. Might not port to your system. */
static int
minikafs_syscall(long function, long arg1, long arg2, long arg3, long arg4)
{
#ifdef __NR_afs_syscall
	return syscall(__NR_afs_syscall, function, arg1, arg2, arg3, arg4);
#else
	errno = ENOSYS;
	return -1;
#endif
}

/* Call into AFS, somehow. */
static int
minikafs_call(long function, long arg1, long arg2, long arg3, long arg4)
{
	if (minikafs_procpath != NULL) {
		return minikafs_ioctlcall(function, arg1, arg2, arg3, arg4);
	}
	return minikafs_syscall(function, arg1, arg2, arg3, arg4);
}

/* Make an AFS pioctl. Might not port to your system. */
static int
minikafs_pioctl(char *file, enum minikafs_pioctl_fn subfunction,
		struct minikafs_ioblock *iob)
{
	return minikafs_call(minikafs_subsys_pioctl, (long) file,
			     subfunction, (long) iob, 0);
}

/* Determine in which cell a given file resides.  Returns 0 on success. */
int
minikafs_cell_of_file(const char *file, char *cell, size_t length)
{
	struct minikafs_ioblock iob;
	char *wfile;
	int i;

	wfile = xstrdup(file ? file : "/afs");

	memset(&iob, 0, sizeof(iob));
	iob.in = wfile;
	iob.insize = strlen(wfile) + 1;
	iob.out = cell;
	iob.outsize = length;

	i = minikafs_pioctl(wfile, minikafs_pioctl_getcelloffile, &iob);

	xstrfree(wfile);
	return i;
}

/* Do minikafs_cell_of_file, but if we can't find out, walk up the filesystem
 * tree until we either get an answer or hit the root directory. */
int
minikafs_cell_of_file_walk_up(const char *file, char *cell, size_t length)
{
	char *p, dir[PATH_MAX + 1];
	int i;

	snprintf(dir, sizeof(dir), "%s", file);
	do {
		memset(cell, '\0', length);
		i = minikafs_cell_of_file(dir, cell, length);
		if (i != 0) {
			p = strrchr(dir, '/');
			if (p != NULL) {
				*p = '\0';
			} else {
				strcpy(dir, "");
			}
		}
	} while ((i != 0) && (strlen(dir) > 0));
	return i;
}

/* Determine if AFS is running. Unlike most other functions, return 0 on
 * FAILURE. */
int
minikafs_has_afs(void)
{
	char cell[PATH_MAX];
	int fd, i, ret;
	struct sigaction news, olds;

	fd = -1;

#ifdef OPENAFS_AFS_IOCTL_FILE
	if (fd == -1) {
		fd = open(OPENAFS_AFS_IOCTL_FILE, O_RDWR);
		if (fd != -1) {
			minikafs_procpath = OPENAFS_AFS_IOCTL_FILE;
			close(fd);
			return 1;
		}
	}
#endif
#ifdef ARLA_AFS_IOCTL_FILE
	if (fd == -1) {
		fd = open(ARLA_AFS_IOCTL_FILE, O_RDWR);
		if (fd != -1) {
			minikafs_procpath = ARLA_AFS_IOCTL_FILE;
			close(fd);
			return 1;
		}
	}
#endif
	if (fd == -1) {
		return 0;
	}

	memset(&news, 0, sizeof(news));
	news.sa_handler = SIG_IGN;
	i = sigaction(SIGSYS, &news, &olds);
	if (i != 0) {
		return 0;
	}

	ret = 0;
	i = minikafs_cell_of_file(NULL, cell, sizeof(cell));
	if ((i == 0) || ((i == -1) && (errno != ENOSYS))) {
		ret = 1;
	}

	sigaction(SIGSYS, &olds, NULL);

	return ret;
}

/* Determine in which realm a cell exists.  We do this by obtaining the address
 * of the fileserver which holds /afs/cellname (assuming that the root.cell
 * volume from the cell is mounted there), converting the address to a host
 * name, and then asking libkrb5 to tell us to which realm the host belongs. */
static int
minikafs_realm_of_cell_with_ctx(krb5_context ctx,
				struct _pam_krb5_options *options,
				const char *cell,
				char *realm, size_t length)
{
	struct minikafs_ioblock iob;
	struct sockaddr_in sin;
	in_addr_t *address;
	krb5_context use_ctx;
	char *path, host[HOSTNAME_SIZE], **realms;
	int i, n_addresses, ret;

	if (cell) {
		path = malloc(strlen(cell) + 6);
	} else {
		path = malloc(5);
	}
	if (path == NULL) {
		return -1;
	}
	if (cell) {
		sprintf(path, "/afs/%s", cell);
	} else {
		sprintf(path, "/afs");
	}

	n_addresses = 16;
	do {
		/* allocate the output buffer for the address [list] */
		address = malloc(n_addresses * sizeof(address[0]));
		if (address == NULL) {
			ret = -1;
			break;
		}
		memset(address, 0, n_addresses * sizeof(address[0]));
		memset(&iob, 0, sizeof(iob));
		iob.in = path;
		iob.insize = strlen(path) + 1;
		iob.out = (char*) &address[0];
		iob.outsize = n_addresses * sizeof(address[0]);
		ret = minikafs_pioctl(path, minikafs_pioctl_whereis, &iob);
		/* if we failed, free the address [list], and if the error was
		 * E2BIG, increase the size we'll use next time, up to a
		 * hard-coded limit */
		if (ret != 0) {
			if (options->debug) {
				debug("error during whereis pioctl: %s",
				      strerror(errno));
			}
			free(address);
			address = NULL;
			if (errno == E2BIG) {
				if (n_addresses > 256) {
					if (options->debug) {
						debug("giving up");
					}
					break;
				}
				if (options->debug) {
					debug("retrying");
				}
				n_addresses *= 2;
			}
		}
	} while ((ret != 0) && (errno == E2BIG));

	if (ret != 0) {
		if (options->debug > 1) {
			debug("got error %d (%s) determining file server for "
			      "\"%s\"", errno, v5_error_message(errno), path);
		}
		free(path);
		return ret;
	}
	free(path);

	sin.sin_family = AF_INET;
	if (options->debug > 1) {
		for (i = 0; (i < n_addresses) && (address[i] != 0); i++) {
			debug("file server for \"/afs/%s\" is %u.%u.%u.%u",
			      cell,
			      (address[i] >>  0) & 0xff,
			      (address[i] >>  8) & 0xff,
			      (address[i] >> 16) & 0xff,
			      (address[i] >> 24) & 0xff);
		}
	}

	if (ctx == NULL) {
		if (_pam_krb5_init_ctx(&use_ctx, 0, NULL) != 0) {
			free(address);
			return -1;
		}
	} else {
		use_ctx = ctx;
	}

	for (i = 0; (i < n_addresses) && (address[i] != 0); i++) {
		memcpy(&sin.sin_addr, &address[i], sizeof(address[i]));
		if (getnameinfo((const struct sockaddr*) &sin, sizeof(sin),
				host, sizeof(host), NULL, 0,
				NI_NAMEREQD) == 0) {
			if (options->debug > 1) {
				debug("file server %d.%d.%d.%d has name %s",
				      (address[i] >>  0) & 0xff,
				      (address[i] >>  8) & 0xff,
				      (address[i] >> 16) & 0xff,
				      (address[i] >> 24) & 0xff,
				      host);
			}
			if (krb5_get_host_realm(use_ctx, host, &realms) == 0) {
				strncpy(realm, realms[0], length - 1);
				realm[length - 1] = '\0';
				krb5_free_host_realm(use_ctx, realms);
				if (options->debug > 1) {
					debug("%s is in realm %s", host, realm);
				}
				i = 0;
				break;
			}
		} else {
			if (options->debug > 1) {
				debug("error %d(%s) determining realm for %s",
				      i, v5_error_message(i), host);
			}
		}
	}

	if (use_ctx != ctx) {
		krb5_free_context(use_ctx);
	}

	free(address);

	return i;
}

/* Create a new PAG. */
int
minikafs_setpag(void)
{
	return minikafs_call(minikafs_subsys_setpag, 0, 0, 0, 0);
}

#if 0
/* Leave any PAG. It turns out this results in an unlog(), which is not what we
 * wanted here. */
static int
minikafs_unpag(void)
{
	struct minikafs_ioblock iob;
	char wfile[] = "/afs";
	int i;

	memset(&iob, 0, sizeof(iob));
	iob.in = wfile;
	iob.insize = sizeof(wfile);
	iob.out = wfile;
	iob.outsize = sizeof(wfile);

	i = minikafs_pioctl(wfile, minikafs_pioctl_unpag, &iob);
	return i;
}
#endif

/* Determine which cell is the default on this workstation. */
int
minikafs_ws_cell(char *cell, size_t length)
{
	struct minikafs_ioblock iob;
	char wfile[] = "/afs";
	int i;

	memset(&iob, 0, sizeof(iob));
	iob.in = wfile;
	iob.insize = strlen(wfile) + 1;
	iob.out = cell;
	iob.outsize = length - 1;
	memset(cell, '\0', length);

	i = minikafs_pioctl(wfile, minikafs_pioctl_getwscell, &iob);
	
	return i;
}

/* Stuff a ticket and DES key into the kernel. */
static int
minikafs_settoken(const void *ticket, uint32_t ticket_size,
		  int kvno, const unsigned char *key,
		  uint32_t uid, uint32_t start, uint32_t end, uint32_t flags,
		  const char *cell)
{
	char *buffer;
	struct minikafs_plain_token plain_token;
	struct minikafs_ioblock iob;
	uint32_t size;
	int i;

	/* Allocate the input buffer. */
	buffer = malloc(4 + ticket_size +
			4 + sizeof(struct minikafs_plain_token) +
			4 +
			strlen(cell) + 1);
	if (buffer == NULL) {
		return -1;
	}

	/* their key, encrypted with our key */
	size = ticket_size;
	memcpy(buffer, &size, 4);
	memcpy(buffer + 4, ticket, size);

	/* our key, plus housekeeping */
	plain_token.kvno = kvno;
	memcpy(&plain_token.key, key, 8);
	plain_token.uid = uid;
	plain_token.start = start;
	plain_token.end = end;
	if (((end - start) % 2) != 0) {
		plain_token.end--;
	}

	size = sizeof(plain_token);
	memcpy(buffer + 4 + ticket_size, &size, 4);
	memcpy(buffer + 4 + ticket_size + 4, &plain_token, size);

	/* flags */
	size = flags;
	memcpy(buffer + 4 + ticket_size + 4 + sizeof(plain_token), &size, 4);

	/* the name of the cell */
	memcpy(buffer + 4 + ticket_size + 4 + sizeof(plain_token) + 4,
	       cell, strlen(cell) + 1);

	/* the regular stuff */
	memset(&iob, 0, sizeof(iob));
	iob.in = buffer;
	iob.insize = 4 + ticket_size +
		     4 + sizeof(struct minikafs_plain_token) +
		     4 + strlen(cell) + 1;
	iob.out = NULL;
	iob.outsize = 0;

	i = minikafs_pioctl(NULL, minikafs_pioctl_settoken, &iob);
	free(buffer);
	return i;
}

#ifdef USE_KRB4
/* Stuff the ticket and key from a v4 credentials structure into the kernel. */
static int
minikafs_4settoken(const char *cell, uid_t uid, uint32_t start, uint32_t end,
		   CREDENTIALS *creds)
{
	return minikafs_settoken(creds->ticket_st.dat,
				 creds->ticket_st.length,
				 creds->kvno,
				 creds->session,
				 uid, start, end, 0, cell);
}
#endif

/* Stuff the ticket and key from a v5 credentials structure into the kernel. */
static int
minikafs_5settoken(const char *cell, krb5_creds *creds, uid_t uid)
{
	/* Assume that the only 8-byte keys are DES keys, and sanity-check. */
	if (v5_creds_key_length(creds) != 8) {
		return -1;
	}
	return minikafs_settoken(creds->ticket.data,
				 creds->ticket.length,
				 0x100, /* magic number, signals OpenAFS
					 * 1.2.8 and later that the ticket
					 * is actually a v5 ticket */
				 v5_creds_key_contents(creds),
				 uid,
				 creds->times.starttime,
				 creds->times.endtime,
				 0,
				 cell);
}

/* Clear our tokens. */
int
minikafs_unlog(void)
{
	return minikafs_pioctl(NULL, minikafs_pioctl_unlog, NULL);
}

#ifdef USE_KRB4
/* Try to convert the v5 credentials to v4 credentials using the krb524 service
 * and then attempt to stuff the resulting v4 credentials into the kernel. */
static int
minikafs_5convert_and_log(krb5_context ctx, struct _pam_krb5_options *options,
			  const char *cell, krb5_creds *creds, uid_t uid)
{
	CREDENTIALS v4creds;
	int i, ret;
	memset(&v4creds, 0, sizeof(v4creds));
	i = -1;
#if defined(HAVE_KRB5_524_CONVERT_CREDS)
	i = krb5_524_convert_creds(ctx, creds, &v4creds);
#else
#if defined(HAVE_KRB524_CONVERT_CREDS_KDC)
	i = krb524_convert_creds_kdc(ctx, creds, &v4creds);
#endif
#endif
	if (i != 0) {
		if (options->debug) {
			debug("got error %d (%s) converting v5 creds to v4 for"
			      " \"%s\"", i, v5_error_message(i), cell);
		}
		return i;
	}
	if (v4creds.kvno == (0x100 - 0x2b)) {
		/* Probably a v5 enc_part blob, per the rxkad 2b proposal.  Do
		 * nothing. */;
	}
	ret = minikafs_4settoken(cell, uid,
				 creds->times.starttime, creds->times.endtime,
				 &v4creds);
	return ret;
}
#else
static int
minikafs_5convert_and_log(krb5_context ctx, struct _pam_krb5_options *options,
			  const char *cell, krb5_creds *creds, uid_t uid)
{
	return -1;
}
#endif

/* Ask the kernel which ciphers it supports for use with rxk5. */
static int
minikafs_get_property(const char *property, char *value, int length)
{
	struct minikafs_ioblock iob;
	int i;

	iob.in = property ? (char *) property : "*";
	iob.insize = strlen(property) + 1;
	iob.out = value;
	iob.outsize = length;
	i = minikafs_pioctl(NULL, minikafs_pioctl_getprop, &iob);
	return i;
}

static int
minikafs_get_rxk5_enctypes(krb5_enctype *etypes, int n_etypes)
{
	int n;
	uint32_t i;
	long l;
	const char *property = "rxk5.enctypes", *p, *v;
	char enctypes[1024], *q;
	n = -1;
	memset(enctypes, '\0', sizeof(enctypes));
	if (minikafs_get_property(property,
				  enctypes, sizeof(enctypes) - 1) == 0) {
		p = enctypes;
		n = 0;
		while ((p != NULL) && (*p != '\0') && (n < n_etypes)) {
			v = p + strlen(p) + 1;
			if (strcmp(p, property) == 0) {
				p = v;
				while ((p != NULL) && (*p != '\0') &&
				       (n < n_etypes)) {
					l = strtol(p, &q, 10);
					if ((q != NULL) &&
					    ((*q == ' ') || (*q == '\0'))) {
						i = l & 0xffffffff;
						if (i != 0) {
							etypes[n++] = i;
						}
						p = q + strcspn(q,
								"0123456789");
					} else {
						break;
					}
				}
			}
			p = v + strlen(v) + 1;
		}
	}
	return n;
}

/* Try to set a token for the given cell using creds for the named principal. */
static int
minikafs_5log_with_principal(krb5_context ctx,
			     struct _pam_krb5_options *options,
			     krb5_ccache ccache,
			     const char *cell,
			     const char *principal,
			     uid_t uid,
			     int use_rxk5,
			     int use_v5_2b)
{
	krb5_principal server, client;
	krb5_creds mcreds, creds, *new_creds;
	char *unparsed_client;
	krb5_enctype v5_2b_etypes[] = {
		ENCTYPE_DES_CBC_CRC,
		ENCTYPE_DES_CBC_MD4,
		ENCTYPE_DES_CBC_MD5,
	};
	krb5_enctype rxk5_enctypes[16];
	krb5_enctype *etypes;
	unsigned int i;
	int n_etypes;
	int tmp;

	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));
	if (use_rxk5) {
		n_etypes = minikafs_get_rxk5_enctypes(rxk5_enctypes,
						      sizeof(rxk5_enctypes) /
						      sizeof(rxk5_enctypes[0]) -
						      1);
#if 1
		n_etypes = 0;
#endif
		if (n_etypes > 0) {
			etypes = rxk5_enctypes;
			rxk5_enctypes[n_etypes] = 0;
		} else {
			etypes = NULL;
			n_etypes = 1; /* hack: we want to try at least once */
		}
	} else {
		etypes = v5_2b_etypes;
		n_etypes = sizeof(v5_2b_etypes) / sizeof(v5_2b_etypes[0]);
	}

	if (krb5_cc_get_principal(ctx, ccache, &client) != 0) {
		if (options->debug) {
			debug("error determining default principal name "
			      "for ccache");
		}
		return -1;
	}
	unparsed_client = NULL;
	if (krb5_unparse_name(ctx, client, &unparsed_client) != 0) {
		warn("error unparsing client principal name from ccache");
		krb5_free_principal(ctx, client);
		return -1;
	}
	if (v5_parse_name(ctx, options, principal, &server) != 0) {
		warn("error parsing principal name '%s'", principal);
		v5_free_unparsed_name(ctx, unparsed_client);
		krb5_free_principal(ctx, client);
		return -1;
	}

	/* Check if we already have a suitable credential. */
	for (i = 0; i < n_etypes; i++) {
		memset(&mcreds, 0, sizeof(mcreds));
		memset(&creds, 0, sizeof(creds));
		mcreds.client = client;
		mcreds.server = server;
		if (etypes != NULL) {
			v5_creds_set_etype(ctx, &mcreds, etypes[i]);
		}
		if (krb5_cc_retrieve_cred(ctx, ccache, v5_cc_retrieve_match(),
					  &mcreds, &creds) == 0) {
			if (use_rxk5 &&
			    (minikafs_5settoken2(cell, &creds) == 0)) {
				krb5_free_cred_contents(ctx, &creds);
				v5_free_unparsed_name(ctx, unparsed_client);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			} else
			if (use_v5_2b &&
			    (minikafs_5settoken(cell, &creds, uid) == 0)) {
				krb5_free_cred_contents(ctx, &creds);
				v5_free_unparsed_name(ctx, unparsed_client);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			} else
			if (options->v4_use_524 &&
			    minikafs_5convert_and_log(ctx, options, cell,
						      &creds, uid) == 0) {
				krb5_free_cred_contents(ctx, &creds);
				v5_free_unparsed_name(ctx, unparsed_client);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			}
			krb5_free_cred_contents(ctx, &creds);
		}
	}

	/* Try to obtain a suitable credential. */
	for (i = 0; i < n_etypes; i++) {
		memset(&mcreds, 0, sizeof(mcreds));
		mcreds.client = client;
		mcreds.server = server;
		if (etypes != NULL) {
			v5_creds_set_etype(ctx, &mcreds, etypes[i]);
		}
		new_creds = NULL;
		tmp = krb5_get_credentials(ctx, 0, ccache,
					   &mcreds, &new_creds);
		if (tmp == 0) {
			if (use_rxk5 &&
			    (minikafs_5settoken2(cell, new_creds) == 0)) {
				krb5_free_creds(ctx, new_creds);
				v5_free_unparsed_name(ctx, unparsed_client);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			} else
			if (use_v5_2b &&
			    (minikafs_5settoken(cell, new_creds, uid) == 0)) {
				krb5_free_creds(ctx, new_creds);
				v5_free_unparsed_name(ctx, unparsed_client);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			} else
			if (options->v4_use_524 &&
			    minikafs_5convert_and_log(ctx, options, cell,
						      new_creds, uid) == 0) {
				krb5_free_creds(ctx, new_creds);
				v5_free_unparsed_name(ctx, unparsed_client);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			}
			krb5_free_creds(ctx, new_creds);
		} else {
			if (options->debug) {
				if (etypes != NULL) {
					debug("error obtaining credentials for "
					      "'%s' (enctype=%d) on behalf of "
					      "'%s': %s",
					      principal, etypes[i],
					      unparsed_client,
					      v5_error_message(tmp));
				} else {
					debug("error obtaining credentials for "
					      "'%s' on behalf of "
					      "'%s': %s",
					      principal,
					      unparsed_client,
					      v5_error_message(tmp));
				}
			}
		}
	}

	v5_free_unparsed_name(ctx, unparsed_client);
	krb5_free_principal(ctx, client);
	krb5_free_principal(ctx, server);

	return -1;
}

/* Try to obtain tokens for the named cell using the default ccache and
 * configuration settings. */
static int
minikafs_5log(krb5_context context, krb5_ccache ccache,
	      struct _pam_krb5_options *options,
	      const char *cell, const char *hint_principal,
	      uid_t uid, int use_rxk5, int use_v5_2b)
{
	krb5_context ctx;
	krb5_ccache use_ccache;
	int ret;
	unsigned int i;
	char *principal, *defaultrealm, realm[PATH_MAX];
	size_t principal_size, base_size;
	const char *base_rxkad[] = {"afs", "afsx"};
	const char *base_rxk5[] = {"afs-k5"};
	const char **base;

	if (context == NULL) {
		if (_pam_krb5_init_ctx(&ctx, 0, NULL) != 0) {
			return -1;
		}
	} else {
		ctx = context;
	}

	if (use_rxk5) {
		base = base_rxk5;
		base_size = sizeof(base_rxk5) / sizeof(base_rxk5[0]);
	} else {
		base = base_rxkad;
		base_size = sizeof(base_rxkad) / sizeof(base_rxkad[0]);
	}

	memset(&use_ccache, 0, sizeof(use_ccache));
	if (ccache != NULL) {
		use_ccache = ccache;
	} else {
		if (krb5_cc_default(ctx, &use_ccache) != 0) {
			if (ctx != context) {
				krb5_free_context(ctx);
			}
			return -1;
		}
	}

	/* If we were given a principal name, try it. */
	if ((hint_principal != NULL) && (strlen(hint_principal) > 0)) {
		if (options->debug) {
			debug("attempting to obtain tokens for \"%s\" "
			      "(hint \"%s\")",
			      cell, hint_principal);
		}
		ret = minikafs_5log_with_principal(ctx, options, use_ccache,
						   cell, hint_principal, uid,
						   use_rxk5, use_v5_2b);
		if (ret == 0) {
			if (use_ccache != ccache) {
				krb5_cc_close(ctx, use_ccache);
			}
			if (ctx != context) {
				krb5_free_context(ctx);
			}
			return 0;
		}
	}

	defaultrealm = NULL;
	if (krb5_get_default_realm(ctx, &defaultrealm) != 0) {
		defaultrealm = NULL;
	}

	if (options->debug > 1) {
		debug("attempting to determine realm for \"%s\"", cell);
	}
	if (minikafs_realm_of_cell_with_ctx(ctx, options, cell,
					    realm, sizeof(realm)) != 0) {
		strncpy(realm, cell, sizeof(realm));
		realm[sizeof(realm) - 1] = '\0';
		for (i = 0; i < sizeof(realm); i++) {
			realm[i] = toupper(realm[i]);
		}
	}

	principal_size = strlen("/@") + 1;
	ret = -1;
	for (i = 0; (ret != 0) && (i < base_size); i++) {
		principal_size += strlen(base[i]);
	}
	principal_size += strlen(cell);
	principal_size += strlen(realm);
	if (defaultrealm != NULL) {
		principal_size += strlen(defaultrealm);
	}
	principal = malloc(principal_size);
	if (principal == NULL) {
		if (use_ccache != ccache) {
			krb5_cc_close(ctx, use_ccache);
		}
		if (defaultrealm != NULL) {
			v5_free_default_realm(ctx, defaultrealm);
		}
		if (ctx != context) {
			krb5_free_context(ctx);
		}
		return -1;
	}

	for (i = 0; (ret != 0) && (i < base_size); i++) {
		/* If the realm name and cell name are similar, and null_afs
		 * is set, try the NULL instance. */
		if ((strcasecmp(realm, cell) == 0) && options->null_afs_first) {
			snprintf(principal, principal_size, "%s@%s",
				 base[i], realm);
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\")", cell, principal);
			}
			ret = minikafs_5log_with_principal(ctx, options,
							   use_ccache,
							   cell, principal, uid,
							   use_rxk5, use_v5_2b);
		}
		if (ret == 0) {
			break;
		}
		/* Try the cell instance in the cell's realm. */
		snprintf(principal, principal_size, "%s/%s@%s",
			 base[i], cell, realm);
		if (options->debug) {
			debug("attempting to obtain tokens for \"%s\" (\"%s\")",
			      cell, principal);
		}
		ret = minikafs_5log_with_principal(ctx, options, use_ccache,
						   cell, principal, uid,
						   use_rxk5, use_v5_2b);
		if (ret == 0) {
			break;
		}
		/* If the realm name and cell name are similar, and null_afs
		 * is not set, try the NULL instance. */
		if ((strcasecmp(realm, cell) == 0) &&
		    !options->null_afs_first) {
			snprintf(principal, principal_size, "%s@%s",
				 base[i], realm);
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\")", cell, principal);
			}
			ret = minikafs_5log_with_principal(ctx, options,
							   use_ccache,
							   cell, principal, uid,
							   use_rxk5, use_v5_2b);
		}
		if (ret == 0) {
			break;
		}
		/* Repeat the last two attempts, but using the default realm. */
		if ((defaultrealm != NULL) &&
		    (strcmp(defaultrealm, realm) != 0)) {
			/* If the default realm name and cell name are similar,
			 * and null_afs is set, try the NULL instance. */
			if ((strcasecmp(defaultrealm, cell) == 0) &&
			    options->null_afs_first) {
				snprintf(principal, principal_size, "%s@%s",
					 base[i], defaultrealm);
				if (options->debug) {
					debug("attempting to obtain tokens for "
					      "\"%s\" (\"%s\")",
					      cell, principal);
				}
				ret = minikafs_5log_with_principal(ctx, options,
								   use_ccache,
								   cell,
								   principal,
								   uid,
								   use_rxk5,
								   use_v5_2b);
			}
			if (ret == 0) {
				break;
			}
			/* Try the cell instance in the default realm. */
			snprintf(principal, principal_size, "%s/%s@%s",
				 base[i], cell, defaultrealm);
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\")", cell, principal);
			}
			ret = minikafs_5log_with_principal(ctx, options,
							   use_ccache,
							   cell, principal, uid,
							   use_rxk5, use_v5_2b);
			if (ret == 0) {
				break;
			}
			/* If the default realm name and cell name are similar,
			 * and null_afs isn't set, try the NULL instance. */
			if ((strcasecmp(defaultrealm, cell) == 0) &&
			    !options->null_afs_first) {
				snprintf(principal, principal_size, "%s@%s",
					 base[i], defaultrealm);
				if (options->debug) {
					debug("attempting to obtain tokens for "
					      "\"%s\" (\"%s\")",
					      cell, principal);
				}
				ret = minikafs_5log_with_principal(ctx, options,
								   use_ccache,
								   cell,
								   principal,
								   uid,
								   use_rxk5,
								   use_v5_2b);
			}
			if (ret == 0) {
				break;
			}
		}
	}

	if (use_ccache != ccache) {
		krb5_cc_close(ctx, use_ccache);
	}
	if (defaultrealm != NULL) {
		v5_free_default_realm(ctx, defaultrealm);
	}
	if (ctx != context) {
		krb5_free_context(ctx);
	}
	free(principal);

	return ret;
}

#ifdef USE_KRB4
/* Try to set a token for the given cell using creds for the named principal. */
static int
minikafs_4log_with_principal(struct _pam_krb5_options *options,
			     const char *cell,
			     char *service, char *instance, char *realm,
			     uid_t uid)
{
	CREDENTIALS creds;
	uint32_t endtime;
	int lifetime, ret;
	char lrealm[PATH_MAX];

	memset(&creds, 0, sizeof(creds));
	lifetime = 255;
	/* Get the lifetime from our TGT. */
	if (krb_get_tf_realm(tkt_string(), lrealm) == 0) {
		if (krb_get_cred(KRB_TICKET_GRANTING_TICKET, lrealm, lrealm,
				 &creds) == 0) {
			lifetime = creds.lifetime;
		}
	}
	/* Read the credential from the ticket file. */
	if (krb_get_cred(service, instance, realm, &creds) != 0) {
		if ((ret = get_ad_tkt(service, instance, realm,
				      lifetime)) != 0) {
			if (options->debug) {
				debug("got error %d (%s) obtaining v4 creds for"
				      " \"%s\"", ret, v5_error_message(ret),
				      cell);
			}
			return -1;
		}
		if (krb_get_cred(service, instance, realm, &creds) != 0) {
			return -1;
		}
	}
#ifdef HAVE_KRB_LIFE_TO_TIME
	/* Convert the ticket lifetime of the v4 credentials into Unixy
	 * lifetime, which is the X coordinate along a curve where Y is the
	 * actual length.  Again, this is magic. */

	endtime = krb_life_to_time(creds.issue_date, creds.lifetime);
#else
	/* No life-to-time function means we have to treat this as if we were
	 * measuring life units in 5-minute increments.  Is this ever right for
	 * AFS? */
	endtime = creds.issue_date + (creds.lifetime * (5 * 60));
#endif
	ret = minikafs_4settoken(cell, uid, creds.issue_date, endtime, &creds);
	return ret;
}

/* Try to obtain tokens for the named cell using the default ticket file and
 * configuration settings. */
static int
minikafs_4log(krb5_context context, struct _pam_krb5_options *options,
	      const char *cell, const char *hint_principal, uid_t uid)
{
	int ret;
	unsigned int i;
	char localrealm[PATH_MAX], realm[PATH_MAX];
	char service[PATH_MAX], instance[PATH_MAX];
	char *base[] = {"afs", "afsx"}, *wcell;
	krb5_context ctx;
	krb5_principal principal;

	/* Make sure we have a context. */
	if (context == NULL) {
		if (_pam_krb5_init_ctx(&ctx, 0, NULL) != 0) {
			return -1;
		}
	} else {
		ctx = context;
	}

	/* If we were given a principal name, try it. */
	if ((hint_principal != NULL) && (strlen(hint_principal) > 0)) {
		principal = NULL;
		if (v5_parse_name(ctx, options,
				  hint_principal, &principal) != 0) {
			principal = NULL;
		}
		if ((principal == NULL) ||
		    (krb5_524_conv_principal(ctx, principal,
					     service, instance, realm) != 0)) {
			memset(service, '\0', sizeof(service));
		}
		ret = -1;
		if (strlen(service) > 0) {
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\"(v5)->\"%s%s%s@%s\"(v4))",
				      cell, hint_principal,
				      service,
				      (strlen(service) > 0) ? "." : "",
				      instance,
				      realm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   service, instance,
							   realm,
							   uid);
		}
		if (principal != NULL) {
			krb5_free_principal(ctx, principal);
		}
		if (ctx != context) {
			krb5_free_context(ctx);
		}
		ctx = NULL;
		if (ret == 0) {
			return 0;
		}
	}

	if (krb_get_lrealm(localrealm, 1) != 0) {
		return -1;
	}
	if (minikafs_realm_of_cell_with_ctx(ctx, options, cell,
					    realm, sizeof(realm)) != 0) {
		strncpy(realm, cell, sizeof(realm));
		realm[sizeof(realm) - 1] = '\0';
		for (i = 0; i < sizeof(realm); i++) {
			realm[i] = toupper(realm[i]);
		}
	}
	wcell = xstrdup(cell);
	if (wcell == NULL) {
		return -1;
	}

	ret = -1;
	for (i = 0; i < sizeof(base) / sizeof(base[0]); i++) {
		/* If the realm name and cell name are similar, and use_null
		 * was set, try the NULL instance. */
		if ((strcasecmp(realm, cell) == 0) &&
		    options->null_afs_first) {
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s@%s\")", cell, base[i], realm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   base[i], "", realm,
							   uid);
		}
		if (ret == 0) {
			break;
		}
		/* Try the cell instance in its own realm. */
		if (options->debug) {
			debug("attempting to obtain tokens for \"%s\" "
			      "(\"%s%s%s@%s\")", cell, base[i],
			      (strlen(wcell) > 0) ? "." : "",
			      wcell, realm);
		}
		ret = minikafs_4log_with_principal(options, cell,
						   base[i], wcell, realm, uid);
		if (ret == 0) {
			break;
		}
		/* If the realm name and cell name are similar, and use_null
		 * was not set, try the NULL instance. */
		if ((strcasecmp(realm, cell) == 0) &&
		    !options->null_afs_first) {
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s@%s\")", cell, base[i], realm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   base[i], "", realm,
							   uid);
		}
		if (ret == 0) {
			break;
		}
		/* Repeat with the local realm. */
		if (strcmp(realm, localrealm) != 0) {
			/* If the realm name and cell name are similar, and
			 * null_afs was set, try the NULL instance. */
			if ((strcasecmp(localrealm, cell) == 0) &&
			    options->null_afs_first) {
				if (options->debug) {
					debug("attempting to obtain tokens for "
					      "\"%s\" (\"%s@%s\")",
					      cell, base[i], localrealm);
				}
				ret = minikafs_4log_with_principal(options,
								   cell,
								   base[i], "",
								   localrealm,
								   uid);
			}
			if (ret == 0) {
				break;
			}
			/* Try the cell instance in its own realm. */
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s%s%s@%s\")", cell, base[i],
				      (strlen(wcell) > 0) ? "." : "",
				      wcell, localrealm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   base[i], wcell,
							   localrealm, uid);
			if (ret == 0) {
				break;
			}
			/* If the realm name and cell name are similar, and
			 * null_afs was not set, try the NULL instance. */
			if ((strcasecmp(localrealm, cell) == 0) &&
			    !options->null_afs_first) {
				if (options->debug) {
					debug("attempting to obtain tokens for "
					      "\"%s\" (\"%s@%s\")",
					      cell, base[i], localrealm);
				}
				ret = minikafs_4log_with_principal(options,
								   cell,
								   base[i], "",
								   localrealm,
								   uid);
			}
			if (ret == 0) {
				break;
			}
		}
	}

	xstrfree(wcell);

	return ret;
}
#endif

/* Try to get tokens for the named cell using every available mechanism. */
int
minikafs_log(krb5_context ctx, krb5_ccache ccache,
	     struct _pam_krb5_options *options,
	     const char *cell, const char *hint_principal,
	     uid_t uid, const int *methods, int n_methods)
{
	int i, method;
	if (n_methods == -1) {
		for (i = 0; methods[i] != 0; i++) {
			continue;
		}
		n_methods = i;
	}
	for (method = 0; method < n_methods; method++) {
		i = -1;
		switch (methods[method]) {
#ifdef USE_KRB4
		case MINIKAFS_METHOD_V4:
			if (options->debug) {
				debug("trying with v4 ticket");
			}
			i = minikafs_4log(ctx, options, cell,
					  hint_principal, uid);
			if (i != 0) {
				if (options->debug) {
					debug("v4 afslog failed to \"%s\"",
					      cell);
				}
			}
			break;
		case MINIKAFS_METHOD_V5_V4:
			if (options->debug) {
				debug("trying with v5 ticket and 524 service");
			}
			i = minikafs_5log(ctx, ccache, options, cell,
					  hint_principal, uid, 0, 0);
			if (i != 0) {
				if (options->debug) {
					debug("v5 with 524 service afslog "
					      "failed to \"%s\"", cell);
				}
			}
			break;
#endif
		case MINIKAFS_METHOD_V5_2B:
			if (options->debug) {
				debug("trying with v5 ticket (2b)");
			}
			i = minikafs_5log(ctx, ccache, options, cell,
					  hint_principal, uid, 0, 1);
			if (i != 0) {
				if (options->debug) {
					debug("v5 afslog (2b) failed to \"%s\"",
					      cell);
				}
			}
			break;
		case MINIKAFS_METHOD_RXK5:
			if (options->debug) {
				debug("trying with v5 ticket (rxk5)");
			}
			i = minikafs_5log(ctx, ccache, options, cell,
					  hint_principal, uid, 1, 0);
			if (i != 0) {
				if (options->debug) {
					debug("v5 afslog (rxk5) failed to \"%s\"",
					      cell);
				}
			}
			break;
		default:
			break;
		}
		if (i == 0) {
			break;
		}
	}
	if (method < n_methods) {
		if (options->debug) {
			debug("got tokens for cell \"%s\"", cell);
		}
		return 0;
	} else {
		return -1;
	}
}

/* We do the XDR here to avoid deps on what might not be a standard part of
 * glibc, and we don't need the decode or free functionality. */
static int
encode_int32(char *buffer, int32_t num)
{
	int32_t net;
	if (buffer) {
		net = ntohl(num);
		memcpy(buffer, &net, 4);
	}
	return 4;
}
static int
encode_boolean(char *buffer, krb5_boolean b)
{
	return encode_int32(buffer, b ? 1 : 0);
}
static int
encode_uint64(char *buffer, uint64_t num)
{
	int32_t net;
	if (buffer) {
		net = ntohl(num >> 32);
		memcpy(buffer + 0, &net, 4);
		net = ntohl(num & 0xffffffff);
		memcpy(buffer + 4, &net, 4);
	}
	return 8;
}
static int
encode_bytes(char *buffer, const char *bytes, int32_t num)
{
	int32_t pad;
	pad = (num % 4) ? (4 - (num % 4)) : 0;
	if (buffer) {
		if (bytes && num) {
			memcpy(buffer, bytes, num);
			memset(buffer + num, 0, pad);
		}
	}
	return num + pad;
}
static int
encode_ubytes(char *buffer, const unsigned char *bytes, int32_t num)
{
	int32_t pad;
	pad = (num % 4) ? (4 - (num % 4)) : 0;
	if (buffer) {
		if (bytes && num) {
			memcpy(buffer, bytes, num);
			memset(buffer + num, 0, pad);
		}
	}
	return num + pad;
}
#define encode_fixed(_op, _buffer, _item) \
	{ \
		int _length; \
		_length = _op(_buffer, _item); \
		if (_buffer) { \
			_buffer += _length; \
		} \
		total += _length; \
	}
#define encode_variable(_op, _buffer, _item, _size) \
	{ \
		int _length; \
		_length = _op(_buffer, _item, _size); \
		if (_buffer) { \
			_buffer += _length; \
		} \
		total += _length; \
	}
static int
encode_data(char *buffer, krb5_data *data)
{
	int32_t total = 0;
	encode_fixed(encode_int32, buffer, data->length);
	encode_variable(encode_bytes, buffer, data->data, data->length);
	return total;
}
static int
encode_string(char *buffer, const char *string, ssize_t length)
{
	int32_t total = 0;
	if (length == -1) {
		length = strlen(string);
	}
	encode_fixed(encode_int32, buffer, length);
	encode_variable(encode_bytes, buffer, string, length);
	return total;
}
static int
encode_creds_keyblock(char *buffer, krb5_creds *creds)
{
	int32_t total = 0;
	encode_fixed(encode_int32, buffer, v5_creds_get_etype(creds));
	encode_fixed(encode_int32, buffer, v5_creds_key_length(creds));
	encode_variable(encode_ubytes, buffer, v5_creds_key_contents(creds),
			v5_creds_key_length(creds));
	return total;
}
static int
encode_principal(char *buffer, krb5_principal princ)
{
	int32_t total = 0;
	int i;
	encode_fixed(encode_int32, buffer, v5_princ_component_count(princ));
	for (i = 0; i < v5_princ_component_count(princ); i++) {
		encode_fixed(encode_int32, buffer,
			     v5_princ_component_length(princ, i));
		encode_variable(encode_bytes, buffer,
				v5_princ_component_contents(princ, i),
				v5_princ_component_length(princ, i));
	}
	encode_fixed(encode_int32, buffer, v5_princ_realm_length(princ));
	encode_variable(encode_bytes, buffer,
			v5_princ_realm_contents(princ),
			v5_princ_realm_length(princ));
	return total;
}
static int
encode_token_rxk5(char *buffer, krb5_creds *creds)
{
	int32_t total = 0;
	int i; 

	encode_fixed(encode_principal, buffer, creds->client);
	encode_fixed(encode_principal, buffer, creds->server);
	encode_fixed(encode_creds_keyblock, buffer, creds);
	encode_fixed(encode_uint64, buffer, creds->times.authtime);
	encode_fixed(encode_uint64, buffer, creds->times.starttime);
	encode_fixed(encode_uint64, buffer, creds->times.endtime);
	encode_fixed(encode_uint64, buffer, creds->times.renew_till);
	encode_fixed(encode_boolean, buffer, v5_creds_get_is_skey(creds));
	encode_fixed(encode_int32, buffer, v5_creds_get_flags(creds));

	encode_fixed(encode_int32, buffer, v5_creds_address_count(creds));
	for (i = 0; i < v5_creds_address_count(creds); i++) {
		encode_fixed(encode_int32, buffer,
			     v5_creds_address_type(creds, i));
		encode_fixed(encode_int32, buffer,
			     v5_creds_address_length(creds, i));
		encode_variable(encode_ubytes, buffer,
				v5_creds_address_contents(creds, i),
				v5_creds_address_length(creds, i));
	}

	encode_fixed(encode_data, buffer, &creds->ticket);
	encode_fixed(encode_data, buffer, &creds->second_ticket);

	encode_fixed(encode_int32, buffer, v5_creds_authdata_count(creds));
	for (i = 0; i < v5_creds_authdata_count(creds); i++) {
		encode_fixed(encode_int32, buffer,
			     v5_creds_authdata_type(creds, i));
		encode_fixed(encode_int32, buffer,
			     v5_creds_authdata_length(creds, i));
		encode_variable(encode_ubytes, buffer,
				v5_creds_authdata_contents(creds, i),
				v5_creds_authdata_length(creds, i));
	}
	return total;
}
#define SOLITON_NONE  0
#define SOLITON_RXKAD 2
#define SOLITON_RXGK  4
#define SOLITON_RXK5  5
static int
encode_soliton(char *buffer, krb5_creds *creds, int soliton_type)
{
	int32_t total = 0;
	encode_fixed(encode_int32, buffer, soliton_type);
	switch (soliton_type) {
	case SOLITON_RXK5:
		encode_fixed(encode_token_rxk5, buffer, creds);
		break;
	default:
		break;
	}
	return total;
}

/* Stuff a ticket and keyblock into the kernel. */
static int
minikafs_5settoken2(const char *cell, krb5_creds *creds)
{
	struct minikafs_ioblock iob;
	int i, bufsize, soliton_size;
	char *buffer, *bufptr;

	soliton_size = encode_soliton(NULL, creds, SOLITON_RXK5);
	bufsize = encode_int32(NULL, 0) +
		  encode_string(NULL, cell, -1) +
		  encode_int32(NULL, 1) +
		  encode_int32(NULL, soliton_size) +
		  soliton_size;
	buffer = malloc(bufsize);
	i = -1;
	if (buffer != NULL) {
		bufptr = buffer;
		bufptr += encode_int32(bufptr, 0); /* flags */
		bufptr += encode_string(bufptr, cell, -1); /* cell */
		bufptr += encode_int32(bufptr, 1); /* number of tokens */
		bufptr += encode_int32(bufptr, soliton_size); /* size of tok */
		bufptr += encode_soliton(bufptr, creds, SOLITON_RXK5); /* tok */
		iob.in = buffer;
		iob.insize = bufptr - buffer;
		iob.out = NULL;
		iob.outsize = 0;
		i = minikafs_pioctl(NULL, minikafs_pioctl_settoken2, &iob);
		free(buffer);
	}
	return i;
}
