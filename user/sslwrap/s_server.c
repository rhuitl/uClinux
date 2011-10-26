/*
 * sslwrap.c
 * 
 * Wrapper that encrypts all data from a simple TCP-based service
 * (POP3, IMAP, SMTP, telnet).  Installs in inetd.
 *
 * Written by Rick Kaseguma
 * <rickk@rickk.com>
 *
 * Version 1:
 * December 28, 1997
 * 
 * Version 2:
 * September 18, 1998 - Added support for SSLeay 0.9.1 and standalone mode
 * instead of inetd mode. Added support for connecting to other hosts.
 *
 * Version 2.0.1 (user contributions)
 * Added "-exec" option to directly run a program instead of having to connect
 *   to localhost
 * Corrected a typo in the usage info for -accept
 * Corrected a segmentation fault when -nocafile is used
 *
 * Version 2.0.2 (user contributions)
 * Corrected missing ")" in call to RSA_generate_key for versions of SSLeay
 * less than 9.0
 *
 * Version 2.0.5
 * Compatibility with OpenSSL 0.9.4
 *
 * Version 2.0.6
 * Changed Malloc to malloc and Free to free
 * Changed #include "err.h" to #include OPENSSL"err.h"
 *
 * Copyright 1997-9, 2000 Rick R. Kaseguma
 * All rights reserved
 *
 * Feel free to use this as you want for commercial or non-commercial use,
 * but no warranty is provided.  Use at your own risk.
 * 
 * Example inetd.conf entry (from Linux):
 * 
 * imaps	stream tcp	nowait	sslwrap	/usr/sbin/tcpd 	
 * /usr/local/ssl/bin/sslwrap -cert /usr/local/ssl/certs/mail.pem -port 143
 *
 * This does not need to be run as root, but it does need to be able to access
 * the (unencrypted) certificate file. 
 *
 * You must specify a certificate file (-cert) but it can be self-signed.
 *
 * You must also specify the port the service actually exists on using -port.
 * sslwrap will make a connection to localhost (127.0.0.1) and this port to
 * do the actual work on the connection. The connection will not come from
 * a privileged port, so you cannot use this to front-end a service that 
 * requires that.
 */


/* apps/s_server.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef WIN16
#define APPS_WIN16
#endif
#include <openssl/lhash.h>
#include <openssl/bn.h>
#define USE_SOCKETS
#include "apps.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "s_apps.h"

#ifndef NOPROTO
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int export
#if SSLEAY_VERSION_NUMBER >= 0x903101L
, int keylen
#endif
);
static int sv_body(char *hostname, int sin, int sout);
static void sv_usage(void);
static int init_ssl_connection(SSL *s);
#ifdef PRINT_STATUS
static void print_stats(BIO *bp,SSL_CTX *ctx);
#endif
static DH *load_dh_param(void );
static DH *get_dh512(void);
#else
static RSA MS_CALLBACK *tmp_rsa_cb();
static int sv_body();
static void sv_usage();
static int init_ssl_connection();
#ifdef PRINT_STATUS
static void print_stats();
#endif
static DH *load_dh_param();
static DH *get_dh512();
#endif

#ifdef WIN32
int errno;
#endif

#ifndef S_ISDIR
#define S_ISDIR(a)	(((a) & _S_IFMT) == _S_IFDIR)
#endif

#define ERR_TO_SYSLOG
#ifdef ERR_TO_SYSLOG
	#define errprint(A...) syslog(LOG_ERR, A)
#else
	#define errprint(A...) BIO_printf(bio_err, A), BIO_printf(bio_err, "\n")
#endif

static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};

static DH *get_dh512()
	{
	DH *dh=NULL;

#ifndef NO_DH
	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
#endif
	return(dh);
	}

/* static int load_CA(SSL_CTX *ctx, char *file);*/

#undef BUFSIZZ
#define BUFSIZZ	1024
static int accept_socket= -1;

#define TEST_CERT	"server.pem"
#undef PROG
#define PROG		s_server_main

#define DH_PARAM	"server.pem"

extern int verify_depth;

static char *cipher=NULL;
int verify=SSL_VERIFY_NONE;
char *s_cert_file=TEST_CERT,*s_key_file=NULL;
#ifdef FIONBIO
static int s_nbio=0;
#endif
static int s_nbio_test=0;
static SSL_CTX *ctx=NULL;

static BIO *bio_s_out=NULL;
static int s_debug=0;
static int s_quiet=1;

static unsigned long dstAddr = (127 << 24) | 1;
static short dstPort = 0;
#ifndef NO_EXEC
#define MAX_EXEC_ARGS 20

static char *exec_pgm[MAX_EXEC_ARGS];
static int exec_pgm_argc;
#endif /*NO_EXEC*/

static void sv_usage()
	{
	BIO_printf(bio_err,"usage: sslwrap [args ...]\n");
	BIO_printf(bio_err,"\n");
	BIO_printf(bio_err," -addr arg     - address to connect to (default is 127.0.0.1)\n");
	BIO_printf(bio_err," -port arg     - port to connect to\n");
	BIO_printf(bio_err," -accept arg   - port to accept on (default is stdin for inetd)\n");
	BIO_printf(bio_err," -verify arg   - turn on peer certificate verification\n");
	BIO_printf(bio_err," -Verify arg   - turn on peer certificate verification, must have a cert.\n");
	BIO_printf(bio_err," -cert arg     - certificate file to use, PEM format assumed\n");
	BIO_printf(bio_err,"                 (default is %s)\n",TEST_CERT);
	BIO_printf(bio_err," -key arg      - RSA file to use, PEM format assumed, in cert file if\n");
	BIO_printf(bio_err,"                 not specified (default is %s)\n",TEST_CERT);
#ifdef FIONBIO
	BIO_printf(bio_err," -nbio         - Run with non-blocking IO\n");
#endif
	BIO_printf(bio_err," -nbio_test    - test with the non-blocking test bio\n");
	BIO_printf(bio_err," -debug        - Print more output\n");
	BIO_printf(bio_err," -state        - Print the SSL states\n");
	BIO_printf(bio_err," -CApath arg   - PEM format directory of CA's\n");
	BIO_printf(bio_err," -CAfile arg   - PEM format file of CA's\n");
	BIO_printf(bio_err," -nocert       - Don't use any certificates (Anon-DH)\n");
	BIO_printf(bio_err," -cipher arg   - play with 'ssleay ciphers' to see what goes here\n");
	BIO_printf(bio_err," -quiet        - No server output\n");
	BIO_printf(bio_err," -no_tmp_rsa   - Do not generate a tmp RSA key\n");
	BIO_printf(bio_err," -ssl2         - Just talk SSLv2\n");
	BIO_printf(bio_err," -ssl3         - Just talk SSLv3\n");
	BIO_printf(bio_err," -no_ssl2      - Do not talk SSLv2\n");
	BIO_printf(bio_err," -no_ssl3      - Do not talk SSLv3\n");
	BIO_printf(bio_err," -no_tls1_0    - Do not talk TLSv1.0\n");
	BIO_printf(bio_err," -bugs         - Turn on SSL bug compatability\n");
	}

static int local_argc;
static char **local_argv;
static int hack;

int MAIN(argc, argv)
int argc;
char *argv[];
	{
	short port=0;
	char *CApath=NULL,*CAfile=NULL;
	int badop=0,bugs=0;
	int ret=1;
	int no_tmp_rsa=0,nocert=0;
	int state=0;
	int ssl2 = 0, ssl3 = 0;
	int no_ssl2 = 0, no_ssl3 = 0, no_tls1_0 = 0;
	SSL_METHOD *meth=NULL;
	DH *dh=NULL;

#if !defined(NO_SSL2) && !defined(NO_SSL3)
	meth=SSLv23_server_method();
#elif !defined(NO_SSL3)
	meth=SSLv3_server_method();
#elif !defined(NO_SSL2)
	meth=SSLv2_server_method();
#endif

	local_argc=argc;
	local_argv=argv;

	apps_startup();
	s_quiet=0;
	s_debug=0;

#ifdef ERR_TO_SYSLOG
	openlog("sslwrap", 0, 0);
#endif

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

	verify_depth=0;
#ifdef FIONBIO
	s_nbio=0;
#endif
	s_nbio_test=0;

	argc--;
	argv++;

	while (argc >= 1)
		{
		if	((strcmp(*argv,"-port") == 0))
			{
			if (--argc < 1) goto bad;
			if (!extract_port(*(++argv),&dstPort))
				goto bad;
			}
		else if	((strcmp(*argv,"-addr") == 0))
			{
			int v1, v2, v3, v4;
			if (--argc < 1) goto bad;
			if (sscanf(*(++argv), "%u.%u.%u.%u", &v1, &v2, &v3, &v4) != 4) 
				goto bad;
			
			dstAddr = ((v1 << 24) & 0xFF000000) | ((v2 << 16) & 0xFF0000) | 
				((v3 << 8) & 0xFF00) | (v4 & 0xFF);
			}
#ifndef NO_EXEC
		else if	((strcmp(*argv,"-exec") == 0))
			{
				int i = 0;

				if (--argc < 1) goto bad;

				while (argc >= 1) {
					exec_pgm[i++] = *(++argv);
					exec_pgm_argc++;
#ifdef DEBUG
					BIO_printf(bio_err,"exec_pgm[%d]='%s'\n", i - 1, exec_pgm[i - 1]);
#endif
					argc--;
				}
				exec_pgm[i] = 0;
			}
#endif /*NO_EXEC*/
		else if	(strcmp(*argv,"-accept") == 0)
			{
			if (--argc < 1) goto bad;
			if (!extract_port(*(++argv),&port))
				goto bad;
			}
		else if	(strcmp(*argv,"-verify") == 0)
			{
			verify=SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
			if (--argc < 1) goto bad;
			verify_depth=atoi(*(++argv));
#ifdef DEBUG
			BIO_printf(bio_err,"verify depth is %d\n",verify_depth);
#endif
			}
		else if	(strcmp(*argv,"-Verify") == 0)
			{
			verify=SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
				SSL_VERIFY_CLIENT_ONCE;
			if (--argc < 1) goto bad;
			verify_depth=atoi(*(++argv));
#ifdef DEBUG
			BIO_printf(bio_err,"verify depth is %d, must return a certificate\n",verify_depth);
#endif
			}
		else if	(strcmp(*argv,"-cert") == 0)
			{
			if (--argc < 1) goto bad;
			s_cert_file= *(++argv);
			}
		else if	(strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			s_key_file= *(++argv);
			}
		else if (strcmp(*argv,"-nocert") == 0)
			{
			nocert=1;
			}
		else if	(strcmp(*argv,"-CApath") == 0)
			{
			if (--argc < 1) goto bad;
			CApath= *(++argv);
			}
		else if	(strcmp(*argv,"-cipher") == 0)
			{
			if (--argc < 1) goto bad;
			cipher= *(++argv);
			}
		else if	(strcmp(*argv,"-CAfile") == 0)
			{
			if (--argc < 1) goto bad;
			CAfile= *(++argv);
			}
#ifdef FIONBIO	
		else if	(strcmp(*argv,"-nbio") == 0)
			{ s_nbio=1; }
#endif
		else if	(strcmp(*argv,"-nbio_test") == 0)
			{
#ifdef FIONBIO	
			s_nbio=1;
#endif
			s_nbio_test=1;
			}
		else if	(strcmp(*argv,"-debug") == 0)
			{ s_debug=1; }
		else if	(strcmp(*argv,"-hack") == 0)
			{ hack=1; }
		else if	(strcmp(*argv,"-state") == 0)
			{ state=1; }
		else if	(strcmp(*argv,"-quiet") == 0)
			{ s_quiet=1; }
		else if	(strcmp(*argv,"-bugs") == 0)
			{ bugs=1; }
		else if	(strcmp(*argv,"-no_tmp_rsa") == 0)
			{ no_tmp_rsa=1; }
#ifndef NO_SSL2
		else if	(strcmp(*argv,"-ssl2") == 0)
			{
				ssl2 = 1;
				meth=SSLv2_server_method();
			}
#endif
#ifndef NO_SSL3
		else if	(strcmp(*argv,"-ssl3") == 0)
			{
				ssl3 = 1;
				meth=SSLv3_server_method();
			}
#endif
		else if	(strcmp(*argv,"-no_ssl2") == 0)
			{ no_ssl2 = 1; }
		else if	(strcmp(*argv,"-no_ssl3") == 0)
			{ no_ssl3 = 1; }
		else if	(strcmp(*argv,"-no_tls1_0") == 0)
			{ no_tls1_0 = 1; }
		else
			{
			errprint("unknown option %s",*argv);
			badop=1;
			break;
			}
		argc--;
		argv++;
		}
#ifndef NO_EXEC
	if (exec_pgm_argc && dstPort) {
	    errprint("options -port and -exec are incompatible");
	    badop=1;
	}
	if (!exec_pgm_argc && !dstPort) {
	    errprint("one of -port or -exec must be supplied");
	    badop=1;
	}
#else  /*NO_EXEC*/
	if (!dstPort) {
	    errprint("-port must be supplied");
	    badop=1;
	}
#endif /*NO_EXEC*/

	if (ssl2 && no_ssl2) {
	    errprint("options -ssl2 and -no_ssl2 are incompatible");
	    badop=1;
	}
	if (ssl3 && no_ssl3) {
	    errprint("options -ssl3 and -no_ssl3 are incompatible");
	    badop=1;
	}
	if (no_ssl2 && no_ssl3 && no_tls1_0) {
	    errprint("Cannot specify -no_ssl2, -no_ssl3 and -no_tls1_0. Must allow at least one (1) protocol");
	    badop=1;
	}

	if (badop)
		{
bad:
		sv_usage();
		goto end;
		}

	if (bio_s_out == NULL)
		{
		if (s_quiet && !s_debug)
			{
			bio_s_out=BIO_new(BIO_s_null());
			}
		else
			{
			if (bio_s_out == NULL)
				bio_s_out=BIO_new_fp(stdout,BIO_NOCLOSE);
			}
		}

#if !defined(NO_RSA) || !defined(NO_DSA)
	if (nocert)
#endif
		{
		s_cert_file=NULL;
		s_key_file=NULL;
		}

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	ctx=SSL_CTX_new(meth);
	if (ctx == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (bugs) SSL_CTX_set_options(ctx,SSL_OP_ALL);
	if (hack) SSL_CTX_set_options(ctx,SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG);
#ifdef SSL_OP_NON_EXPORT_FIRST
	if (hack) SSL_CTX_set_options(ctx,SSL_OP_NON_EXPORT_FIRST);
#endif

	if (no_ssl2) SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2);
	if (no_ssl3) SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv3);
	if (no_tls1_0) SSL_CTX_set_options(ctx,SSL_OP_NO_TLSv1);

	if (state) SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);

#if 0
	if (cipher == NULL) cipher=getenv("SSL_CIPHER");
#endif

#if 0
	if (s_cert_file == NULL)
		{
		BIO_printf(bio_err,"You must specify a certificate file for the server to use\n");
		goto end;
		}
#endif

	/* 980921 RRK - Removed this code; not necessary for sslwrap */
	/* 041004 matthewn@snapgear.com - Re-add this code to work with client
		certificates */
	if (CAfile || CApath) {
		if (!SSL_CTX_load_verify_locations(ctx,CAfile,CApath) || !SSL_CTX_set_default_verify_paths(ctx)) {
			BIO_printf(bio_err,"X509_load_verify_locations\n");
			ERR_print_errors(bio_err);
			goto end;
		} else {
			STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(CAfile);
			if (list == NULL) {
				BIO_printf(bio_err,"Couldn't load CA file.\n");
				ERR_print_errors(bio_err);
				goto end;
			}
			else {
				SSL_CTX_set_client_CA_list(ctx, list);
				/*syslog(LOG_INFO, "Added client certs successfully.\n");*/
			}
		}
	}

#ifndef NO_DH
	/* EAY EAY EAY evil hack */
	dh=load_dh_param();
	if (dh != NULL)
		{
		/* BIO_printf(bio_s_out,"Setting temp DH parameters\n"); */
		}
	else
		{
		/* BIO_printf(bio_s_out,"Using default temp DH parameters\n"); */
		dh=get_dh512();
		}
	/* BIO_flush(bio_s_out); */

	SSL_CTX_set_tmp_dh(ctx,dh);
	DH_free(dh);
#endif
	
	if (!set_cert_stuff(ctx,s_cert_file,s_key_file))
		goto end;

#if 1
	SSL_CTX_set_tmp_rsa_callback(ctx,tmp_rsa_cb);
#else
	if (!no_tmp_rsa && SSL_CTX_need_tmp_RSA(ctx))
		{
		RSA *rsa;

		/* BIO_printf(bio_s_out,"Generating temp (512 bit) RSA key..."); */
		/* BIO_flush(bio_s_out); */

		rsa=RSA_generate_key(512,RSA_F4,NULL);

		if (!SSL_CTX_set_tmp_rsa(ctx,rsa))
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		RSA_free(rsa);
		/* BIO_printf(bio_s_out,"\n"); */
		}
#endif

	if (cipher != NULL)
		SSL_CTX_set_cipher_list(ctx,cipher);
	SSL_CTX_set_verify(ctx,verify,verify_callback);


	if (port) {
		/* BIO_printf(bio_s_out,"ACCEPT\n"); */
		do_server(port,&accept_socket,sv_body);
		/* print_stats(bio_s_out,ctx); */
		ret=0;
	} else {
		/* stdin/stdout for inetd */
		sv_body( "", fileno(stdin), fileno(stdout) );
	}
end:
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (bio_s_out != NULL)
		{
		BIO_free(bio_s_out);
		bio_s_out=NULL;
		}
	EXIT(ret);
	}

#ifdef PRINT_STATS
static void print_stats(bio,ssl_ctx)
BIO *bio;
SSL_CTX *ssl_ctx;
	{
	BIO_printf(bio,"%4ld items in the session cache\n",
		SSL_CTX_sess_number(ssl_ctx));
	BIO_printf(bio,"%4d client connects (SSL_connect())\n",
		SSL_CTX_sess_connect(ssl_ctx));
	BIO_printf(bio,"%4d client connects that finished\n",
		SSL_CTX_sess_connect_good(ssl_ctx));
	BIO_printf(bio,"%4d server accepts (SSL_accept())\n",
		SSL_CTX_sess_accept(ssl_ctx));
	BIO_printf(bio,"%4d server accepts that finished\n",
		SSL_CTX_sess_accept_good(ssl_ctx));
	BIO_printf(bio,"%4d session cache hits\n",SSL_CTX_sess_hits(ssl_ctx));
	BIO_printf(bio,"%4d session cache misses\n",SSL_CTX_sess_misses(ssl_ctx));
	BIO_printf(bio,"%4d session cache timeouts\n",SSL_CTX_sess_timeouts(ssl_ctx));
	BIO_printf(bio,"%4d callback cache hits\n",SSL_CTX_sess_cb_hits(ssl_ctx));
	}
#endif

static int sv_body(hostname, s_stdin, s_stdout)
char *hostname;
int s_stdin;
int s_stdout;
	{
	char *buf=NULL;
	fd_set readfds;
	int ret=1,width;
	int k,i;
	unsigned long l;
	SSL *con=NULL;
	BIO *sbi, *sbo;
	int s_in, s_out;
	struct sockaddr_in srvr;
	int flags;
	
	if (dstPort) {
	    s_in = s_out = socket( AF_INET, SOCK_STREAM, 0 );
	    
	    memset((void *)&srvr, 0, sizeof(srvr));
	    srvr.sin_family = AF_INET;
	    srvr.sin_port = htons( dstPort );
	    srvr.sin_addr.s_addr = htonl( dstAddr );
	    
	    connect(s_in, (struct sockaddr *) &srvr, sizeof(srvr));
#ifndef NO_EXEC
	} else {
	    if (spawn(exec_pgm_argc, exec_pgm, &s_in, &s_out) < 0) {
		errprint("could not run %s", exec_pgm[0]);
		goto err;
	    }
#endif /*NO_EXEC*/
	}

	if ((buf=malloc(BUFSIZZ)) == NULL)
		{
		errprint("out of memory");
		goto err;
		}

	if (con == NULL)
		con=(SSL *)SSL_new(ctx);
	SSL_clear(con);

	fcntl(s_stdin, F_SETFL, (flags = fcntl(s_stdin, F_GETFL))
		| O_NONBLOCK);

	sbi=BIO_new_socket(s_stdin,BIO_NOCLOSE);	
	sbo=BIO_new_socket(s_stdout,BIO_NOCLOSE);

	SSL_set_bio(con,sbi,sbo);
	SSL_set_accept_state(con);
	/* SSL_set_fd(con,s); */

	width=s_stdin;
	if (s_stdout > width) width = s_stdout;
	if (s_in > width) width = s_in;
	width++;
	for(;;)
		{
		FD_ZERO(&readfds);
		FD_SET(s_in,&readfds);
		FD_SET(s_stdin,&readfds);
		i=select(width,&readfds,NULL,NULL,NULL);
		if (i <= 0) continue;
		if (FD_ISSET(s_in,&readfds))
			{
			i=read(s_in,buf,BUFSIZZ);
			if (!s_quiet)
				{
				if (i <= 0)
					{
					goto err;
					}

				}
			l=k=0;
			for (;;)
				{
				/* should do a select for the write */
				k=SSL_write(con,&(buf[l]),(unsigned int)i);
				if (
					BIO_sock_should_retry(k))
					{
					continue;
					}
				if (k <= 0)
					{
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
					}
				l+=k;
				i-=k;
				if (i <= 0) break;
				}
			}
		if (FD_ISSET(s_stdin,&readfds))
			{
			if (!SSL_is_init_finished(con))
				{
				i=init_ssl_connection(con);
				
				if (i < 0)
					{
					ret=0;
					goto err;
					}
				else if (i == 0)
					{
					ret=1;
					goto err;
					}
				}
			else
				{
read:
				i=SSL_read(con,(char *)buf,BUFSIZZ);
				if ((i <= 0) &&
					BIO_sock_should_retry(i))
					{
					}
				else if (i <= 0)
					{
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
					}
				else
					{
					write(s_out,buf,
						(unsigned int)i);
					if (i == BUFSIZZ)
						goto read;
					}
				}
			}
		}
err:

#if 1
	SSL_set_shutdown(con,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
	SSL_shutdown(con);
#endif
	if (con != NULL) SSL_free(con);
	if (buf != NULL)
		{
		memset(buf,0,BUFSIZZ);
		free(buf);
		}

	fcntl(s_stdin, F_SETFL, flags);

	return(ret);
	}

static int init_ssl_connection(con)
SSL *con;
	{
	int i;
	X509 *peer;
	int verify_error;
	/*
	char *str;
	MS_STATIC char buf[BUFSIZ];
	*/

	if ((i=SSL_accept(con)) <= 0)
		{
		if (BIO_sock_should_retry(i))
			{
			/* BIO_printf(bio_s_out,"DELAY\n"); */
			return(1);
			}

		verify_error=SSL_get_verify_result(con);
		if (verify_error != X509_V_OK)
			{
			errprint("verify error:%s",
				X509_verify_cert_error_string(verify_error));
			}
		else
			ERR_print_errors(bio_err);
		return(0);
		}

	/* PEM_write_bio_SSL_SESSION(bio_s_out,SSL_get_session(con)); */

	peer=SSL_get_peer_certificate(con);
	if (peer != NULL)
		{
		/*
		BIO_printf(bio_s_out,"Client certificate\n");
		PEM_write_bio_X509(bio_s_out,peer);
		X509_NAME_oneline(X509_get_subject_name(peer),buf,BUFSIZ);
		BIO_printf(bio_s_out,"subject=%s\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(peer),buf,BUFSIZ);
		BIO_printf(bio_s_out,"issuer=%s\n",buf);
		X509_free(peer);
		*/
		}
	/*
	if (SSL_get_shared_ciphers(con,buf,BUFSIZ) != NULL)
		BIO_printf(bio_s_out,"Shared ciphers:%s\n",buf);
	str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
	BIO_printf(bio_s_out,"CIPHER is %s\n",(str != NULL)?str:"(NONE)");
	if (con->hit) BIO_printf(bio_s_out,"Reused session-id\n");
	*/
	return(1);
	}

static DH *load_dh_param()
	{
	DH *ret=NULL;
	BIO *bio;

#ifndef NO_DH
	if ((bio=BIO_new_file(DH_PARAM,"r")) == NULL)
		goto err;
	ret=PEM_read_bio_DHparams(bio,NULL,NULL
#if SSLEAY_VERSION_NUMBER >= 0x904100L
				  , NULL
#endif
);
err:
	if (bio != NULL) BIO_free(bio);
#endif
	return(ret);
	}

#if 0
static int load_CA(ctx,file)
SSL_CTX *ctx;
char *file;
	{
	FILE *in;
	X509 *x=NULL;

	if ((in=fopen(file,"r")) == NULL)
		return(0);

	for (;;)
		{
		if (PEM_read_X509(in,&x,NULL) == NULL)
			break;
		SSL_CTX_add_client_CA(ctx,x);
		}
	if (x != NULL) X509_free(x);
	fclose(in);
	return(1);
	}
#endif


static RSA MS_CALLBACK *tmp_rsa_cb(s,export
#if SSLEAY_VERSION_NUMBER >= 0x903101L
,keylen
#endif

)
SSL *s;
int export;
#if SSLEAY_VERSION_NUMBER >= 0x903101L
int keylen;
#endif
	{
	static RSA *rsa_tmp=NULL;

	if (rsa_tmp == NULL)
		{
		if (!s_quiet)
			{
			/* BIO_printf(bio_err,"Generating temp (512 bit) RSA key...");
			BIO_flush(bio_err); */
			}
#ifndef NO_RSA
#if SSLEAY_VERSION_NUMBER >= 0x0900
		rsa_tmp=RSA_generate_key(512,RSA_F4,NULL,NULL);
#else
		rsa_tmp=RSA_generate_key(512,RSA_F4,NULL);
#endif
#endif
		if (!s_quiet)
			{
			/* BIO_printf(bio_err,"\n");
			BIO_flush(bio_err); */
			}
		}
	return(rsa_tmp);
	}
