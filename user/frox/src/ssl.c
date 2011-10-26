/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  
      ssl.c -- implementation of rfc2228 AUTH/SSL/TLS security extensions.
               Needs openssl libraries.

	       So far this is only tested with vsftpd. May not work with
	       anything else.

  ***************************************/

#include <openssl/ssl.h>
#include <stdlib.h>

#include "common.h"
#include "control.h"
#include "sstr.h"
#include "ssl.h"

static SSL_CTX *ctx;
/* ------------------------------------------------------------- **
** init ssl context
** ------------------------------------------------------------- */
void ssl_init(void)
{
	sstr *msg;
	int i;

	if(!config.usessl)
		return;
	if(info->greeting == FAKED || info->greeting == AWAITED) {
		get_message(&i, &msg);
		if(i != 220) {
			die(INFO, "Unable to contact server in ntp", 421,
			    "Server Unable to accept connection", 0);
		}
		info->greetingmsg = sstr_dup(msg);
		info->greeting = info->greeting == FAKED ? DONE : SUPPRESSED;
	}

	send_ccommand("AUTH", config.datassl ? "TLS-P" : "TLS");
	get_message(&i, &msg);
	if(i != 234) {
		write_log(IMPORT, "SSL connection refused. "
			  "Using unencrypted connection");
		return;
	}

	SSL_load_error_strings();
	SSL_library_init();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
		die(ERROR, "Unable to initialise SSL", 0, 0, -1);

	info->ssl_sc = ssl_initfd(info->server_control.fd, SSL_CTRL);
	if(info->ssl_sc)
		write_log(IMPORT, "SSL initialised on control connection");
	else
		die(ERROR, "Unable to initialise SSL", 0, 0, -1);

	if(info->greeting == SUPPRESSED) {
		send_message(220, info->greetingmsg);
		info->greeting = DONE;
		sstr_free(info->greetingmsg);
	}
}

/*Initialise SSL on a file descriptor if required*/
void *ssl_initfd(int fd, int type)
{
	SSL *ssl;

	if(!config.usessl)
		return NULL;
	if(type == SSL_DATA) {
		if(config.datassl)
			write_log(VERBOSE,
				  "Initialising ssl on data connection.");
		else
			return NULL;
	}

	ssl = SSL_new(ctx);
	if(!SSL_set_fd(ssl, fd))
		die(ERROR, "Unable to init SSL", 0, 0, -1);
	if(type != SSL_DATA)
		SSL_connect(ssl);
	return (void *) ssl;
}

void ssl_shutdown(void **ssl)
{
	SSL *s = (SSL *) * ssl;
	if(!s)
		return;

	SSL_shutdown(s);
	SSL_free(s);
	*ssl = NULL;
}

int ssl_append_read(void *ssl, sstr * buf, int len)
{
	int i;
	char *tbuf;
	SSL *s = (SSL *) ssl;

	if(!len)
		len = 4096;
	tbuf = malloc(len);
	if(!tbuf)
		die(ERROR, "Malloc failure", 0, 0, -1);
	i = SSL_read(s, tbuf, len);
	if(i <= 0) {
		free(tbuf);
		if(i == 0)
			return 0;
		write_log(ERROR, "SSL Error %d\n", SSL_get_error(s, i));
		return 0;	/*SSL often seems to give an error on closing */
	}

	sstr_ncat2(buf, tbuf, i);
	free(tbuf);
	return i;
}

int ssl_write(void *ssl, sstr * buf)
{
	int i;
	SSL *s = (SSL *) ssl;
	i = SSL_write(s, sstr_buf(buf), sstr_len(buf));
	return i;
}

/* We need to intercept 150 messages so that we can initialise ssl on the
 * data connection if required. We can't do it when the initial tcp data
 * connection is made as this frequently happens before the 150 reply, the
 * ftp server isn't ready to negotiate the ssl, and SSL_connect() blocks.
 *
 * We can't just call SSL_set_connect_state() because if we are downloading
 * then frox select()s for a read on the data line, but it is the ftp client's
 * responsibility to play the part of the SSL client and initialise the
 * connection.
 *
 * We always return 0 as we never actually deal with the reply ourselves, but
 * just need notification. We should be called first in the && list in
 * control.c to ensure we always get it.*/
int ssl_parsed_reply(int code, sstr * msg)
{
	if(code != 150)
		return 0;
	if(!config.usessl || !config.datassl)
		return 0;
	if(SSL_connect(info->ssl_sd) == -1)
		die(ERROR, "Unable to initialise ssl connection", 0, 0, -1);
	return 0;
}
