/*
 *	DDNS v3 Client
 *
 *		Author:		Alan Yates <alany@ay.com.au>
 *		Version:	$Id: crypto.h,v 1.1.1.1 2002/07/19 11:47:20 alany Exp $
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

char *ddns3_crypto_md5hash(char *s, int len);
char *ddns3_crypto_crypt(char *key, char *salt);

#endif /* _CRYPTO_H */
