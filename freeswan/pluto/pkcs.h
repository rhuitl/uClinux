/* Support of PKCS#1 and PKCS#7 data structures
 * Copyright (C) 2002 Andreas Steffen, Zuercher Hochschule Winterthur
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: pkcs.h,v 0.1 2002/04/12 00:00:00 as Exp $
 */

/* path definition for my private keys */

#include <config/autoconf.h>

#ifdef CONFIG_USER_FLATFSD_FLATFSD
#define PRIVATE_KEY_PATH  "/etc/config"
#else
#define PRIVATE_KEY_PATH  "/etc"
#endif

/* access structure for a PKCS#1 private key */

typedef struct pkcs1privkey pkcs1privkey_t;

struct pkcs1privkey {
    chunk_t pkcs1object;
    chunk_t field[8];
};

/* used for initialization */

extern const pkcs1privkey_t empty_pkcs1privkey;

extern bool parse_pkcs1_private_key(chunk_t blob, pkcs1privkey_t *key);
extern pkcs1privkey_t* load_pkcs1_private_key(const char* filename,
					      const char* passphrase);

extern bool parse_pkcs7_cert(chunk_t blob, x509cert_t **cert);
