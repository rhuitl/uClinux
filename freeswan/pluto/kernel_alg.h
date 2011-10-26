/*
 * Kernel runtime algorithm handling interface definitions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * $Id: kernel_alg.h,v 1.1 2002-07-15 05:55:21 danield Exp $
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
 */

#ifndef _KERNEL_ALG_H
#define _KERNEL_ALG_H

/* status info */
extern void kernel_alg_show_status(void);
void kernel_alg_show_connection(struct connection *c, const char *instance);

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(void *buf, int buflen);

struct alg_info;
struct esp_info;
struct alg_info_ike;
struct alg_info_esp;
/* ESP interface */
extern struct sadb_alg *kernel_alg_esp_sadb_alg(int alg_id);
extern int kernel_alg_esp_ivlen(int alg_id);
/* returns bool success if esp encrypt alg is present  */
extern bool kernel_alg_esp_enc_ok(int alg_id, unsigned int key_len, struct alg_info_esp *nfo);
/* returns encrypt keylen in BYTES for esp enc alg passed */
extern int kernel_alg_esp_enc_keylen(int alg_id);
/* returns bool success if esp auth alg is present  */
extern bool kernel_alg_esp_auth_ok(int auth, struct alg_info_esp *nfo);
/* returns auth keylen in BYTES for esp auth alg passed */
extern int kernel_alg_esp_auth_keylen(int auth);
/* returns 0 if read ok from /proc/net/pf_key_supported */
extern int kernel_alg_proc_read(void);

/* get sadb_alg for passed args */
extern const struct sadb_alg * kernel_alg_sadb_alg_get(int satype, int exttype, int alg_id);

struct db_prop;
extern struct db_context * kernel_alg_db_new(struct alg_info_esp *ai, lset_t policy);
/* returns pointer to static buffer, no reentrant */
struct esp_info * kernel_alg_esp_info(int esp_id, int auth_id);
#endif /* _KERNEL_ALG_H */
