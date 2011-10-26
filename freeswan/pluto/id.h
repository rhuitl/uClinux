/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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
 * RCSID $Id: id.h,v 1.16 2002/01/21 03:14:17 dhr Exp $
 */

struct id {
    int kind;	        /* ID_* value */
    ip_address ip_addr;	/* ID_IPV4_ADDR, ID_IPV6_ADDR     */
    chunk_t name;	/* ID_FQDN, ID_USER_FQDN (with @) */
			/* ID_KEY_ID, ID_DER_ASN_DN       */
};

extern const struct id empty_id;

extern err_t atoid(char *src, struct id *id);
extern int keyidtoa(char *dst, size_t dstlen, chunk_t keyid);
extern void iptoid(const ip_address *ip, struct id *id);
extern char* temporary_cyclic_buffer(void);
extern int idtoa(const struct id *id, char *dst, size_t dstlen);
#define IDTOA_BUF 512
struct end;	/* forward declaration of tag (defined in connections.h) */
extern void unshare_id_content(struct id *id);
extern void free_id_content(struct id *id);
extern bool same_id(const struct id *a, const struct id *b);
#define id_is_ipaddr(id) ((id)->kind == ID_IPV4_ADDR || (id)->kind == ID_IPV6_ADDR)

struct isakmp_ipsec_id;	/* forward declaration of tag (defined in packet.h) */
extern void
    build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, struct end *end);
