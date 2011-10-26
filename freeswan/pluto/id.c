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
 * RCSID $Id: id.c,v 1.18 2002/03/09 20:45:38 dhr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "x509.h"
#include "id.h"
#include "log.h"
#include "x509.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"

const struct id empty_id;	/* all zeros and NULLs */

/*  Note that there may be as many as four IDs that are temporary at
 *  one time before unsharing the two ends of a connection. So we need
 *  at least four temporary buffers for DER_ASN1_DN IDs.
 *  We rotate them. Be careful!
*/
char*
temporary_cyclic_buffer(void)
{
    static char buf[4][IDTOA_BUF];	/* four internal buffers */
    static int counter = 0;		/* cyclic counter */

    if (++counter == 4) counter = 0;	/* next internal buffer */
    return buf[counter];		/* assign temporary buffer */
}

/* Convert textual form of id into a (temporary) struct id.
 * Note that if the id is to be kept, unshare_id_content will be necessary.
 */
err_t
atoid(char *src, struct id *id)
{
    err_t ugh = NULL;

    *id = empty_id;

    if (strchr(src, '=') != NULL)
    {
	/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN */
	id->kind = ID_DER_ASN1_DN;
	id->name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
	id->name.len = 0;
	/* convert from LDAP style or openssl x509 -subject style to ASN.1 DN
	 * discard optional @ character in front of DN
	 */
	ugh = atodn((*src == '@')?src+1:src, &id->name);
    }
    else if (strchr(src, '@') == NULL)
    {
	if (streq(src, "%any") || streq(src, "0.0.0.0"))
	{
	    /* any ID will be accepted */
	    id->kind = ID_NONE;
	}
	else
	{
	   /* !!! this test is not sufficient for distinguishing address families.
	    * We need a notation to specify that a FQDN is to be resolved to IPv6.
	    */
	   const struct af_info *afi = strchr(src, ':') == NULL
		? &af_inet4_info: &af_inet6_info;

	   id->kind = afi->id_addr;
	   ugh = ttoaddr(src, 0, afi->af, &id->ip_addr);
	}
    }
    else
    {
	if (*src == '@')
	{
	    if (*(src+1) == '#')
	    {
		/* if there is a second specifier (#) on the line
		 * we interprete this as ID_KEY_ID
		 */
		id->kind = ID_KEY_ID;
		id->name.ptr = src;
		/* discard @~, convert from hex to bin */
		ugh = ttodata(src+2, 0, 16, id->name.ptr, strlen(src), &id->name.len);
	    }
	    else if (*(src+1) == '~')
	    {
		/* if there is a second specifier (~) on the line
		* we interprete this as a binary ID_DER_ASN1_DN
		*/
		id->kind = ID_DER_ASN1_DN;
		id->name.ptr = src;
		/* discard @~, convert from hex to bin */
		ugh = ttodata(src+2, 0, 16, id->name.ptr, strlen(src), &id->name.len);
	    }
	    else
	    {
		id->kind = ID_FQDN;
		id->name.ptr = src+1;	/* discard @ */
		id->name.len = strlen(src)-1;
	    }
	}
	else
	{
	    /* We leave in @, as per DOI 4.6.2.4
	     * (but DNS wants . instead).
	     */
	    id->kind = ID_USER_FQDN;
	    id->name.ptr = src;
	    id->name.len = strlen(src);
	}
#ifdef INTEROP_CHECKPOINT_FW_4_1
	/* why couldn't they have used ID_KEY_ID? (violates RFC2407 4.6.2.4) */
	if (id->kind == ID_USER_FQDN && id->name.len > 0)
	{
	    if (src[id->name.len-1] == '@')
		id->name.len--;
	}
#endif
    }
    return ugh;
}


/*
 *  Converts a binary key ID into hexadecimal format
 */
int
keyidtoa(char *dst, size_t dstlen, chunk_t keyid)
{
    chunk_t str;
    str.ptr = dst;
    str.len = dstlen;
    hex_str(keyid, &str);
    return (int)(dstlen - str.len);
}

void
iptoid(const ip_address *ip, struct id *id)
{
    *id = empty_id;

    switch (addrtypeof(ip))
    {
    case AF_INET:
	id->kind = ID_IPV4_ADDR;
	break;
    case AF_INET6:
	id->kind = ID_IPV6_ADDR;
	break;
    default:
	impossible();
    }
    id->ip_addr = *ip;
}

int
idtoa(const struct id *id, char *dst, size_t dstlen)
{
    int n;

    switch (id->kind)
    {
    case ID_NONE:
	n = snprintf(dst, dstlen, "(none)");
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	n = (int)addrtot(&id->ip_addr, 0, dst, dstlen) - 1;
	break;
    case ID_FQDN:
	n = snprintf(dst, dstlen, "@%.*s", (int)id->name.len, id->name.ptr);
	break;
    case ID_USER_FQDN:
#ifdef INTEROP_CHECKPOINT_FW_4_1
 	n = snprintf(dst, dstlen, "%.*s%s", (int)id->name.len, id->name.ptr,
	    strchr(id->name.ptr, '@') ? "" : "@");
	break;
#else
	n = snprintf(dst, dstlen, "%.*s", (int)id->name.len, id->name.ptr);
	break;
#endif
    case ID_DER_ASN1_DN:
	n = dntoa(dst, dstlen, id->name);
	break;
    case ID_KEY_ID:
	n = keyidtoa(dst, dstlen, id->name);
	break;
    default:
	n = snprintf(dst, dstlen, "unknown id kind %d", id->kind);
	break;
    }

    /* "Sanitize" string so that log isn't endangered:
     * replace unprintable characters with '?'.
     */
    if (n > 0)
    {
	for ( ; *dst != '\0'; dst++)
	    if (!isprint(*dst))
		*dst = '?';
    }

    return n;
}

/* Make private copy of string in struct id.
 * This is needed if the result of atoid is to be kept.
 */
void
unshare_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	id->name.ptr = clone_bytes(id->name.ptr, id->name.len, "keep id name");
	break;
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	impossible();
    }
}

void
free_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	pfree(id->name.ptr);
	break;
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	impossible();
    }
}

/* compare two struct id values */
bool
same_id(const struct id *a, const struct id *b)
{
    if (a->kind != b->kind)
	return FALSE;
    switch (a->kind)
    {
    case ID_NONE:
	return TRUE;	/* kind of vacuous */

    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	return sameaddr(&a->ip_addr, &b->ip_addr);

    case ID_FQDN:
    case ID_USER_FQDN:
	/* assumption: case should be ignored */
	return a->name.len == b->name.len
	    && strncasecmp(a->name.ptr, b->name.ptr, a->name.len) == 0;
    case ID_DER_ASN1_DN:
    	return same_dn(a->name, b->name);
    case ID_KEY_ID:
	/* pretend that it's binary */
	return a->name.len == b->name.len
	    && memcmp(a->name.ptr, b->name.ptr, a->name.len) == 0;
    default:
	impossible();
    }
}

/* build an ID payload
 * Note: no memory is allocated for the body of the payload (tl->ptr).
 * We assume it will end up being a pointer into a sufficiently
 * stable datastructure.  It only needs to last a short time.
 */
void
build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, struct end *end)
{
    zero(hd);
    hd->isaiid_idtype = end->id.kind;
    switch (end->id.kind)
    {
    case ID_NONE:
	hd->isaiid_idtype = aftoinfo(addrtypeof(&end->host_addr))->id_addr;
	tl->len = addrbytesptr(&end->host_addr
	    , (const unsigned char **)&tl->ptr);	/* sets tl->ptr too */
	break;
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	*tl = end->id.name;
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	tl->len = addrbytesptr(&end->id.ip_addr
	    , (const unsigned char **)&tl->ptr);	/* sets tl->ptr too */
	break;
    default:
	impossible();
    }
}
