/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: preshared.c,v 1.60 2002/03/22 23:38:28 dhr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <netdb.h>

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND	/* fix for old versions */
#endif

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "preshared.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs preshared.h and adns.h */
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "pkcs.h"

/* Maximum length of filename and passphrase buffer */

#define BUF_LEN		256

#ifdef NAT_TRAVERSAL
#define PB_STREAM_UNDEFINED
#include "nat_traversal.h"
#endif

struct fld {
    const char *name;
    size_t offset;
};

static const struct fld RSA_private_field[] =
{
    { "Modulus", offsetof(struct RSA_private_key, pub.n) },
    { "PublicExponent", offsetof(struct RSA_private_key, pub.e) },

    { "PrivateExponent", offsetof(struct RSA_private_key, d) },
    { "Prime1", offsetof(struct RSA_private_key, p) },
    { "Prime2", offsetof(struct RSA_private_key, q) },
    { "Exponent1", offsetof(struct RSA_private_key, dP) },
    { "Exponent2", offsetof(struct RSA_private_key, dQ) },
    { "Coefficient", offsetof(struct RSA_private_key, qInv) },
};

#ifdef DEBUG
static void
RSA_show_key_fields(struct RSA_private_key *k, int fieldcnt)
{
    const struct fld *p;

    DBG_log(" keyid: *%s", k->pub.keyid);

    for (p = RSA_private_field; p < &RSA_private_field[fieldcnt]; p++)
    {
	MP_INT *n = (MP_INT *) ((char *)k + p->offset);
	size_t sz = mpz_sizeinbase(n, 16);
	char buf[2048/4 + 2];	/* ought to be big enough */

	passert(sz <= sizeof(buf));
	mpz_get_str(buf, 16, n);

	DBG_log(" %s: %s", p->name, buf);
    }
}

/* debugging info that compromises security! */
static void
RSA_show_private_key(struct RSA_private_key *k)
{
    RSA_show_key_fields(k, elemsof(RSA_private_field));
}

static void
RSA_show_public_key(struct RSA_public_key *k)
{
    /* Kludge: pretend that it is a private key, but only display the
     * first two fields (which are the public key).
     */
    passert(offsetof(struct RSA_private_key, pub) == 0);
    RSA_show_key_fields((struct RSA_private_key *)k, 2);
}
#endif

static const char *
RSA_private_key_sanity(struct RSA_private_key *k)
{
    /* note that the *last* error found is reported */
    err_t ugh = NULL;
    mpz_t t, u, q1;

#ifdef DEBUG	/* debugging info that compromises security */
    DBG(DBG_PRIVATE, RSA_show_private_key(k));
#endif

    /* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
     * We actually require more (for security).
     */
    if (k->pub.k < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    /* we picked a max modulus size to simplify buffer allocation */
    if (k->pub.k > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    mpz_init(t);
    mpz_init(u);
    mpz_init(q1);

    /* check that n == p * q */
    mpz_mul(u, &k->p, &k->q);
    if (mpz_cmp(u, &k->pub.n) != 0)
	ugh = "n != p * q";

    /* check that e divides neither p-1 nor q-1 */
    mpz_sub_ui(t, &k->p, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides p-1";

    mpz_sub_ui(t, &k->q, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides q-1";

    /* check that d is e^-1 (mod lcm(p-1, q-1)) */
    /* see PKCS#1v2, aka RFC 2437, for the "lcm" */
    mpz_sub_ui(q1, &k->q, 1);
    mpz_sub_ui(u, &k->p, 1);
    mpz_gcd(t, u, q1);		/* t := gcd(p-1, q-1) */
    mpz_mul(u, u, q1);		/* u := (p-1) * (q-1) */
    mpz_divexact(u, u, t);	/* u := lcm(p-1, q-1) */

    mpz_mul(t, &k->d, &k->pub.e);
    mpz_mod(t, t, u);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "(d * e) mod (lcm(p-1, q-1)) != 1";

    /* check that dP is d mod (p-1) */
    mpz_sub_ui(u, &k->p, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dP) != 0)
	ugh = "dP is not congruent to d mod (p-1)";

    /* check that dQ is d mod (q-1) */
    mpz_sub_ui(u, &k->q, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dQ) != 0)
	ugh = "dQ is not congruent to d mod (q-1)";

    /* check that qInv is (q^-1) mod p */
    mpz_mul(t, &k->qInv, &k->q);
    mpz_mod(t, t, &k->p);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "qInv is not conguent ot (q^-1) mod p";

    mpz_clear(t);
    mpz_clear(u);
    mpz_clear(q1);
    return ugh;
}

const char *shared_secrets_file = SHARED_SECRETS_FILE;

struct id_list {
    struct id id;
    struct id_list *next;
};

struct secret {
    struct id_list *ids;
    enum PrivateKeyKind kind;
    union {
	chunk_t preshared_secret;
	struct RSA_private_key RSA_private_key;
    } u;
    struct secret *next;
};

static struct pubkeyrec*
allocate_RSA_public_key(const x509cert_t *cert)
{
    struct pubkeyrec *p = alloc_thing(struct pubkeyrec, "pubkeyrec");
    chunk_t e = cert->publicExponent;
    chunk_t n = cert->modulus;

    /* eliminate leading zero byte in modulus from ASN.1 coding */
    if (*n.ptr == 0x00)
    {
	n.ptr++;  n.len--;
    }
    n_to_mpz(&p->u.rsa.e, e.ptr, e.len);
    n_to_mpz(&p->u.rsa.n, n.ptr, n.len);

    /* form keyid */
    p->u.rsa.keyid[0] = '\0';	/* in case of splitkeytoid failure */
    splitkeytoid(e.ptr, e.len, n.ptr, n.len, p->u.rsa.keyid, sizeof(p->u.rsa.keyid));

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(&p->u.rsa));
#endif

    p->u.rsa.k = mpz_sizeinbase(&p->u.rsa.n, 2);	/* size in bits, for a start */
    p->u.rsa.k = (p->u.rsa.k + BITS_PER_BYTE - 1) / BITS_PER_BYTE;	/* now octets */

    p->alg = PUBKEY_ALG_RSA;
    p->id  = empty_id;

    return p;
}

struct secret *secrets = NULL;

/* find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 */
static const struct secret *
get_id_secret(enum PrivateKeyKind kind
, bool asym
, struct id *my_id
, struct id *his_id
, struct pubkeyrec *my_public_key)
{
    enum {
	match_default = 0x01,
	match_him = 	0x02,
	match_me = 	0x04,
	match_pubkey =	0x08
    };

    unsigned int best_match = 0;
    struct secret *best = NULL;
    struct secret *s;

    for (s = secrets; s != NULL; s = s->next)
    {
	if (s->kind == kind)
	{
	    unsigned int match = 0;

	    if (s->ids == NULL)
	    {
		/* a default (signified by lack of ids):
		 * accept if no more specific match found
		 */
		match = match_default;
	    }
	    else
	    {
		/* check if both ends match ids */
		struct id_list *i;

		for (i = s->ids; i != NULL; i = i->next)
		{
		    if (same_id(my_id, &i->id))
			match |= match_me;

		    if (same_id(his_id, &i->id))
			match |= match_him;
		}

		/* If our end matched the only id in the list,
		 * default to matching any peer.
		 * A more specific match will trump this.
		 */
		if (match == match_me
		&& s->ids->next == NULL)
		    match |= match_default;
	    }

	    if (my_public_key != NULL &&
	    	same_RSA_public_key(&s->u.RSA_private_key.pub, &my_public_key->u.rsa))
	    {
		match = match_pubkey;
	    }

	    if (match == match_pubkey)
	    {
		best = s;
		break; /* we have found the private key - no sense in searching further */
	    }

	    switch (match)
	    {
	    case match_me:
		/* if this is an asymmetric (eg. public key) system,
		 * allow this-side-only match to count, even if
		 * there are other ids in the list.
		 */
		if(!asym)
		    break;
		/* FALLTHROUGH */
	    case match_default:	/* default all */
	    case match_me | match_default:	/* default peer */
	    case match_me | match_him:	/* explicit */
		if (match == best_match)
		{
		    /* two good matches are equally good:
		     * do they agree?
		     */
		    bool same;

		    switch (kind)
		    {
		    case PPK_PSK:
			same = s->u.preshared_secret.len == best->u.preshared_secret.len
			    && memcmp(s->u.preshared_secret.ptr, best->u.preshared_secret.ptr, s->u.preshared_secret.len) == 0;
			break;
		    case PPK_RSA:
			/* Dirty trick: since we have code to compare
			 * RSA public keys, but not private keys, we
			 * make the assumption that equal public keys
			 * mean equal private keys.  This ought to work.
			 */
			same = same_RSA_public_key(&s->u.RSA_private_key.pub
			    , &best->u.RSA_private_key.pub);
			break;
		    default:
			impossible();
		    }
		    if (!same)
		    {
			loglog(RC_LOG_SERIOUS, "multiple ipsec.secrets entries with distinct secrets match endpoints:"
			    " first secret used");
			best = s;	/* list is backwards: take latest in list */
		    }
		}
		else if (match > best_match)
		{
		    /* this is the best match so far */
		    best_match = match;
		    best = s;
		}
	    }
	}
    }
    return best;
}

static const struct secret *
get_secret(struct connection *c, enum PrivateKeyKind kind, bool asym)
{
    const struct secret *best = NULL;
    struct id *my_id = &c->this.id
	, rw_id, my_rw_id
	, *his_id = &c->that.id;

    struct pubkeyrec *my_public_key = NULL;

    /* is there a certificate assigned to this connection? */
    if (kind == PPK_RSA && c->this.cert != NULL)
    {
	my_public_key = allocate_RSA_public_key(c->this.cert);
    }

    if (his_id_was_instantiated(c))
    {
	/* roadwarrior: replace him with ID_NONE */
	rw_id.kind = ID_NONE;
	his_id = &rw_id;
    }
#ifdef NAT_TRAVERSAL
    else if ((nat_traversal_enabled) && (c->policy & POLICY_PSK) &&
	(kind == PPK_PSK) && (
	    ((c->kind == CK_TEMPLATE) && (c->that.id.kind == ID_NONE)) ||
	    ((c->kind == CK_INSTANCE) && (id_is_ipaddr(&c->that.id)))))
    {
	/* roadwarrior: replace him with ID_NONE */
	rw_id.kind = ID_NONE;
	his_id = &rw_id;
    }
#endif

    best = get_id_secret(kind, asym, my_id, his_id, my_public_key);
    if (best == NULL) {
	/* replace me with ID_NONE and try again */
	my_rw_id.kind = ID_NONE;
	my_id = &my_rw_id;
	best = get_id_secret(kind, asym, my_id, his_id, my_public_key);
    }

    if (my_public_key != NULL)
    {
	free_public_key(my_public_key);
    }
    return best;
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t *
get_preshared_secret(struct connection *c)
{
    const struct secret *s = get_secret(c, PPK_PSK, FALSE);

#ifdef DEBUG
    DBG(DBG_PRIVATE,
	if (s == NULL)
	    DBG_log("no Preshared Key Found");
	else
	    DBG_dump_chunk("Preshared Key", s->u.preshared_secret);
	);
#endif
    return s == NULL? NULL : &s->u.preshared_secret;
}

/* find the appropriate RSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct RSA_private_key *
get_RSA_private_key(struct connection *c)
{
    const struct secret *s = get_secret(c, PPK_RSA, TRUE);

    return s == NULL? NULL : &s->u.RSA_private_key;
}

/* digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for ttodata(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The key part can be in several forms.
 *
 * The old form of the key is still supported: a simple
 * quoted strings (with no escapes) is taken as a preshred key.
 *
 * The new form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for ttodata(3).
 *
 * For RSA Private Key, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by ttodata(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 */

struct secrets_file_position
{
    int depth;	/* how deeply we are nested */
    char *filename;
    FILE *fp;
    enum { B_none, B_record, B_file } bdry;	/* current boundary */
    int lino;	/* line number in file */
    char buffer[2049];    /* note: one extra char for our use (jamming '"') */
    char *cur;	/* cursor */
    char under;	/* except in shift(): character orignally at *cur */
    struct secrets_file_position *previous;
};

static struct secrets_file_position *sfp = NULL;

/* Token decoding: shift() loads the next token into tok.
 * Iff a token starts at the left margin, it is considered
 * to be the first in a record.  We create a special condition,
 * Record Boundary (analogous to EOF), just before such a token.
 * We are unwilling to shift through a record boundary:
 * it must be overridden first.
 * Returns FALSE iff Record Boundary or EOF (i.e. no token);
 * tok will then be NULL.
 */

static void process_secrets_file(const char *file_pat);

static char *tok;
#define tokeq(s) (streq(tok, (s)))
#define tokeqword(s) (strcasecmp(tok, (s)) == 0)

static bool
shift(void)
{
    char *p = sfp->cur;
    char *sor = NULL;	/* start of record for any new lines */

    passert(sfp->bdry == B_none);

    *p = sfp->under;
    sfp->under = '\0';

    for (;;)
    {
	switch (*p)
	{
	case '\0':	/* end of line */
	case '#':	/* comment to end of line: treat as end of line */
	    /* get the next line */
	    if (fgets(sfp->buffer, sizeof(sfp->buffer)-1, sfp->fp) == NULL)
	    {
		sfp->bdry = B_file;
		tok = sfp->cur = NULL;
		return FALSE;
	    }
	    else
	    {
		/* strip trailing whitespace, including \n */

		for (p = sfp->buffer+strlen(sfp->buffer)-1; p>sfp->buffer; p--)
		    if (!isspace(p[-1]))
			break;
		*p = '\0';

		sfp->lino++;
		sor = p = sfp->buffer;
	    }
	    break;	/* try again for a token */

	case ' ':	/* whitespace */
	case '\t':
	    p++;
	    break;	/* try again for a token */

	case '"':	/* quoted token */
	case '\'':
	    if (p != sor)
	    {
		/* we have a quoted token: note and advance to its end */
		tok = p;
		p = strchr(p+1, *p);
		if (p == NULL)
		{
		    loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unterminated string"
			, sfp->filename, sfp->lino);
		    p = tok + strlen(tok);
		}
		else
		{
		    p++;	/* include delimiter in token */
		}

		/* remember token delimiter and replace with '\0' */
		sfp->under = *p;
		*p = '\0';
		sfp->cur = p;
		return TRUE;
	    }
	    /* FALL THROUGH */
	default:
	    if (p != sor)
	    {
		/* we seem to have a token: note and advance to its end */
		tok = p;

		if (p[0] == '0' && p[1] == 't')
		{
		    /* 0t... token goes to end of line */
		    p += strlen(p);
		}
		else
		{
		    /* "ordinary" token: up to whitespace or end of line */
		    do {
			p++;
		    } while (*p != '\0' && !isspace(*p))
			;

		    /* fudge to separate ':' from a preceding adjacent token */
		    if (p-1 > tok && p[-1] == ':')
			p--;
		}

		/* remember token delimiter and replace with '\0' */
		sfp->under = *p;
		*p = '\0';
		sfp->cur = p;
		return TRUE;
	    }

	    /* we have a start-of-record: return it, deferring "real" token */
	    sfp->bdry = B_record;
	    tok = NULL;
	    sfp->under = *p;
	    sfp->cur = p;
	    return FALSE;
	}
    }
}

/* ensures we are at a Record (or File) boundary, optionally warning if not */

static bool
flushline(const char *m)
{
    if (sfp->bdry != B_none)
    {
	return TRUE;
    }
    else
    {
	if (m != NULL)
	    loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s", sfp->filename, sfp->lino, m);
	do ; while (shift());
	return FALSE;
    }
}

/* parse PSK from file */
static err_t
process_psk_secret(chunk_t *psk)
{
    err_t ugh = NULL;

    if (*tok == '"' || *tok == '\'')
    {
	clonetochunk(*psk, tok+1, sfp->cur - tok  - 2, "PSK");
	(void) shift();
    }
    else
    {
	char buf[2048];	/* limit on size of binary representation of key */
	size_t sz;

	ugh = ttodatav(tok, sfp->cur - tok, 0, buf, sizeof(buf), &sz
	    , diag_space, sizeof(diag_space));
	if (ugh != NULL)
	{
	    /* ttodata didn't like PSK data */
	    ugh = builddiag("PSK data malformed (%s): %s", ugh, tok);
	}
	else
	{
	    clonetochunk(*psk, buf, sz, "PSK");
	    (void) shift();
	}
    }
    return ugh;
}

/* Parse fields of RSA private key.
 * A braced list of keyword and value pairs.
 * At the moment, each field is required, in order.
 * The fields come from BIND 8.2's representation
 */
static err_t
process_rsa_secret(struct RSA_private_key *rsak)
{
    char buf[2048];	/* limit on size of binary representation of key */
    const struct fld *p;

    /* save bytes of Modulus and PublicExponent for keyid calculation */
    unsigned char ebytes[sizeof(buf)];
    unsigned char *eb_next = ebytes;
    chunk_t pub_bytes[2];
    chunk_t *pb_next = &pub_bytes[0];

    for (p = RSA_private_field; p < &RSA_private_field[elemsof(RSA_private_field)]; p++)
    {
	size_t sz;
	err_t ugh;

	if (!shift())
	{
	    return "premature end of RSA key";
	}
	else if (!tokeqword(p->name))
	{
	    return builddiag("%s keyword not found where expected in RSA key"
		, p->name);
	}
	else if (!(shift()
	&& (!tokeq(":") || shift())))	/* ignore optional ":" */
	{
	    return "premature end of RSA key";
	}
	else if (NULL != (ugh = ttodatav(tok, sfp->cur - tok
	, 0, buf, sizeof(buf), &sz, diag_space, sizeof(diag_space))))
	{
	    /* in RSA key, ttodata didn't like */
	    return builddiag("RSA data malformed (%s): %s", ugh, tok);
	}
	else
	{
	    MP_INT *n = (MP_INT *) ((char *)rsak + p->offset);

	    n_to_mpz(n, buf, sz);
	    if (pb_next < &pub_bytes[elemsof(pub_bytes)])
	    {
		if (eb_next - ebytes + sz > sizeof(ebytes))
		    return "public key takes too many bytes";

		setchunk(*pb_next, eb_next, sz);
		memcpy(eb_next, buf, sz);
		eb_next += sz;
		pb_next++;
	    }
#if 0	/* debugging info that compromises security */
	    {
		size_t sz = mpz_sizeinbase(n, 16);
		char buf[2048/4 + 2];	/* ought to be big enough */

		passert(sz <= sizeof(buf));
		mpz_get_str(buf, 16, n);

		loglog(RC_LOG_SERIOUS, "%s: %s", p->name, buf);
	    }
#endif
	}
    }

    /* We require an (indented) '}' and the end of the record.
     * We break down the test so that the diagnostic will be
     * more helpful.  Some people don't seem to wish to indent
     * the brace!
     */
    if (!shift() || !tokeq("}"))
    {
	return "malformed end of RSA private key -- indented '}' required";
    }
    else if (shift())
    {
	return "malformed end of RSA private key -- unexpected token after '}'";
    }
    else
    {
	unsigned bits = mpz_sizeinbase(&rsak->pub.n, 2);

	rsak->pub.k = (bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
	rsak->pub.keyid[0] = '\0';	/* in case of splitkeytoid failure */
	splitkeytoid(pub_bytes[1].ptr, pub_bytes[1].len
	    , pub_bytes[0].ptr, pub_bytes[0].len
	    , rsak->pub.keyid, sizeof(rsak->pub.keyid));
	return RSA_private_key_sanity(rsak);
    }
}

static void
process_secret(struct secret *s)
{
    err_t ugh = NULL;

    s->kind = PPK_PSK;	/* default */
    if (*tok == '"' || *tok == '\'')
    {
	/* old PSK format: just a string */
	ugh = process_psk_secret(&s->u.preshared_secret);
    }
    else if (tokeqword("psk"))
    {
	/* preshared key: quoted string or ttodata format */
	ugh = !shift()? "unexpected end of record in PSK"
	    : process_psk_secret(&s->u.preshared_secret);
    }
    else if (tokeqword("rsa"))
    {
	/* RSA key: the fun begins.
	 * A braced list of keyword and value pairs.
	 */
	s->kind = PPK_RSA;
	if (!shift())
	{
	    ugh = "bad RSA key syntax";
	}
	else if (tokeq("{"))
	{
	    ugh = process_rsa_secret(&s->u.RSA_private_key);
	}
	else
	{
	    /* we expect the filename of a PKCS#1 private key file */
	    char filename[BUF_LEN];
	    char passphrase[BUF_LEN];
	    pkcs1privkey_t *key = NULL;

	    memset(filename,   '\0', BUF_LEN);
	    memset(passphrase, '\0', BUF_LEN);

	    if (*tok == '"' || *tok == '\'')  /* quoted filename */
		memcpy(filename, tok+1, sfp->cur - tok - 2);
	    else
	    	memcpy(filename, tok, sfp->cur - tok);

	    if (shift())
	    {
		/* we expect an appended passphrase */
		if (*tok == '"' || *tok == '\'') /* quoted passphrase */
		   memcpy(passphrase, tok+1, sfp->cur - tok - 2);
		else
		   memcpy(passphrase, tok, sfp->cur - tok);

		if (shift())
		{
		    ugh = "RSA private key file -- unexpected token after passphrase";
		}
	    }

	    key = load_pkcs1_private_key(filename, passphrase);

	    if (key == NULL)
		ugh = "error loading RSA private key file";
	    else
	    {
		u_int i;

		for (i = 0; ugh == NULL && i < elemsof(RSA_private_field); i++)
		{
		    MP_INT *n = (MP_INT *) ((char *)&s->u.RSA_private_key +
							  RSA_private_field[i].offset);
		    n_to_mpz(n, key->field[i].ptr, key->field[i].len);
		}
		{
		    unsigned bits = mpz_sizeinbase(&s->u.RSA_private_key.pub.n, 2);
		    chunk_t n = key->field[0]; /* public modulus n */
		    chunk_t e = key->field[1]; /* public exponent e */

		    /* eliminate leading zero byte in modulus from ASN.1 coding */
		    if (*n.ptr == 0x00)
		    {
			n.ptr++;  n.len--;
    		    }

		    s->u.RSA_private_key.pub.k = (bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;

		    /* compute keyid */
		    s->u.RSA_private_key.pub.keyid[0] = '\0';	/* in case of splitkeytoid failure */
		    splitkeytoid(e.ptr, e.len, n.ptr, n.len
			, s->u.RSA_private_key.pub.keyid, sizeof(s->u.RSA_private_key.pub.keyid));

		    ugh = RSA_private_key_sanity(&s->u.RSA_private_key);
		}
		pfree(key->pkcs1object.ptr);
		pfree(key);
	    }
	}
    }
    else
    {
	ugh = builddiag("unrecognized key format: %s", tok);
    }

    if (ugh != NULL)
    {
	loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s"
	    , sfp->filename, sfp->lino, ugh);
    }
    else if (flushline("expected record boundary in key"))
    {
	/* gauntlet has been run: install new secret */
	s->next = secrets;
	secrets = s;
    }
}

static void
process_secret_records(void)
{
    struct hostent *h;
    const char *cp;
    size_t n;
    char **h_addr_list_element;
    int h_addr_list_size = 0;
    size_t strlength = 0;
    int count;
    int multiple_ips = FALSE;
    /* read records from ipsec.secrets and load them into our table */
    for (;;)
    {
	(void)flushline(NULL);	/* silently ditch leftovers, if any */
	if (sfp->bdry == B_file)
	    break;

	sfp->bdry = B_none;	/* eat the Record Boundary */
	(void)shift();	/* get real first token */

	if (tokeqword("include"))
	{
	    /* an include directive */
	    char fn[2048];	/* space for filename (I hope) */
	    char *p = fn;
	    char *end_prefix = strrchr(sfp->filename, '/');

	    if (!shift())
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of include directive"
		    , sfp->filename, sfp->lino);
		continue;   /* abandon this record */
	    }

	    /* if path is relative and including file's pathname has
	     * a non-empty dirname, prefix this path with that dirname.
	     */
	    if (tok[0] != '/' && end_prefix != NULL)
	    {
		size_t pl = end_prefix - sfp->filename + 1;

		/* "clamp" length to prevent problems now;
		 * will be rediscovered and reported later.
		 */
		if (pl > sizeof(fn))
		    pl = sizeof(fn);
		memcpy(fn, sfp->filename, pl);
		p += pl;
	    }
	    if (sfp->cur - tok >= &fn[sizeof(fn)] - p)
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: include pathname too long"
		    , sfp->filename, sfp->lino);
		continue;   /* abandon this record */
	    }
	    strcpy(p, tok);
	    (void) shift();	/* move to Record Boundary, we hope */
	    if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
	    {
		process_secrets_file(fn);
		tok = NULL;	/* correct, but probably redundant */
	    }
	}
	else
	{
	    /* expecting a list of indices and then the key info */
	    struct secret *s = alloc_thing(struct secret, "secret");

	    s->ids = NULL;
	    s->kind = PPK_PSK;	/* default */
	    setchunk(s->u.preshared_secret, NULL, 0);
	    s->next = NULL;

	    for (;;)
	    {
		if (tok[0] == '"' || tok[0] == '\'')
		{
		    /* found key part */
		    process_secret(s);
		    break;
		}
		else if (tokeq(":"))
		{
		    /* found key part */
		    shift();	/* discard explicit separator */
		    process_secret(s);
		    break;
		}
		else
		{
		    /* an id
		     * See RFC2407 IPsec Domain of Interpretation 4.6.2
		     */
		    struct id id;
		    err_t ugh;

		    if (tokeq("%any"))
		    {
			id = empty_id;
			id.kind = ID_IPV4_ADDR;
			ugh = anyaddr(AF_INET, &id.ip_addr);
		    }
		    else if (tokeq("%any6"))
		    {
			id = empty_id;
			id.kind = ID_IPV6_ADDR;
			ugh = anyaddr(AF_INET6, &id.ip_addr);
		    }
		    else
		    {
			ugh = atoid(tok, &id);	
		    }
		    if (ugh != NULL)
		    {
			loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s \"%s\""
			    , sfp->filename, sfp->lino, ugh, tok);
		    }
		    else
		    {
			struct id_list *i = alloc_thing(struct id_list
			    , "id_list");

			i->id = id;
			unshare_id_content(&i->id);
			i->next = s->ids;
			s->ids = i;
			/* DBG_log("id type %d: %s %.*s", i->kind, ip_str(&i->ip_addr), (int)i->name.len, i->name.ptr); */
		    }
		    if (!shift())
		    {
			/* unexpected Record Boundary or EOF */
			loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of id list"
			    , sfp->filename, sfp->lino);
			break;
		    }
		}
	    }
	}
    }
}

static int
globugh(const char *epath, int eerrno)
{
    log_errno_routine(eerrno, "problem with secrets file \"%s\"", epath);
    return 1;	/* stop glob */
}

static void
process_secrets_file(const char *file_pat)
{
    struct secrets_file_position pos;
    char **fnp;
    glob_t globbuf;

    pos.depth = sfp == NULL? 0 : sfp->depth + 1;

    if (pos.depth > 10)
    {
	loglog(RC_LOG_SERIOUS, "preshared secrets file \"%s\" nested too deeply", file_pat);
	return;
    }

    /* do globbing */
    {
	int r = glob(file_pat, GLOB_ERR, globugh, &globbuf);

	if (r != 0)
	{
	    switch (r)
	    {
	    case GLOB_NOSPACE:
		loglog(RC_LOG_SERIOUS, "out of space processing secrets filename \"%s\"", file_pat);
		break;
	    case GLOB_ABORTED:
		break;	/* already logged */
	    case GLOB_NOMATCH:
		loglog(RC_LOG_SERIOUS, "no secrets filename matched \"%s\"", file_pat);
		break;
	    default:
		loglog(RC_LOG_SERIOUS, "unknown glob error %d", r);
		break;
	    }
	    globfree(&globbuf);
	    return;
	}
    }

    pos.previous = sfp;
    sfp = &pos;

    /* for each file... */
    for (fnp = globbuf.gl_pathv; *fnp != NULL; fnp++)
    {
#if defined(CONFIG_SNAPGEAR) || defined(CONFIG_SECUREEDGE)
	char *cmd;
	int len;

	len = strlen(*fnp) + sizeof("ipsec showfile %s");
	cmd = (char *) malloc(len);
	if (!cmd) {
	    log_errno((e, "fail to allocate memory"));
	    continue;	/* try the next one */
	}
	snprintf(cmd, len, "ipsec showfile %s", *fnp);
	pos.filename = *fnp;
	pos.fp = popen(cmd, "r");
	if (pos.fp == NULL)
	{
	    log_errno((e, "could not open \"%s\"", cmd));
		free(cmd);
	    continue;	/* try the next one */
	}
	free(cmd);
#else
	pos.filename = *fnp;
	pos.fp = fopen(pos.filename, "r");
	if (pos.fp == NULL)
	{
	    log_errno((e, "could not open \"%s\"", pos.filename));
	    continue;	/* try the next one */
	}
#endif

	log("loading secrets from \"%s\"", pos.filename);

	pos.lino = 0;
	pos.bdry = B_none;

	pos.cur = pos.buffer;	/* nothing loaded yet */
	pos.under = *pos.cur = '\0';

	(void) shift();	/* prime tok */
	(void) flushline("file starts with indentation (continuation notation)");
	process_secret_records();
#if defined(CONFIG_SNAPGEAR) || defined(CONFIG_SECUREEDGE)
	pclose(pos.fp);
#else
	fclose(pos.fp);
#endif
    }

    sfp = pos.previous;	/* restore old state */
}

void
free_preshared_secrets(void)
{
    if (secrets != NULL)
    {
	struct secret *s, *ns;

	log("forgetting secrets");

	for (s = secrets; s != NULL; s = ns)
	{
	    struct id_list *i, *ni;

	    ns = s->next;	/* grab before freeing s */
	    for (i = s->ids; i != NULL; i = ni)
	    {
		ni = i->next;	/* grab before freeing i */
		free_id_content(&i->id);
		pfree(i);
	    }
	    switch (s->kind)
	    {
	    case PPK_PSK:
		pfree(s->u.preshared_secret.ptr);
		break;
	    case PPK_RSA:
		free_RSA_public_content(&s->u.RSA_private_key.pub);
		mpz_clear(&s->u.RSA_private_key.d);
		mpz_clear(&s->u.RSA_private_key.p);
		mpz_clear(&s->u.RSA_private_key.q);
		mpz_clear(&s->u.RSA_private_key.dP);
		mpz_clear(&s->u.RSA_private_key.dQ);
		mpz_clear(&s->u.RSA_private_key.qInv);
		break;
	    default:
		impossible();
	    }
	    pfree(s);
	}
	secrets = NULL;
    }
}

void
load_preshared_secrets(void)
{
    free_preshared_secrets();
    (void) process_secrets_file(shared_secrets_file);
}

/* public key machinery */

struct pubkeyrec *
public_key_from_rsa(const struct RSA_public_key *k)
{
    struct pubkeyrec *p = alloc_thing(struct pubkeyrec, "pubkeyrec");

    p->id = empty_id;	/* don't know, doesn't matter */

    p->alg = PUBKEY_ALG_RSA;

    p->u.rsa.k = k->k;
    mpz_init_set(&p->u.rsa.e, &k->e);
    mpz_init_set(&p->u.rsa.n, &k->n);

    p->next = NULL;
    return p;
}

void free_RSA_public_content(struct RSA_public_key *rsa)
{
    mpz_clear(&rsa->n);
    mpz_clear(&rsa->e);
}

/* Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkeyrec *
free_public_key(struct pubkeyrec *p)
{
    struct pubkeyrec *nxt = p->next;

    free_id_content(&p->id);

    /* algorithm-specific freeing */
    switch (p->alg)
    {
    case PUBKEY_ALG_RSA:
	free_RSA_public_content(&p->u.rsa);
	break;
    default:
	impossible();
    }

    pfree(p);
    return nxt;
}

void
free_public_keys(struct pubkeyrec **keys)
{
    while (*keys != NULL)
	*keys = free_public_key(*keys);
}

/* root of chained public key list */

struct pubkeyrec *pubkeys = NULL;	/* keys from ipsec.conf */

void
free_remembered_public_keys(void)
{
    free_public_keys(&pubkeys);
}

/* transfer public keys from *keys list to front of pubkeys list */
void
remember_public_keys(struct pubkeyrec **keys)
{
    struct pubkeyrec **pp = keys;

    while (*pp != NULL)
	pp = &(*pp)->next;
    *pp = pubkeys;
    pubkeys = *keys;
    *keys = NULL;
}

/* decode of RSA pubkey chunk
 * - format specified in RFC 2537 RSA/MD5 Keys and SIGs in the DNS
 * - exponent length in bytes (1 or 3 octets)
 *   + 1 byte if in [1, 255]
 *   + otherwise 0x00 followed by 2 bytes of length
 * - exponent
 * - modulus
 */
err_t
unpack_RSA_public_key(struct RSA_public_key *rsa, chunk_t *pubkey)
{
    chunk_t exp;
    chunk_t mod;

    rsa->keyid[0] = '\0';	/* in case of keybolbtoid failure */

    if (pubkey->len < 3)
	return "RSA public key blob way to short";	/* not even room for length! */

    if (pubkey->ptr[0] != 0x00)
    {
	setchunk(exp, pubkey->ptr + 1, pubkey->ptr[0]);
    }
    else
    {
	setchunk(exp, pubkey->ptr + 3
	    , (pubkey->ptr[1] << BITS_PER_BYTE) + pubkey->ptr[2]);
    }

    if (pubkey->len - (exp.ptr - pubkey->ptr) < exp.len + RSA_MIN_OCTETS_RFC)
	return "RSA public key blob too short";

    mod.ptr = exp.ptr + exp.len;
    mod.len = &pubkey->ptr[pubkey->len] - mod.ptr;

    if (mod.len < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    if (mod.len > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    n_to_mpz(&rsa->e, exp.ptr, exp.len);
    n_to_mpz(&rsa->n, mod.ptr, mod.len);

    keyblobtoid(pubkey->ptr, pubkey->len, rsa->keyid, sizeof(rsa->keyid));

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(rsa));
#endif


    rsa->k = mpz_sizeinbase(&rsa->n, 2);	/* size in bits, for a start */
    rsa->k = (rsa->k + BITS_PER_BYTE - 1) / BITS_PER_BYTE;	/* now octets */

    if (rsa->k != mod.len)
    {
	mpz_clear(&rsa->e);
	mpz_clear(&rsa->n);
	return "RSA modulus shorter than specified";
    }

    return NULL;
}

bool
same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b)
{
    return a == b
    || (a->k == b->k && mpz_cmp(&a->n, &b->n) == 0 && mpz_cmp(&a->e, &b->e) == 0);
}


static void
install_public_key(struct pubkeyrec *p, struct pubkeyrec **head)
{
    unshare_id_content(&p->id);

    /* store the time the public key was installed */
    time(&p->installed);

    /* install new key at front */
    p->next = *head;
    *head = p;
}


void
delete_public_keys(const struct id *id, enum pubkey_alg alg)
{
    struct pubkeyrec **pp, *p;

    for (pp = &pubkeys; (p = *pp) != NULL; )
    {
	if (same_id(id, &p->id) && p->alg == alg)
	    *pp = free_public_key(p);
	else
	    pp = &p->next;
    }
}

err_t
add_public_key(const struct id *id
, enum dns_auth_level dns_auth_level
, enum pubkey_alg alg
, chunk_t *key
, struct pubkeyrec **head)
{
    struct pubkeyrec *p = alloc_thing(struct pubkeyrec, "pubkeyrec");

    /* first: algorithm-specific decoding of key chunk */
    switch (alg)
    {
    case PUBKEY_ALG_RSA:
	{
	    err_t ugh = unpack_RSA_public_key(&p->u.rsa, key);

	    if (ugh != NULL)
	    {
		pfree(p);
		return ugh;
	    }
	}
	break;
    default:
	impossible();
    }

    p->id = *id;
    p->dns_auth_level = dns_auth_level;
    p->alg = alg;
    p->until = UNDEFINED_TIME;
    install_public_key(p, head);
    return NULL;
}

/*  extract id and public key from x.509 certificate and insert it
 *  into a pubkeyrec
 */
void
add_x509_public_key(const x509cert_t *cert , enum dns_auth_level dns_auth_level)
{
    generalName_t *gn;
    struct pubkeyrec *p;

    /* we support RSA only */
    if (cert->subjectPublicKeyAlgorithm != PUBKEY_ALG_RSA) return;

    /* ID type: ID_DER_ASN1_DN  (X.509 subject field) */
    p = allocate_RSA_public_key(cert);
    p->id.kind = ID_DER_ASN1_DN;
    p->id.name = cert->subject;
    p->dns_auth_level = dns_auth_level;
    p->until = cert->notAfter;
    delete_public_keys(&p->id, p->alg);
    install_public_key(p, &pubkeys);

    gn = cert->subjectAltName;

    while (gn != NULL) /* insert all subjectAltNames */
    {
	struct id id = empty_id;

	gntoid(&id, gn);
	if (id.kind != ID_NONE)
	{
	    p = allocate_RSA_public_key(cert);
	    p->id = id;
	    p->dns_auth_level = dns_auth_level;
	    p->until = cert->notAfter;
	    delete_public_keys(&p->id, p->alg);
	    install_public_key(p, &pubkeys);
	}
	gn = gn->next;
    }
}

/*  when a X.509 certificate gets revoked, all instances of
 *  the corresponding public key must be removed
 */
void
remove_x509_public_key(const x509cert_t *cert)
{
    struct pubkeyrec *p, **pp, *revoked_p;

    revoked_p = allocate_RSA_public_key(cert);
    p         = pubkeys;
    pp        = &pubkeys;

    while(p != NULL)
   {
	if (same_RSA_public_key(&p->u.rsa, &revoked_p->u.rsa))
	{
	    /* remove p from list and free memory */
	    *pp = free_public_key(p);
	    loglog(RC_LOG_SERIOUS,
		"revoked RSA public key deleted");
	}
	else
	{
	    pp = &p->next;
	}
	p =*pp;
    }
    free_public_key(revoked_p);
}

/*
 *  list all public keys in the chained list
 */
void list_public_keys(bool utc)
{
    struct pubkeyrec *p = pubkeys;

    whack_log(RC_COMMENT, " ");
    whack_log(RC_COMMENT, "List of Public Keys:");
    whack_log(RC_COMMENT, " ");

    while (p != NULL)
    {
	if (p->alg == PUBKEY_ALG_RSA)
	{
	    char id_buf[IDTOA_BUF];
	    char expires_buf[TIMETOA_BUF];

	    idtoa(&p->id, id_buf, IDTOA_BUF);
	    strcpy(expires_buf, timetoa(&p->until, utc));

	    whack_log(RC_COMMENT, "%s, %4d RSA Key %s, until %s %s",
		timetoa(&p->installed, utc), 8*p->u.rsa.k, p->u.rsa.keyid,
		expires_buf,
		check_expiry(p->until, PUBKEY_WARNING_INTERVAL, TRUE));
	    whack_log(RC_COMMENT,"       %s '%s'",
		enum_show(&ident_names, p->id.kind), id_buf);
	}
	p = p->next;
    }
}
