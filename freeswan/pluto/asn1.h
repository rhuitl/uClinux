/* Simple ASN.1 parser
 * Copyright (C) 2000-2002 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * RCSID $Id: asn1.h,v 0.1 2002/04/12 00:00:00 as Exp $
 */

/* Defines some primitive ASN1 types */

typedef enum {
    ASN1_EOC =			0x00,
    ASN1_BOOLEAN =		0x01,
    ASN1_INTEGER =		0x02,
    ASN1_BIT_STRING =		0x03,
    ASN1_OCTET_STRING = 	0x04,
    ASN1_NULL = 		0x05,
    ASN1_OID =			0x06,
    ASN1_UTF8STRING =		0x0C,
    ASN1_NUMERICSTRING =	0x12,
    ASN1_PRINTABLESTRING =	0x13,
    ASN1_T61STRING =		0x14,
    ASN1_VIDEOTEXSTRING =	0x15,
    ASN1_IA5STRING =		0x16,
    ASN1_UTCTIME =		0x17,
    ASN1_GENERALIZEDTIME =	0x18,
    ASN1_GRAPHICSTRING =	0x19,
    ASN1_VISIBLESTRING = 	0x1A,
    ASN1_GENERALSTRING =	0x1B,
    ASN1_UNIVERSALSTRING =	0x1C,
    ASN1_BMPSTRING =		0x1E,

    ASN1_CONSTRUCTED =		0x20,

    ASN1_SEQUENCE =		0x30,

    ASN1_SET =			0x31,

    ASN1_CONTEXT_S_0 =		0x80,
    ASN1_CONTEXT_S_1 =		0x81,
    ASN1_CONTEXT_S_2 =		0x82,
    ASN1_CONTEXT_S_3 =		0x83,
    ASN1_CONTEXT_S_4 =		0x84,
    ASN1_CONTEXT_S_5 =		0x85,
    ASN1_CONTEXT_S_6 =		0x86,
    ASN1_CONTEXT_S_7 =		0x87,
    ASN1_CONTEXT_S_8 =		0x88,

    ASN1_CONTEXT_C_0 =		0xA0,
    ASN1_CONTEXT_C_1 =		0xA1,
    ASN1_CONTEXT_C_2 =		0xA2,
    ASN1_CONTEXT_C_3 =		0xA3,
    ASN1_CONTEXT_C_4 =		0xA4,
    ASN1_CONTEXT_C_5 =		0xA5
} asn1_t;

/* Definition of ASN1 flags */

#define ASN1_NONE	0x00
#define ASN1_DEF	0x01
#define ASN1_OPT	0x02
#define ASN1_LOOP	0x04
#define ASN1_END	0x08
#define ASN1_OBJ	0x10
#define ASN1_BODY	0x20

#define ASN1_INVALID_LENGTH     0xffffffff

/* definition of an ASN.1 object */

typedef struct {
    u_int   level;
    u_char  *name;
    asn1_t  type;
    u_char  flags;
} asn1Object_t;

/* defines a node in a the hierarchical OID tree */

typedef struct {
    u_char digit;
    u_int  next;
    u_int  down;
    u_char *name;
} oid_t;

/* Some well known object identifiers (OIDs) */

extern const oid_t oid_names[];

#define OID_SUBJECT_ALT_NAME		19
#define OID_BASIC_CONSTRAINTS		21
#define OID_CRL_DISTRIBUTION_POINTS	23
#define OID_RSA_ENCRYPTION		35
#define OID_MD2_WITH_RSA		36
#define OID_MD5_WITH_RSA		37
#define OID_SHA1_WITH_RSA		38
#define OID_SHA256_WITH_RSA		39
#define OID_SHA384_WITH_RSA		40
#define OID_SHA512_WITH_RSA		41
#define OID_PKCS7_DATA			43
#define OID_PKCS7_SIGNED_DATA		44
#define OID_PKCS9_EMAIL			50
#define OID_MD2				53
#define OID_MD5				54
#define OID_SHA1			70

/* internal context of ASN.1 parser */

#define ASN1_MAX_LEVEL  20

typedef struct {
    bool  implicit;
    u_int cond;
    u_int level0;
    u_int loopAddr[ASN1_MAX_LEVEL+1];
    chunk_t  blobs[ASN1_MAX_LEVEL+2];
} asn1_ctx_t;

extern int known_oid(chunk_t object);
extern u_int asn1_length(chunk_t *blob);
extern bool is_printablestring(chunk_t str);
extern time_t asn1totime(const chunk_t *utctime, asn1_t type);
extern void asn1_init(asn1_ctx_t *ctx, chunk_t blob,
    u_int level0, bool implicit, u_int cond);
extern bool extract_object(asn1Object_t const *objects, 
    u_int *objectID, chunk_t *object, asn1_ctx_t *ctx);
extern bool load_asn1_file(const char* filename, const char* passphrase,
    const char* type, chunk_t *blob);

