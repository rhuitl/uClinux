/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
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
 * RCSID $Id: x509.c,v 1.16 2005-06-08 05:06:38 matthewn Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "x509.h"
#include "preshared.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "whack.h"

/* path definitions for cacerts and crls */

#include <config/autoconf.h>

#ifdef CONFIG_USER_FLATFSD_FLATFSD
#define __IPSEC__PREFIX__ "/etc/config"
#else
#define __IPSEC__PREFIX__ "/etc"
#endif

#define X509_CERT_PATH	__IPSEC__PREFIX__ "/"
#define PGP_CERT_PATH	__IPSEC__PREFIX__ "/pgpcert.pgp"
#define CA_CERT_PATH	__IPSEC__PREFIX__
#define CRL_PATH	__IPSEC__PREFIX__

/* chained lists of host/user and ca certificates and crls */

static x509cert_t *x509certs   = NULL;
static x509cert_t *x509cacerts = NULL;
static x509crl_t  *x509crls    = NULL;

/* contains my X.509 or OpenPGP certificate
 " not used for X.509 certs anymore, backward compatibility only
 */

static cert_t my_default_cert;

/* ASN.1 definition of a basicConstraints extension */

static const asn1Object_t basicConstraintsObjects[] = {
  { 0, "basicConstraints",		ASN1_SEQUENCE,     ASN1_NONE  }, /*  0 */
  { 1,   "CA",				ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /*  1 */
  { 1,   "pathLenConstraint",		ASN1_INTEGER,      ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 1,   "end opt",			ASN1_EOC,          ASN1_END  }, /*  3 */
};

#define BASIC_CONSTRAINTS_CA	1
#define BASIC_CONSTRAINTS_ROOF	4

/* ASN.1 definition of generalNames */

static const asn1Object_t generalNamesObjects[] = {
  { 0, "generalNames",			ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "otherName",			ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_BODY }, /*  1 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  2 */
  { 1,   "rfc822Name",			ASN1_CONTEXT_S_1,  ASN1_OPT |
							   ASN1_BODY }, /*  3 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  4 */
  { 1,   "dnsName",			ASN1_CONTEXT_S_2,  ASN1_OPT |
							   ASN1_BODY }, /*  5 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  6 */
  { 1,   "x400Address",			ASN1_CONTEXT_S_3,  ASN1_OPT |
							   ASN1_BODY }, /*  7 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  8 */
  { 1,   "directoryName",		ASN1_CONTEXT_C_4,  ASN1_OPT |
							   ASN1_BODY }, /*  9 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 10 */
  { 1,   "ediPartyName",		ASN1_CONTEXT_C_5,  ASN1_OPT |
							   ASN1_BODY }, /* 11 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 12 */
  { 1,   "uniformResourceIdentifier",	ASN1_CONTEXT_S_6,  ASN1_OPT |
							   ASN1_BODY }, /* 13 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 14 */
  { 1,   "ipAddress",			ASN1_CONTEXT_S_7,  ASN1_OPT |
							   ASN1_BODY }, /* 15 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 16 */
  { 1,   "registeredID",		ASN1_CONTEXT_S_8,  ASN1_OPT |
							   ASN1_BODY }, /* 17 */
  { 1,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 18 */
  { 0, "end loop",			ASN1_EOC,          ASN1_END  }, /* 19 */
};

#define GN_OBJ_OTHER_NAME	 1
#define GN_OBJ_RFC822_NAME	 3
#define GN_OBJ_DNS_NAME		 5
#define GN_OBJ_X400_ADDRESS	 7
#define GN_OBJ_DIRECTORY_NAME	 9
#define GN_OBJ_EDI_PARTY_NAME	11
#define GN_OBJ_URI		13
#define GN_OBJ_IP_ADDRESS	15
#define GN_OBJ_REGISTERED_ID	17
#define GN_OBJ_ROOF		20

/* ASN.1 definition of crlDistributionPoints */

static const asn1Object_t crlDistributionPointsObjects[] = {
  { 0, "crlDistributionPoints",		ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "DistributionPoint",		ASN1_SEQUENCE,     ASN1_NONE }, /*  1 */
  { 2,     "distributionPoint",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_LOOP }, /*  2 */
  { 3,       "fullName",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_OBJ  }, /*  3 */
  { 3,       "end choice",		ASN1_EOC,          ASN1_END  }, /*  4 */
  { 3,       "nameRelativeToCRLIssuer",	ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_BODY }, /*  5 */
  { 3,       "end choice",		ASN1_EOC,          ASN1_END  }, /*  6 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  7 */
  { 2,     "reasons",			ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_BODY }, /*  8 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  9 */
  { 2,     "crlIssuer",			ASN1_CONTEXT_C_2,  ASN1_OPT |
							   ASN1_BODY }, /* 10 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 11 */
  { 0, "end loop",			ASN1_EOC,          ASN1_END  }, /* 12 */
};

#define CRL_DIST_POINTS_FULLNAME	 3
#define CRL_DIST_POINTS_ROOF		13

/* ASN.1 definition of an X.509v3 certificate */

static const asn1Object_t certObjects[] = {
  { 0, "certificate",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "tbsCertificate",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
  { 2,     "DEFAULT v1",		ASN1_CONTEXT_C_0,  ASN1_DEF  }, /*  2 */
  { 3,       "version",			ASN1_INTEGER,      ASN1_BODY }, /*  3 */
  { 2,     "serialNumber",		ASN1_INTEGER,      ASN1_BODY }, /*  4 */
  { 2,     "signature",			ASN1_SEQUENCE,     ASN1_NONE }, /*  5 */
  { 3,       "sigAlg",			ASN1_OID,          ASN1_BODY }, /*  6 */
  { 2,     "issuer",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  7 */
  { 2,     "validity",			ASN1_SEQUENCE,     ASN1_NONE }, /*  8 */
  { 3,       "notBefore",		ASN1_UTCTIME,      ASN1_BODY }, /*  9 */
  { 3,       "notAfter",		ASN1_UTCTIME,      ASN1_BODY }, /* 10 */
  { 2,     "subject",			ASN1_SEQUENCE,     ASN1_OBJ  }, /* 11 */
  { 2,     "subjectPublicKeyInfo",	ASN1_SEQUENCE,     ASN1_NONE }, /* 12 */
  { 3,       "algorithm",		ASN1_SEQUENCE,     ASN1_NONE }, /* 13 */
  { 4,          "algorithm",		ASN1_OID,          ASN1_BODY }, /* 14 */
  { 3,       "subjectPublicKey",	ASN1_BIT_STRING,   ASN1_NONE }, /* 15 */
  { 4,         "RSAPublicKey",		ASN1_SEQUENCE,     ASN1_NONE }, /* 16 */
  { 5,           "modulus",		ASN1_INTEGER,      ASN1_BODY }, /* 17 */
  { 5,           "publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /* 18 */
  { 2,     "issuerUniqueID",		ASN1_CONTEXT_C_1,  ASN1_OPT  }, /* 19 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 20 */
  { 2,     "subjectUniqueID",		ASN1_CONTEXT_C_2,  ASN1_OPT  }, /* 21 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 22 */
  { 2,     "optional extensions",	ASN1_CONTEXT_C_3,  ASN1_OPT  }, /* 23 */
  { 3,       "extensions",		ASN1_SEQUENCE,     ASN1_LOOP }, /* 24 */
  { 4,         "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 25 */
  { 5,           "extnID",		ASN1_OID,          ASN1_BODY }, /* 26 */
  { 5,           "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 27 */
  { 5,           "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 28 */
  { 3,       "end loop",		ASN1_EOC,          ASN1_END  }, /* 29 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 30 */
  { 1,   "signatureAlgorithm",		ASN1_SEQUENCE,     ASN1_NONE }, /* 31 */
  { 2,     "algorithm",			ASN1_OID,          ASN1_BODY }, /* 32 */
  { 1,   "signature",			ASN1_BIT_STRING,   ASN1_BODY }  /* 33 */
};

#define X509_OBJ_CERTIFICATE			 0
#define X509_OBJ_TBS_CERTIFICATE		 1
#define X509_OBJ_VERSION			 3
#define X509_OBJ_SERIAL_NUMBER			 4
#define X509_OBJ_SIG_ALG			 6
#define X509_OBJ_ISSUER 			 7
#define X509_OBJ_NOT_BEFORE			 9
#define X509_OBJ_NOT_AFTER			10
#define X509_OBJ_SUBJECT			11
#define X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM	14
#define X509_OBJ_SUBJECT_PUBLIC_KEY		15
#define X509_OBJ_MODULUS			17
#define X509_OBJ_PUBLIC_EXPONENT		18
#define X509_OBJ_EXTN_ID			26
#define X509_OBJ_CRITICAL			27
#define X509_OBJ_EXTN_VALUE			28
#define X509_OBJ_ALGORITHM			32
#define X509_OBJ_SIGNATURE			33
#define X509_OBJ_ROOF				34


/* ASN.1 definition of an X.509 certificate list */

static const asn1Object_t crlObjects[] = {
  { 0, "certificateList",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "tbsCertList",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
  { 2,     "version",			ASN1_INTEGER,      ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  3 */
  { 2,     "signature",			ASN1_SEQUENCE,     ASN1_NONE }, /*  4 */
  { 3,       "sigAlg",			ASN1_OID,          ASN1_BODY }, /*  5 */
  { 2,     "issuer",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  6 */
  { 2,     "thisUpdate",		ASN1_UTCTIME,      ASN1_BODY }, /*  7 */
  { 2,     "nextUpdate",		ASN1_UTCTIME,      ASN1_OPT |
							   ASN1_BODY }, /*  8 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  9 */
  { 2,     "revokedCertificates",	ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /* 10 */
  { 3,       "certList",		ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
  { 4,         "userCertificate",	ASN1_INTEGER,      ASN1_BODY }, /* 12 */
  { 4,         "revocationDate",	ASN1_UTCTIME,      ASN1_BODY }, /* 13 */
  { 4,         "crlEntryExtensions",	ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /* 14 */
  { 5,           "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 15 */
  { 6,             "extnID",		ASN1_OID,          ASN1_BODY }, /* 16 */
  { 6,             "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 17 */
  { 6,             "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 18 */
  { 4,         "end opt or loop",	ASN1_EOC,          ASN1_END  }, /* 19 */
  { 2,     "end opt or loop",		ASN1_EOC,          ASN1_END  }, /* 20 */
  { 2,     "optional extensions",	ASN1_CONTEXT_C_0,  ASN1_OPT  }, /* 21 */
  { 3,       "crlExtensions",		ASN1_SEQUENCE,     ASN1_LOOP }, /* 22 */
  { 4,         "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 23 */
  { 5,           "extnID",		ASN1_OID,          ASN1_BODY }, /* 24 */
  { 5,           "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 25 */
  { 3,       "end loop",		ASN1_EOC,          ASN1_END  }, /* 26 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 27 */
  { 1,   "signatureAlgorithm",		ASN1_SEQUENCE,     ASN1_NONE }, /* 28 */
  { 2,     "algorithm",			ASN1_OID,          ASN1_BODY }, /* 29 */
  { 1,   "signature",			ASN1_BIT_STRING,   ASN1_BODY }  /* 30 */
 };

#define CRL_OBJ_CERTIFICATE_LIST		 0
#define CRL_OBJ_TBS_CERT_LIST			 1
#define CRL_OBJ_VERSION				 2
#define CRL_OBJ_SIG_ALG				 5
#define CRL_OBJ_ISSUER				 6
#define CRL_OBJ_THIS_UPDATE			 7
#define CRL_OBJ_NEXT_UPDATE			 8
#define CRL_OBJ_USER_CERTIFICATE		12
#define CRL_OBJ_REVOCATION_DATE			13
#define CRL_OBJ_CRITICAL			17
#define CRL_OBJ_ALGORITHM			29
#define CRL_OBJ_SIGNATURE			30
#define CRL_OBJ_ROOF				31


const x509cert_t empty_x509cert = {
      NULL     , /* *next */
            0  , /* installed */
            0  , /* count */
    { NULL, 0 }, /* certificate */
    { NULL, 0 }, /*   tbsCertificate */
            1  , /*     version */
    { NULL, 0 }, /*     serialNumber */
                 /*     signature */
    { NULL, 0 }, /*       sigAlg */
    { NULL, 0 }, /*     issuer */
                 /*     validity */
            0  , /*       notBefore */
            0  , /*       notAfter */
    { NULL, 0 }, /*     subject */
                 /*     subjectPublicKeyInfo */
            0  , /*       subjectPublicKeyAlgorithm */
                 /*     subjectPublicKey */
    { NULL, 0 }, /*       modulus */
    { NULL, 0 }, /*       publicExponent */
    { NULL, 0 }, /*     issuerUniqueID */
    { NULL, 0 }, /*     subjectUniqueID */
                 /*     extensions */
                 /*       extension */
                 /*         extnID */
                 /*         critical */
                 /*         extnValue */
      FALSE    , /*           isCA */
      NULL     , /*           subjectAltName */
      NULL     , /*           crlDistributionPoints */
                 /*   signatureAlgorithm */
    { NULL, 0 }, /*     algorithm */
    { NULL, 0 }  /*   signature */
};

const x509crl_t empty_x509crl = {
      NULL     , /* *next */
            0  , /* installed */
    { NULL, 0 }, /* certificateList */
    { NULL, 0 }, /*   tbsCertList */
            1  , /*     version */
    { NULL, 0 }, /*     sigAlg */
    { NULL, 0 }, /*     issuer */
            0  , /*     thisUpdate */
            0  , /*     nextUpdate */
      NULL     , /*     revokedCertificates */
		 /*     crlExtensions*/
   		 /*   signatureAlgorithm*/
    { NULL, 0 }, /*     algorithm*/
    { NULL, 0 }  /*   signature*/
};


/* coding of X.501 distinguished name */

typedef struct {
    u_char *name;
    chunk_t oid;
    u_char type;
} x501rdn_t;


/* X.501 acronyms for well known object identifiers (OIDs) */

static const u_char oid_CN[] = {0x55, 0x04, 0x03};
static const u_char oid_S[]  = {0x55, 0x04, 0x04};
static const u_char oid_SN[] = {0x55, 0x04, 0x05};
static const u_char oid_C[]  = {0x55, 0x04, 0x06};
static const u_char oid_L[]  = {0x55, 0x04, 0x07};
static const u_char oid_ST[] = {0x55, 0x04, 0x08};
static const u_char oid_O[]  = {0x55, 0x04, 0x0A};
static const u_char oid_OU[] = {0x55, 0x04, 0x0B};
static const u_char oid_T[]  = {0x55, 0x04, 0x0C};
static const u_char oid_D[]  = {0x55, 0x04, 0x0D};
static const u_char oid_N[]  = {0x55, 0x04, 0x29};
static const u_char oid_G[]  = {0x55, 0x04, 0x2A};
static const u_char oid_I[]  = {0x55, 0x04, 0x2B};
static const u_char oid_E[]  = {0x2A, 0x86, 0x48, 0x86, 0xF7,
                                      0x0D, 0x01, 0x09, 0x01};
static const u_char oid_TCGID[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x89,
                                   0x31, 0x01, 0x01, 0x02, 0x02, 0x4B};

static const x501rdn_t x501rdns[] = {
  {"CN"    , {oid_CN,     3}, ASN1_PRINTABLESTRING},
  {"S"     , {oid_S,      3}, ASN1_PRINTABLESTRING},
  {"SN"    , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"C"     , {oid_C,      3}, ASN1_PRINTABLESTRING},
  {"L"     , {oid_L,      3}, ASN1_PRINTABLESTRING},
  {"ST"    , {oid_ST,     3}, ASN1_PRINTABLESTRING},
  {"O"     , {oid_O,      3}, ASN1_PRINTABLESTRING},
  {"OU"    , {oid_OU,     3}, ASN1_PRINTABLESTRING},
  {"T"     , {oid_T,      3}, ASN1_PRINTABLESTRING},
  {"D"     , {oid_D,      3}, ASN1_PRINTABLESTRING},
  {"N"     , {oid_N,      3}, ASN1_PRINTABLESTRING},
  {"G"     , {oid_G,      3}, ASN1_PRINTABLESTRING},
  {"I"     , {oid_I,      3}, ASN1_PRINTABLESTRING},
  {"E"     , {oid_E,      9}, ASN1_IA5STRING},
  {"Email" , {oid_E,      9}, ASN1_IA5STRING},
  {"emailAddress" , {oid_E,      9}, ASN1_IA5STRING},
  {"TCGID" , {oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};

#define X501_RDN_ROOF   16

/* Maximum length of ASN.1 distinquished name */

#define BUF_LEN	      512

static void
code_asn1_length(u_int length, chunk_t *code)
{
    if (length < 128)
    {
	code->ptr[0] = length;
	code->len = 1;
    }
    else if (length < 256)
    {
	code->ptr[0] = 0x81;
	code->ptr[1] = length;
	code->len = 2;
    }
    else
    {
	code->ptr[0] = 0x82;
	code->ptr[1] = length >> 8;
	code->ptr[2] = length & 0xff;
	code->len = 3;
    }
}


static void
update_chunk(chunk_t *ch, int n)
{
    n = (n > -1 && n < ch->len)? n : ch->len-1;
    ch->ptr += n; ch->len -= n;
}


/*
 *  Pointer is set to the first RDN in a DN
 */
static err_t
init_rdn(chunk_t dn, chunk_t *rdn)
{
    *rdn = empty_chunk;

    /* a DN is a SEQUENCE OF RDNs */

    if (*dn.ptr != ASN1_SEQUENCE)
    {
	return "DN is not a SEQUENCE";
    }

    rdn->len = asn1_length(&dn);
    rdn->ptr = dn.ptr;

    return NULL;
}

/*
 *  Fetches the next RDN in a DN
 */
static err_t
get_next_rdn(chunk_t *rdn, chunk_t *oid, chunk_t *value, asn1_t *type)
{
    chunk_t attribute;

    /* initialize return values */
    *oid   = empty_chunk;
    *value = empty_chunk;

    /* an RDN is a SET OF attributeTypeAndValue */
    if (*rdn->ptr != ASN1_SET)
	return "RDN is not a SET";

    attribute.len = asn1_length(rdn);
    attribute.ptr = rdn->ptr;

    /* advance to start of next RDN */
    rdn->ptr += attribute.len;
    rdn->len -= attribute.len;

    /* an attributeTypeAndValue is a SEQUENCE */
    if (*attribute.ptr != ASN1_SEQUENCE)
 	return "attributeTypeAndValue is not a SEQUENCE";

    /* extract the attribute body */
    attribute.len = asn1_length(&attribute);

    /* attribute type is an OID */
    if (*attribute.ptr != ASN1_OID)
	return "attributeType is not an OID";

    /* extract OID */
    oid->len = asn1_length(&attribute);
    oid->ptr = attribute.ptr;

    /* advance to the attribute value */
    attribute.ptr += oid->len;
    attribute.len -= oid->len;

    /* extract string type */
    *type = *attribute.ptr;

    /* extract string value */
    value->len = asn1_length(&attribute);
    value->ptr = attribute.ptr;

    return NULL;
}

/*
 *  Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t
dn_parse(chunk_t dn, chunk_t *str)
{
    chunk_t rdn, oid, value;
    asn1_t type;
    int oid_code;
    int first = TRUE;

    err_t ugh = init_rdn(dn, &rdn);

    if (ugh != NULL) /* a parsing error has occured */
        return ugh;

    while (rdn.len > 0)
    {
	ugh = get_next_rdn(&rdn, &oid, &value, &type);

	if (ugh != NULL) /* a parsing error has occured */
	    return ugh;

	if (first)		/* first OID/value pair */
	    first = FALSE;
	else			/* separate OID/value pair by a comma */
	    update_chunk(str, snprintf(str->ptr,str->len,", "));

	/* print OID */
	oid_code = known_oid(oid);
	if (oid_code == -1)	/* OID not found in list */
	    hex_str(oid, str);
	else
	    update_chunk(str, snprintf(str->ptr,str->len,"%s",
			      oid_names[oid_code].name));

	/* print value */
	update_chunk(str, snprintf(str->ptr,str->len,"=%.*s",
			      (int)value.len,value.ptr));
    }
    return NULL;
}

/*
 * Prints a binary string in hexadecimal form
 */
void
hex_str(chunk_t bin, chunk_t *str)
{
    u_int i;
    update_chunk(str, snprintf(str->ptr,str->len,"0x"));
    for (i=0; i < bin.len; i++)
	update_chunk(str, snprintf(str->ptr,str->len,"%02X",*bin.ptr++));
}


/*  Converts a binary DER-encoded ASN.1 distinguished name
 *  into LDAP-style human-readable ASCII format
 */
int
dntoa(char *dst, size_t dstlen, chunk_t dn)
{
    err_t ugh = NULL;
    chunk_t str;

    str.ptr = dst;
    str.len = dstlen;
    ugh = dn_parse(dn, &str);

    if (ugh != NULL) /* error, print DN as hex string */
    {
	DBG(DBG_PARSING,
	    DBG_log("error in DN parsing: %s", ugh)
	)
	str.ptr = dst;
	str.len = dstlen;
	hex_str(dn, &str);
    }
    return (int)(dstlen - str.len);
}

/*  Converts an LDAP-style human-readable ASCII-encoded
 *  ASN.1 distinguished name into binary DER-encoded format
 */
err_t
atodn(char *src, chunk_t *dn)
{
  /* finite state machine for atodn */

    typedef enum {
	SEARCH_OID =	0,
	READ_OID =	1,
	SEARCH_NAME =	2,
	READ_NAME =	3,
        UNKNOWN_OID =	4
    } state_t;

    u_char oid_len_buf[3];
    u_char name_len_buf[3];
    u_char rdn_seq_len_buf[3];
    u_char rdn_set_len_buf[3];
    u_char dn_seq_len_buf[3];

    chunk_t asn1_oid_len     = { oid_len_buf,     0 };
    chunk_t asn1_name_len    = { name_len_buf,    0 };
    chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
    chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
    chunk_t asn1_dn_seq_len  = { dn_seq_len_buf,  0 };
    chunk_t oid  = empty_chunk;
    chunk_t name = empty_chunk;

    int whitespace  = 0;
    int rdn_seq_len = 0;
    int rdn_set_len = 0;
    int dn_seq_len  = 0;
    int pos         = 0;

    err_t ugh = NULL;

    u_char *dn_ptr = dn->ptr + 4;

    state_t state = SEARCH_OID;

    do
    {
        switch (state)
	{
	case SEARCH_OID:
	    if (*src != ' ' && *src != '/' && *src !=  ',')
	    {
		oid.ptr = src;
		oid.len = 1;
		state = READ_OID;
	    }
	    break;
	case READ_OID:
	    if (*src != ' ' && *src != '=')
		oid.len++;
	    else
	    {
		for (pos = 0; pos < X501_RDN_ROOF; pos++)
		{
		    if (strlen(x501rdns[pos].name) == oid.len &&
			strncasecmp(x501rdns[pos].name, oid.ptr, oid.len) == 0)
			break; /* found a valid OID */
		}
		if (pos == X501_RDN_ROOF)
		{
		    ugh = "unknown OID in ID_DER_ASN1_DN";
		    state = UNKNOWN_OID;
		    break;
		}
		code_asn1_length(x501rdns[pos].oid.len, &asn1_oid_len);

		/* reset oid and change state */
		oid = empty_chunk;
		state = SEARCH_NAME;
	    }
	    break;
	case SEARCH_NAME:
	    if (*src != ' ' && *src != '=')
	    {
		name.ptr = src;
		name.len = 1;
		whitespace = 0;
		state = READ_NAME;
	    }
	    break;
	case READ_NAME:
	    if (*src != ',' && *src != '/' && *src != '\0')
	    {
		name.len++;
		if (*src == ' ')
		    whitespace++;
		else
		    whitespace = 0;
	    }
	    else
	    {
		name.len -= whitespace;
		code_asn1_length(name.len, &asn1_name_len);

		/* compute the length of the relative distinguished name sequence */
		rdn_seq_len = 1 + asn1_oid_len.len + x501rdns[pos].oid.len +
			      1 + asn1_name_len.len + name.len;
		code_asn1_length(rdn_seq_len, &asn1_rdn_seq_len);

		/* compute the length of the relative distinguished name set */
		rdn_set_len = 1 + asn1_rdn_seq_len.len + rdn_seq_len;
		code_asn1_length(rdn_set_len, &asn1_rdn_set_len);

		/* encode the relative distinguished name */
		*dn_ptr++ = ASN1_SET;
		chunkcpy(dn_ptr, asn1_rdn_set_len);
		*dn_ptr++ = ASN1_SEQUENCE;
		chunkcpy(dn_ptr, asn1_rdn_seq_len);
		*dn_ptr++ = ASN1_OID;
		chunkcpy(dn_ptr, asn1_oid_len);
		chunkcpy(dn_ptr, x501rdns[pos].oid);
		/* encode the ASN.1 character string type of the name */
		*dn_ptr++ = (x501rdns[pos].type == ASN1_PRINTABLESTRING
		    && !is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
		chunkcpy(dn_ptr, asn1_name_len);
		chunkcpy(dn_ptr, name);

		/* accumulate the length of the distinguished name sequence */
		dn_seq_len += 1 + asn1_rdn_set_len.len + rdn_set_len;

		/* reset name and change state */
		name = empty_chunk;
		state = SEARCH_OID;
	    }
	    break;
	case UNKNOWN_OID:
	    break;
	}
    } while (*src++ != '\0');

    /* complete the distinguished name sequence*/
    code_asn1_length(dn_seq_len, &asn1_dn_seq_len);
    dn->ptr += 3 - asn1_dn_seq_len.len;
    dn->len =  1 + asn1_dn_seq_len.len + dn_seq_len;
    dn_ptr = dn->ptr;
    *dn_ptr++ = ASN1_SEQUENCE;
    chunkcpy(dn_ptr, asn1_dn_seq_len);
    return ugh;
}

/*  compare two distinguished names by
 *  comparing the individual RDNs
 */
bool
same_dn(chunk_t a, chunk_t b)
{
    chunk_t rdn_a,   rdn_b;
    chunk_t oid_a,   oid_b;
    chunk_t value_a, value_b;
    asn1_t  type_a,  type_b;

    /* same lengths for the DNs */
    if (a.len != b.len)
	return FALSE;

    /* initialize DN parsing */
    if (init_rdn(a, &rdn_a) != NULL || init_rdn(b, &rdn_b) != NULL)
    	return FALSE;

    /* fetch next RDN pair */
    while (rdn_a.len > 0 && rdn_b.len > 0)
    {
	/* parse next RDNs and check for errors */
	if (get_next_rdn(&rdn_a, &oid_a, &value_a, &type_a) != NULL ||
	    get_next_rdn(&rdn_b, &oid_b, &value_b, &type_b) != NULL)
	{
	    return FALSE;
	}

	/* OIDs must agree */
	if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
	    return FALSE;

	/* same lengths for values */
	if (value_a.len != value_b.len)
	    return FALSE;

	/* printableStrings and email RDNs require uppercase comparison */
	if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
	   (type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
	{
	    if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
		return FALSE;
	}
	else
	{
	    if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
		return FALSE;
	}
    }
    /* both DNs must have same number of RDNs */
    if (rdn_a.len != 0 || rdn_b.len != 0)
	return FALSE;

    /* the two DNs are equal! */
    return TRUE;
}

/*
 *  compare two certificates by comparing their signatures
 */
static bool
same_cert(x509cert_t *a, x509cert_t *b)
{
    return a->signature.len == b->signature.len &&
	memcmp(a->signature.ptr, b->signature.ptr, b->signature.len) == 0;
}

/*  for each link pointing to the certificate
 "  increase the count by one
 */
void
share_x509cert(x509cert_t *cert)
{
    if (cert != NULL)
 	cert->count++;
}

/*
 *  add a X.509 user/host certificate to the chained list
 */
x509cert_t*
add_x509cert(x509cert_t *cert)
{
    x509cert_t *c = x509certs;

    while (c != NULL)
    {
	if (same_cert(c, cert)) /* already in chain, free cert */
	{
	    free_x509cert(cert);
	    return c;
	}
	c = c->next;
    }

    /* insert new cert at the root of the chain */
    cert->next = x509certs;
    x509certs = cert;
    return cert;
}

/*
 *  get the X.509 CA certificate with a given subject
 */
static x509cert_t*
get_x509cacert(chunk_t subject)
{
    x509cert_t *cert = x509cacerts;
    x509cert_t *prev_cert = NULL;

    while(cert != NULL)
   {
	if (same_dn(cert->subject, subject))
	{
	    if (cert != x509cacerts)
	    {
		/* bring the certificate up front */
		prev_cert->next = cert->next;
		cert->next = x509cacerts;
		x509cacerts = cert;
	    }
	    return cert;
	}
	prev_cert = cert;
	cert = cert->next;
    }
    return NULL;
}

/*
 *  get the X.509 CRL with a given issuer
 */
static x509crl_t*
get_x509crl(chunk_t issuer)
{
    x509crl_t *crl = x509crls;
    x509crl_t *prev_crl = NULL;

    while(crl != NULL)
   {
	if (same_dn(crl->issuer, issuer))
	{
	    if (crl != x509crls)
	    {
		/* bring the CRL up front */
		prev_crl->next = crl->next;
		crl->next = x509crls;
		x509crls = crl;
	    }
	    return crl;
	}
	prev_crl = crl;
	crl = crl->next;
    }
    return NULL;
}

/*  Send my certificate either defined and loaded via
 *  /etc/ipsec.conf or by default loaded from /etc/x509cert.der
 *  (deprecated for X.509 certificates)
 */
bool
get_mycert(cert_t *mycert, x509cert_t *cert)
{
    *mycert = my_default_cert;

    if (cert != NULL)
    {
	mycert->type = CERT_X509_SIGNATURE;
	mycert->cert = cert->certificate;
    }
    return mycert->type != CERT_NONE;
}

/*
 *  free the dynamic memory used to store generalNames
 */
void
free_generalNames(generalName_t* gn)
{
    while (gn != NULL)
    {
	generalName_t *gn_top = gn;
	gn = gn->next;
	pfree(gn_top);
    }
}

/*
 *  free a X.509 certificate
 */
void
free_x509cert(x509cert_t *cert)
{
    if (cert != NULL)
    {
	free_generalNames(cert->subjectAltName);
	free_generalNames(cert->crlDistributionPoints);
	if (cert->certificate.ptr != NULL)
	    pfree(cert->certificate.ptr);
	pfree(cert);
	cert = NULL;
    }
}

/*  release of a certificate decreases the count by one
 "  the certificate is freed when the counter reaches zero
 */
void
release_x509cert(x509cert_t *cert)
{
    if (cert != NULL && --cert->count == 0)
    {
	x509cert_t **pp = &x509certs;
	while (*pp != cert)
	    pp = &(*pp)->next;
        *pp = cert->next;
	free_x509cert(cert);
    }
}

/*
 *  free the first CA certificate in the chain
 */
static void
free_first_cacert(void)
{
    x509cert_t *first = x509cacerts;
    x509cacerts = first->next;
    free_x509cert(first);
}

/*
 *  free  all CA certificates
 */
void
free_cacerts(void)
{
    while (x509cacerts != NULL)
        free_first_cacert();
}

/*
 *  free the dynamic memory used to store revoked certificates
 */
static void
free_revoked_certs(revokedCert_t* revokedCerts)
{
    while (revokedCerts != NULL)
    {
	revokedCert_t * revokedCert = revokedCerts;
	revokedCerts = revokedCert->next;
	pfree(revokedCert);
    }
}

/*
 *  free the dynamic memory used to store CRLs
 */
static void
free_first_crl(void)
{
    x509crl_t * crl = x509crls;
    x509crls = crl->next;
    free_revoked_certs(crl->revokedCertificates);
    pfree(crl->certificateList.ptr);
    pfree(crl);
}

void
free_crls(void)
{
    while (x509crls != NULL)
	free_first_crl();
}

/*
 *  free the dynamic memory used to store my X.509 or OpenPGP certificate
 */
void
free_mycert(void)
{
    freeanychunk(my_default_cert.cert);
}

/*
 *  Filter eliminating the directory entries '.' and '..'
 */
static int
file_select(const struct dirent *entry)
{
    return strcmp(entry->d_name, "." ) &&
	   strcmp(entry->d_name, "..");
}

/*
 * stores a chained list of user/host and CA certs
 */
void
store_x509certs(x509cert_t **firstcert)
{
    x509cert_t **pp = firstcert;

    /* first store CA certs */

    while (*pp != NULL)
    {
	x509cert_t *cert = *pp;

	if (cert->isCA)
	{
	    /* we don't accept self-signed CA certs */
	    if (same_dn(cert->issuer, cert->subject))
	    {
		log("self-signed cacert rejected");
	        *pp = cert->next;
		free_x509cert(cert);
	    }
	    else
	    {
		if (get_x509cacert(cert->subject))
		{
		    free_first_cacert();
		    DBG(DBG_PARSING,
			DBG_log("existing cacert deleted")
		    )
		}
		share_x509cert(cert);  /* set count to one */

		/* insert into chained cacert list*/
	        *pp = cert->next;
		cert->next = x509cacerts;
		x509cacerts = cert;
		DBG(DBG_PARSING,
		    DBG_log("cacert inserted")
		)
	    }
	}
	else
	    pp = &cert->next;
    }

    /* now verify user/host certificates */

    pp = firstcert;

    while (*pp != NULL)
    {
	x509cert_t *cert = *pp;

	if (verify_x509cert(cert))
	{
	    DBG(DBG_PARSING,
		DBG_log("Public key validated")
	    )
	    add_x509_public_key(cert, DAL_SIGNED);
	}
	else
	{
	    log("X.509 certificate rejected");
	}
	*pp = cert->next;
	free_x509cert(cert);
    }
}

/*
 *  Loads a X.509 certificate
 */
x509cert_t*
load_x509cert(const char* filename, const char* label)
{
    chunk_t blob = empty_chunk;
    if (load_asn1_file(filename, "", label, &blob))
    {
	x509cert_t *cert = alloc_thing(x509cert_t, "x509cert");
	*cert = empty_x509cert;
	if (parse_x509cert(blob, 0, cert)) {
	    log("  X.509 loaded: %s", filename);
	    return cert;
	} else
	{
	    log("  error in X.509 certificate: %s", filename);
	    free_x509cert(cert);
	}
    }
    return NULL;
}

/*
 *  Loads a host certificate
 */
x509cert_t*
load_host_cert(const char* filename)
{
    char path[BUF_LEN];

    if (*filename == '/')	/* absolute pathname */
    	strncpy(path, filename, BUF_LEN);
    else			/* relative pathname */
	snprintf(path, BUF_LEN, "%s/%s", HOST_CERT_PATH, filename);

    return load_x509cert(path, "host cert");
}

/*
 *  Loads CA certificates
 */
void
load_cacerts(void)
{
    struct dirent **filelist;
    u_char buf[BUF_LEN];
    u_char *save_dir;
    int n;

    /* change directory to specified path */
    save_dir = getcwd(buf, BUF_LEN);
    if (chdir(CA_CERT_PATH))
    {
	log("Could not change to directory '%s'", CA_CERT_PATH);
    }
    else
    {
	log("Changing to directory '%s'",CA_CERT_PATH);
	n = scandir(CA_CERT_PATH, &filelist, file_select, alphasort);

	if (n <= 0)
	    log("  Warning: empty directory");
	else
	{
	    while (n--)
	    {
		x509cert_t *cacert = load_x509cert(filelist[n]->d_name, "cacert");
		if (cacert != NULL)
		{
		    if (get_x509cacert(cacert->subject))
		    {
			free_first_cacert();
			DBG(DBG_PARSING,
			    DBG_log("  existing cacert deleted")
			)
		    }
		    share_x509cert(cacert);  /* set count to one */
		    cacert->next = x509cacerts;
		    x509cacerts = cacert;
		}
		free(filelist[n]);
	    }
	    free(filelist);
	}
    }
    /* restore directory path */
    chdir(save_dir);
}

/*
 *  Loads CRLs
 */
void
load_crls(void)
{
    struct dirent **filelist;
    u_char buf[BUF_LEN];
    u_char *save_dir;
    int n;

    /* change directory to specified path */
    save_dir = getcwd(buf, BUF_LEN);
    if (chdir(CRL_PATH))
    {
	log("Could not change to directory '%s'", CRL_PATH);
    }
    else
    {
//	log("Changing to directory '%s'", CRL_PATH);
	n = scandir(CRL_PATH, &filelist, file_select, alphasort);

	if (n <= 0)
	    log("  Warning: empty directory");
	else
	{
	    while (n--)
	    {
		chunk_t blob = empty_chunk;
		if (load_asn1_file(filelist[n]->d_name, "", "crl", &blob))
		{
		    x509crl_t *crl = alloc_thing(x509crl_t, "x509crl");
		    *crl = empty_x509crl;
		    if (parse_x509crl(blob, 0, crl))
		    {
			if (get_x509crl(crl->issuer))
			{
			    free_first_crl();
			    DBG(DBG_PARSING,
				DBG_log("  existing CRL deleted")
			    )
			}
			log("  X.509 CRL loaded: %s",filelist[n]->d_name);
			crl->next = x509crls;
			x509crls = crl;
		    }
		    else
		    {
			log("  error in X.509 CRL: %s",filelist[n]->d_name);
			free_revoked_certs(crl->revokedCertificates);
			pfree(blob.ptr);
			pfree(crl);
		    }
		}
		else
		free(filelist[n]);
	    }
	    free(filelist);
	}
    }
    /* restore directory path */
    chdir(save_dir);
}

/*  Loads the X.509 or OpenPGP certificate sent by FreeS/WAN to
 *  its peers during ISAKMP Phase 1
 */
void
load_mycert(void)
{
    x509cert_t *myX509cert = NULL;

    /* deleting old certificate, if present */
    pfreeany(my_default_cert.cert.ptr);

    /* initializing certificate */
    my_default_cert.type = CERT_NONE;
    my_default_cert.cert = empty_chunk;

    /* loading a default X.509 certificate, if available */
    myX509cert = load_x509cert(X509_CERT_PATH, "my default X.509 cert");

    if (myX509cert != NULL)
    {
	my_default_cert.type = CERT_X509_SIGNATURE;
	my_default_cert.cert = myX509cert->certificate;
	myX509cert->certificate = empty_chunk;
	free_x509cert(myX509cert);
    }
    else
    {
	/* loading an OpenPGP certificate, if available */
	FILE *fd = NULL;
	int i;

	fd = fopen(PGP_CERT_PATH, "r");
	if (fd)
	{
	    my_default_cert.type = CERT_PGP;
	    fseek(fd, 0, SEEK_END );
	    my_default_cert.cert.len = ftell(fd);
	    rewind(fd);
	    my_default_cert.cert.ptr = alloc_bytes(my_default_cert.cert.len, "cert");
	    i = fread(my_default_cert.cert.ptr, 1, my_default_cert.cert.len, fd);
	    fclose(fd);
	    log("Loaded my OpenPGP certificate file '%s' (%d bytes)",
		PGP_CERT_PATH, i);
	}
	else
	{
//	    log("OpenPGP certificate file '%s' not found", PGP_CERT_PATH);
	}
    }
}

/*
 * extracts the basicConstraints extension
 */
static bool
parse_basicConstraints(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    int objectID = 0;
    bool isCA = FALSE;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < BASIC_CONSTRAINTS_ROOF) {

	if (!extract_object(basicConstraintsObjects, &objectID,
			    &object, &ctx))
	     break;

	if (objectID == BASIC_CONSTRAINTS_CA)
	{
	    isCA = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(isCA)?"TRUE":"FALSE");
	    )
	}
	objectID++;
    }
    return isCA;
}

/*
 *  Converts a X.500 generalName into an ID
 */
void
gntoid(struct id *id, const generalName_t *gn)
{
    switch(gn->kind)
    {
    case GN_DNS_NAME:		/* ID type: ID_FQDN */
	id->kind = ID_FQDN;
	id->name = gn->name;
	break;
    case GN_IP_ADDRESS:		/* ID type: ID_IPV4_ADDR */
	{
	    const struct af_info *afi = &af_inet4_info;
	    err_t ugh = NULL;

	    id->kind = afi->id_addr;
	    ugh = initaddr(gn->name.ptr, gn->name.len, afi->af, &id->ip_addr);
	}
	break;
    case GN_RFC822_NAME:	/* ID type: ID_USER_FQDN */
	id->kind = ID_USER_FQDN;
	id->name = gn->name;
	break;
    default:
	id->kind = ID_NONE;
	id->name = empty_chunk;
	break;
    }
}

/*
 * extracts one or several GNs and puts them into a chained list
 */
static generalName_t*
parse_generalNames(chunk_t blob, int level0, bool implicit)
{
    u_char buf[BUF_LEN];
    asn1_ctx_t ctx;
    chunk_t object;
    int objectID = 0;
   
    generalName_t *top_gn = NULL;

    asn1_init(&ctx, blob, level0, implicit, DBG_RAW);
 
    while (objectID < GN_OBJ_ROOF) {
	bool valid_gn = FALSE;

	if (!extract_object(generalNamesObjects, &objectID, &object, &ctx))
	     return NULL;

	switch (objectID) {
	case GN_OBJ_RFC822_NAME:
	case GN_OBJ_DNS_NAME:
	case GN_OBJ_URI:
	    DBG(DBG_PARSING,
		DBG_log("  '%.*s'", (int)object.len, object.ptr);
	    )
	    valid_gn = TRUE;
	    break;
	case GN_OBJ_DIRECTORY_NAME:
	    dntoa(buf, BUF_LEN, object);
	    DBG(DBG_PARSING,
		DBG_log("  '%s'", buf);
	    )
	    valid_gn = TRUE;
	    break;
	case GN_OBJ_IP_ADDRESS:
	    DBG(DBG_PARSING,
		DBG_log("  '%d.%d.%d.%d'", *object.ptr, *(object.ptr+1),
				      *(object.ptr+2), *(object.ptr+3));
	    )
	    valid_gn = TRUE;
	    break;
	case GN_OBJ_OTHER_NAME:
	case GN_OBJ_X400_ADDRESS:
	case GN_OBJ_EDI_PARTY_NAME:
	case GN_OBJ_REGISTERED_ID:
	    break;
	default:
	    break;
	}

	if (valid_gn)
	{
	    generalName_t *gn = alloc_thing(generalName_t, "generalName");
	    gn->kind = (objectID - GN_OBJ_OTHER_NAME) / 2;
	    gn->name = object;
	    gn->next = top_gn;
	    top_gn = gn;
	}
	objectID++;
    }
    return top_gn;
}

/*  extracts one or several crlDistributionPoints and puts them into
 *  a chained list
 */
static generalName_t*
parse_crlDistributionPoints(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    int objectID = 0;

    generalName_t *top_gn = NULL;      /* top of the chained list */
    generalName_t **tail_gn = &top_gn; /* tail of the chained list */

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < CRL_DIST_POINTS_ROOF) {

	if (!extract_object(crlDistributionPointsObjects, &objectID,
			    &object, &ctx))
	     return NULL;

	if (objectID == CRL_DIST_POINTS_FULLNAME)
	{
	    u_int level = crlDistributionPointsObjects[objectID].level + level0;
	    generalName_t *gn = parse_generalNames(object, level, TRUE);
	    /* append extracted generalNames to existing chained list */
	    *tail_gn = gn;
	    /* find new tail of the chained list */
            while (gn != NULL)
	    {
		tail_gn = &gn->next;  gn = gn->next;
	    }
	}
	objectID++;
    }
    return top_gn;
}


/*
 *  Parses an X.509v3 certificate
 */
bool
parse_x509cert(chunk_t blob, u_int level0, x509cert_t *cert)
{
    u_char  buf[BUF_LEN];
    asn1_ctx_t ctx;
    bool critical;
    chunk_t extnID;
    chunk_t object;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < X509_OBJ_ROOF) {

	if (!extract_object(certObjects, &objectID, &object, &ctx))
	     return FALSE;

	switch (objectID) {
	case X509_OBJ_CERTIFICATE:
	    cert->certificate = object;
	    break;
	case X509_OBJ_TBS_CERTIFICATE:
	    cert->tbsCertificate = object;
	    break;
	case X509_OBJ_VERSION:
	    cert->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
	    DBG(DBG_PARSING,
		DBG_log("  v%d", cert->version);
	    )
	    break;
	case X509_OBJ_SERIAL_NUMBER:
	    cert->serialNumber = object;
	    break;
	case X509_OBJ_SIG_ALG:
	    cert->sigAlg = object;
	    break;
	case X509_OBJ_ISSUER:
	    cert->issuer = object;
	    dntoa(buf, BUF_LEN, object);
	    DBG(DBG_PARSING,
		DBG_log("  '%s'",buf);
	    )
	    break;
	case X509_OBJ_NOT_BEFORE:
	    cert->notBefore = asn1totime(&object, ASN1_UTCTIME);
	    break;
	case X509_OBJ_NOT_AFTER:
	    cert->notAfter = asn1totime(&object, ASN1_UTCTIME);
	    break;
	case X509_OBJ_SUBJECT:
	    cert->subject = object;
	    dntoa(buf, BUF_LEN, object);
	    DBG(DBG_PARSING,
		DBG_log("  '%s'",buf);
	    )
	    break;
	case X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM:
	    if ( known_oid(object) == OID_RSA_ENCRYPTION )
		cert->subjectPublicKeyAlgorithm = PUBKEY_ALG_RSA;
	    break;
	case X509_OBJ_SUBJECT_PUBLIC_KEY:
	    if (cert->subjectPublicKeyAlgorithm == PUBKEY_ALG_RSA)
	    {
		ctx.blobs[4].ptr++; ctx.blobs[4].len--;
	    }
	    else
		objectID = X509_OBJ_MODULUS;
	    break;
	case X509_OBJ_MODULUS:
	    cert->modulus = object;
	    break;
	case X509_OBJ_PUBLIC_EXPONENT:
	    cert->publicExponent = object;
	    break;
	case X509_OBJ_EXTN_ID:
	    extnID = object;
	    break;
	case X509_OBJ_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case X509_OBJ_EXTN_VALUE:
	    {
		u_int extn_oid = known_oid(extnID);
		u_int level = level0 + certObjects[objectID].level + 1;

		if (extn_oid == OID_BASIC_CONSTRAINTS)
		    cert->isCA =
			parse_basicConstraints(object, level);
		else if (extn_oid == OID_SUBJECT_ALT_NAME)
		    cert->subjectAltName =
			parse_generalNames(object, level, FALSE);
		else if (extn_oid == OID_CRL_DISTRIBUTION_POINTS)
		    cert->crlDistributionPoints =
			parse_crlDistributionPoints(object, level);
	    }
	    break;
	case X509_OBJ_ALGORITHM:
	    cert->algorithm = object;
	    break;
	case X509_OBJ_SIGNATURE:
	    cert->signature = object;
	    break;
	default:
	    break;
	}
	objectID++;
    }
    time(&cert->installed);
    return TRUE;
}


/*
 *  Parses an X.509 CRL
 */
bool
parse_x509crl(chunk_t blob, u_int level0, x509crl_t *crl)
{
    u_char buf[BUF_LEN];
    asn1_ctx_t ctx;
    bool critical;
    chunk_t userCertificate;
    chunk_t object;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);
 
    while (objectID < CRL_OBJ_ROOF) {

	if (!extract_object(crlObjects, &objectID, &object, &ctx))
	     return FALSE;

	switch (objectID) {
	case CRL_OBJ_CERTIFICATE_LIST:
	    crl->certificateList = object;
	    break;
	case CRL_OBJ_TBS_CERT_LIST:
	    crl->tbsCertList = object;
	    break;
	case CRL_OBJ_VERSION:
	    crl->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
	    DBG(DBG_PARSING,
		DBG_log("  v%d", crl->version);
	    )
	    break;
	case CRL_OBJ_SIG_ALG:
	    crl->sigAlg = object;
	    break;
	case CRL_OBJ_ISSUER:
	    crl->issuer = object;
	    dntoa(buf, BUF_LEN, object);
	    DBG(DBG_PARSING,
		DBG_log("  '%s'",buf);
	    )
	    break;
	case CRL_OBJ_THIS_UPDATE:
	    crl->thisUpdate = asn1totime(&object, ASN1_UTCTIME);
	    break;
	case CRL_OBJ_NEXT_UPDATE:
	    crl->nextUpdate = asn1totime(&object, ASN1_UTCTIME);
	    break;
	case CRL_OBJ_USER_CERTIFICATE:
	    userCertificate = object;
	    break;
	case CRL_OBJ_REVOCATION_DATE:
	    {
		/* put all the serial numbers and the revocation date in a chained list
		   with revocedCertificates pointing to the first revoked certificate */

		revokedCert_t *revokedCert = alloc_thing(revokedCert_t, "revokedCert");
		revokedCert->userCertificate = userCertificate;
		revokedCert->revocationDate = asn1totime(&object, ASN1_UTCTIME);
		revokedCert->next = crl->revokedCertificates;
		crl->revokedCertificates = revokedCert;
	    }
	    break;
	case CRL_OBJ_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case CRL_OBJ_ALGORITHM:
	    crl->algorithm = object;
	    break;
	case CRL_OBJ_SIGNATURE:
	    crl->signature = object;
	    break;
	default:
	    break;
	}
	objectID++;
    }
    time(&crl->installed);
    return TRUE;
}

/* verify the validity of a certificate by
 * checking the notBefore and notAfter dates
*/
bool
check_validity(const x509cert_t *cert)
{
    time_t current_time;

    time(&current_time);
#define DNDEBUG
#ifdef DNDEBUG
	{
	// FIXME - This is probabaly not the best place to put this
	// however it makes debugging certificate problems much easier
	struct id id = empty_id;
	char buf[IDTOA_BUF];

	id.kind = ID_DER_ASN1_DN;
	id.name.len = (&cert->subject)->len;
	id.name.ptr = temporary_cyclic_buffer();
	memcpy(id.name.ptr, cert->subject.ptr, cert->subject.len);
	idtoa(&id, buf, IDTOA_BUF);

	log("  Certificate DN: %s", buf);
	log("  valid from: %s", timetoa(&cert->notBefore, TRUE)); 
	log("          to: %s", timetoa(&cert->notAfter, TRUE));
	}
#endif
#undef DNDEBUG
    DBG(DBG_PARSING,
	DBG_log("  not before  : %s", timetoa(&cert->notBefore, TRUE));
	DBG_log("  current time: %s", timetoa(&current_time, TRUE));
	DBG_log("  not after   : %s", timetoa(&cert->notAfter, TRUE));
    )

   return (current_time >= cert->notBefore) &&
	  (current_time <= cert->notAfter);
}


/*
 *  compute a digest over a binary blob
 */
static bool
compute_digest(chunk_t tbs, int alg, chunk_t *digest)
{
    switch (alg)
    {
	case OID_MD2:
	case OID_MD2_WITH_RSA:
	{
	    MD2_CTX context;
	    MD2Init(&context);
	    MD2Update(&context, tbs.ptr, tbs.len);
	    MD2Final(digest->ptr, &context);
	    digest->len = MD2_DIGEST_SIZE;
	    return TRUE;
	}
	case OID_MD5:
	case OID_MD5_WITH_RSA:
	{
	    MD5_CTX context;
	    MD5Init(&context);
	    MD5Update(&context, tbs.ptr, tbs.len);
	    MD5Final(digest->ptr, &context);
	    digest->len = MD5_DIGEST_SIZE;
	    return TRUE;
	}
	case OID_SHA1:
	case OID_SHA1_WITH_RSA:
	{
	    SHA1_CTX context;
	    SHA1Init(&context);
	    SHA1Update(&context, tbs.ptr, tbs.len);
	    SHA1Final(digest->ptr, &context);
	    digest->len = SHA1_DIGEST_SIZE;
	    return TRUE;
	}
	default:
	    digest->len = 0;
	    return FALSE;
    }
}

/*
 *  decrypts an RSA signature using the issuer's certificate
 */
static bool
decrypt_sig(chunk_t sig, int alg, const x509cert_t *issuer_cert,
	    chunk_t *digest)
{
    switch (alg)
    {
	chunk_t decrypted;
	case OID_RSA_ENCRYPTION:
	case OID_MD2_WITH_RSA:
	case OID_MD5_WITH_RSA:
	case OID_SHA1_WITH_RSA:
	case OID_SHA256_WITH_RSA:
	case OID_SHA384_WITH_RSA:
	case OID_SHA512_WITH_RSA:
	{
	    mpz_t s;
	    mpz_t e;
	    mpz_t n;

	    n_to_mpz(s, sig.ptr, sig.len);
	    n_to_mpz(e, issuer_cert->publicExponent.ptr,
			issuer_cert->publicExponent.len);
	    n_to_mpz(n, issuer_cert->modulus.ptr,
			issuer_cert->modulus.len);

	    /* decrypt the signature s = s^e mod n */
	    mpz_powm(s, s, e, n);
	    /* convert back to bytes */
	    decrypted = mpz_to_n(s, issuer_cert->modulus.len);
	    DBG(DBG_PARSING,
		DBG_dump_chunk("  decrypted signature: ", decrypted)
	    )

	    /*  copy the least significant bits of decrypted signature
	     *  into the digest string
	    */
	    memcpy(digest->ptr, decrypted.ptr + decrypted.len - digest->len,
		   digest->len);

	    /* free memory */
	    pfree(decrypted.ptr);
	    mpz_clear(s);
	    mpz_clear(e);
	    mpz_clear(n);
	    return TRUE;
	}
	default:
	    digest->len = 0;
	    return FALSE;
    }
}

/*
 *   Check if a signature over binary blob is genuine
 */
static bool
check_signature(chunk_t tbs, chunk_t sig, chunk_t algorithm,
		const x509cert_t *issuer_cert)
{
    u_char digest_buf[MAX_DIGEST_LEN];
    u_char decrypted_buf[MAX_DIGEST_LEN];
    chunk_t digest = {digest_buf, MAX_DIGEST_LEN};
    chunk_t decrypted = {decrypted_buf, MAX_DIGEST_LEN};

    int alg = known_oid(algorithm);

    if (alg != -1)
    {
	DBG(DBG_PARSING,
	    DBG_log("Signature Algorithm: '%s'",oid_names[alg].name);
	)
    }
    else
    {
	u_char buf[BUF_LEN];
	chunk_t hex_oid = {buf, BUF_LEN};
	DBG(DBG_PARSING,
	    hex_str(hex_oid, &algorithm);
	    DBG_log("Signature Algorithm: '%s'", hex_oid.ptr);
	)
    }

    if (!compute_digest(tbs, alg, &digest))
    {
	log("  digest algorithm not supported");
	return FALSE;
    }

    DBG(DBG_PARSING,
	DBG_dump_chunk("  digest:", digest)
    )

    decrypted.len = digest.len; /* we want the same digest length */

    if (!decrypt_sig(sig, alg, issuer_cert, &decrypted))
    {
    	log("  decryption algorithm not supported");
	return FALSE;
    }

    /* check if digests are equal */
    return !memcmp(decrypted.ptr, digest.ptr, digest.len);
}

/*  Checks if the current certificate is revoked. It goes through the
 *  list of revoked certificates of the corresponding crl. If the
 *  certificate is not found in the list, then the certificate is valid
 *  and FALSE is returned.
 */
static bool
check_crl(const x509crl_t *crl, chunk_t serial)
{
    revokedCert_t *revokedCert = crl->revokedCertificates;
    time_t current_time;

    time(&current_time);
    DBG(DBG_PARSING,
	DBG_log("Next CRL update:");
	DBG_log("  this update : %s", timetoa(&crl->thisUpdate, TRUE));
	DBG_log("  current time: %s", timetoa(&current_time, TRUE));
	DBG_log("  next update : %s", timetoa(&crl->nextUpdate, TRUE));
    )
    if (current_time > crl->nextUpdate)
	log("Next CRL update was expected on %s",
		timetoa(&crl->nextUpdate, TRUE));

    DBG(DBG_PARSING,
	DBG_dump_chunk("Serial number:", serial)
    )

    while(revokedCert != NULL)
    {
	/* compare serial numbers */
	if (revokedCert->userCertificate.len == serial.len &&
	    memcmp(revokedCert->userCertificate.ptr, serial.ptr, serial.len) == 0)
	{
	    log("Revocation date: %s",
		timetoa(&revokedCert->revocationDate, TRUE));
	    return TRUE;
	}
	revokedCert = revokedCert->next;
    }
    return FALSE;
}


/*
 *  verifies a X.509 certificate
 */
bool
verify_x509cert(const x509cert_t *cert){

    int pathlen;

    if (same_dn(cert->issuer, cert->subject))
    {
	log("end certificate with identical subject and issuer not accepted");
	return FALSE;
    }

    for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
    {
	u_char buf[BUF_LEN];
	x509cert_t *issuer_cert;
	x509crl_t  *crl;

	DBG(DBG_PARSING,
	    dntoa(buf, BUF_LEN, cert->subject);
	    DBG_log("Subject: '%s'",buf);
	)
	if (!check_validity(cert))
	{
	    log("Certificate is invalid");
	    return FALSE;
	}
	DBG(DBG_PARSING,
	    DBG_log("  certificate is valid")
	)

	DBG(DBG_PARSING,
	    dntoa(buf, BUF_LEN, cert->issuer);
	    DBG_log("Issuer: '%s'",buf);
	)

	issuer_cert = get_x509cacert(cert->issuer);

	if (issuer_cert == NULL)
	{
	    log("Issuer CA certificate not found");
	    return FALSE;
	}
	DBG(DBG_PARSING,
	    DBG_log("  issuer CA certificate found")
	)

	if (!check_signature(cert->tbsCertificate, cert->signature,
			     cert->algorithm, issuer_cert))
	{
	    log("Certificate signature is invalid");
	    return FALSE;
	}
	DBG(DBG_PARSING,
	    DBG_log("  certificate signature is valid")
	)

	crl = get_x509crl(cert->issuer);

	if (crl == NULL)
	{
	    log("Issuer CRL not found");
	}
	else
	{
	    DBG(DBG_PARSING,
		DBG_log("  issuer CRL found")
	    )
	    if (check_signature(crl->tbsCertList, crl->signature,
				crl->algorithm, issuer_cert))
	    {
		DBG(DBG_PARSING,
		    DBG_log("  CRL signature is valid")
		)

		if (check_crl(crl, cert->serialNumber))
		{
		    log("Certificate has been revoked");
		    remove_x509_public_key(cert);
		    return FALSE;
		}
		DBG(DBG_PARSING,
 		    DBG_log("  certificate not revoked")
		)
	    }
	    else
	    {
		log("CRL signature is invalid");
	    }
	}
	/* check if cert is a self-signed root ca */
	if (pathlen > 0 && same_dn(cert->issuer, cert->subject))
	{
	    DBG(DBG_CONTROL,
		DBG_log("reached self-signed root ca")
	    )
	    return TRUE;
	}
        /* otherwise go up one step in the trust chain */
	cert = issuer_cert;
    }
    
    log("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
    return FALSE;
}

/*
 *  list all certs in a chained list
 */
static void
list_cert_chain(const char * caption, x509cert_t* cert, bool utc)
{
    time_t now;

    /* determine the current time */
    time(&now);

    whack_log(RC_COMMENT, " ");
    whack_log(RC_COMMENT, "List of %s:", caption);
    whack_log(RC_COMMENT, " ");

    while (cert != NULL)
    {
	u_char buf[BUF_LEN];

	whack_log(RC_COMMENT, "%s, count: %d", timetoa(&cert->installed, utc), cert->count);
	dntoa(buf, BUF_LEN, cert->subject);
	whack_log(RC_COMMENT, "       subject: '%s'", buf);
	dntoa(buf, BUF_LEN, cert->issuer);
	whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	whack_log(RC_COMMENT, "       validity: not before %s %s",
		timetoa(&cert->notBefore, utc),
		(cert->notBefore < now)?"ok":"fatal (not valid yet)");
	whack_log(RC_COMMENT, "                 not after  %s %s",
		timetoa(&cert->notAfter, utc),
		check_expiry(cert->notAfter, CA_CERT_WARNING_INTERVAL, TRUE));
	cert = cert->next;
    }
}

/*
 *  list all user/host certs in a chained list
 */
void
list_certs(bool utc)
{
    list_cert_chain("User/Host Certificates", x509certs, utc);
}

/*
 *  list all user/host certs in a chained list
 */
void
list_cacerts(bool utc)
{
    list_cert_chain("CA Certificates", x509cacerts, utc);
}

/*
 *  list all crls in the chained list
 */
void
list_crls(bool utc)
{
    const bool strict = FALSE; /*expiry of CRL is non-fatal */

    x509crl_t* crl = x509crls;

    whack_log(RC_COMMENT, " ");
    whack_log(RC_COMMENT, "List of CRLs:");
    whack_log(RC_COMMENT, " ");

    while (crl != NULL)
    {
	u_char buf[BUF_LEN];
	u_int revoked = 0;
	revokedCert_t *revokedCert = crl->revokedCertificates;

	/* count number of revoked certificates in CRL */
	while (revokedCert != NULL)
	{
	    revoked++;
	    revokedCert = revokedCert->next;
        }

	whack_log(RC_COMMENT, "%s, revoked certs: %d",
		timetoa(&crl->installed, utc), revoked);
	dntoa(buf, BUF_LEN, crl->issuer);
	whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	whack_log(RC_COMMENT, "       updates:  this %s",
		timetoa(&crl->thisUpdate, utc));
	whack_log(RC_COMMENT, "                 next %s %s",
		timetoa(&crl->nextUpdate, utc),
		check_expiry(crl->nextUpdate, CRL_WARNING_INTERVAL, strict));
	crl = crl->next;
    }
}
