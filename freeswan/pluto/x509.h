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
 * RCSID $Id: x509.h,v 1.6 2004-09-30 23:14:52 danield Exp $
 */
#ifndef _X509_H
#define _X509_H

/*
 * path definitions for my X.509 or PGP cert, peer certs, cacerts and crls
 */
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
#define HOST_CERT_PATH    __IPSEC__PREFIX__

/* advance warning of imminent expiry of
 * cacerts, public keys, and crls
 */
#define CA_CERT_WARNING_INTERVAL	30 /* days */
#define PUBKEY_WARNING_INTERVAL		14 /* days */
#define CRL_WARNING_INTERVAL		 7 /* days */

/* Definition of generalNames kinds */

typedef enum {
    GN_OTHER_NAME =		0,
    GN_RFC822_NAME =		1,
    GN_DNS_NAME =		2,
    GN_X400_ADDRESS =		3,
    GN_DIRECTORY_NAME =		4,
    GN_EDI_PARTY_NAME = 	5,
    GN_URI =			6,
    GN_IP_ADDRESS =		7,
    GN_REGISTERED_ID =		8
} generalNames_t;

/* access structure for a GeneralName */

typedef struct generalName generalName_t;

struct generalName {
    generalName_t   *next;
    generalNames_t  kind;
    chunk_t         name;
};

/* access structure for an X.509v3 certificate */

typedef struct x509cert x509cert_t;

struct x509cert {
  x509cert_t     *next;
  time_t	 installed;
  int		 count;
  chunk_t	 certificate;
  chunk_t          tbsCertificate;
  u_int              version;
  chunk_t            serialNumber;
                /*   signature */
  chunk_t              sigAlg;
  chunk_t            issuer;
                /*   validity */
  time_t               notBefore;
  time_t               notAfter;
  chunk_t            subject;
                /*   subjectPublicKeyInfo */
  enum pubkey_alg      subjectPublicKeyAlgorithm;
                /*     subjectPublicKey */
  chunk_t                modulus;
  chunk_t                publicExponent;
  chunk_t            issuerUniqueID;
  chunk_t            subjectUniqueID;
                /*   v3 extensions */
                /*   extension */
                /*     extension */
                /*       extnID */
                /*        critical */
                /*        extnValue */
  bool			  isCA;
  generalName_t		  *subjectAltName;
  generalName_t		  *crlDistributionPoints;
		/* signatureAlgorithm */
  chunk_t            algorithm;
  chunk_t          signature;
};

/* access structure for a revoked serial number */

typedef struct revokedCert revokedCert_t;

struct revokedCert{
  revokedCert_t *next;
  chunk_t       userCertificate;
  time_t        revocationDate;
};

/* storage structure for an X.509 CRL */

typedef struct x509crl x509crl_t;

struct x509crl {
  x509crl_t     *next;
  time_t	 installed;
  chunk_t        certificateList;
  chunk_t          tbsCertList;
  u_int              version;
  	         /*  signature */
  chunk_t              sigAlg;
  chunk_t            issuer;
  time_t             thisUpdate;
  time_t             nextUpdate;
  revokedCert_t      *revokedCertificates;
                /*   crlExtensions */
                /* signatureAlgorithm */
  chunk_t            algorithm;
  chunk_t          signature;
};

/* stores either a X.509 or OpenPGP certificate */

typedef struct {
    u_char type;
    chunk_t cert;
} cert_t;

/*  do not send certificate requests
 *  flag set in main.c and used in ipsec_doi.c
 */
extern bool no_cr_send;

/* used for initialization */
extern const x509crl_t  empty_x509crl;
extern const x509cert_t empty_x509cert;

extern bool same_dn(chunk_t a, chunk_t b);
#define MAX_CA_PATH_LEN		7
extern void hex_str(chunk_t bin, chunk_t *str);
extern int dntoa(char *dst, size_t dstlen, chunk_t dn);
extern err_t atodn(char *src, chunk_t *dn);
extern void gntoid(struct id *id, const generalName_t *gn);
extern bool parse_x509cert(chunk_t blob, u_int level0, x509cert_t *cert);
extern bool parse_x509crl(chunk_t blob, u_int level0, x509crl_t *crl);
extern bool check_validity(const x509cert_t *cert);
extern bool verify_x509cert(const x509cert_t *cert);
extern bool get_mycert(cert_t *mycert, x509cert_t *cert);
extern x509cert_t* load_x509cert(const char* filename, const char* label);
extern x509cert_t* load_host_cert(const char* filename);
extern x509cert_t* add_x509cert(x509cert_t *cert);
extern void share_x509cert(x509cert_t *cert);
extern void release_x509cert(x509cert_t *cert);
extern void free_x509cert(x509cert_t *cert);
extern void store_x509certs(x509cert_t **firstcert);
extern void load_cacerts(void);
extern void load_crls(void);
extern void load_mycert(void);
extern void list_certs(bool utc);
extern void list_cacerts(bool utc);
extern void list_crls(bool utc);
extern void free_cacerts(void);
extern void free_crls(void);
extern void free_mycert(void);
extern void free_generalNames(generalName_t* gn);
#endif
