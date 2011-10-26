/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* This file contains global variable definitions for all
 * globals used in sscep
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* Global variables from sscep.h */
int operation_flag;
/* Program name */
char *pname;

/* Network timeout */
int timeout;

/* Certificates, requests, keys.. */
X509 *cacert;
X509 *encert;
X509 *localcert;
X509 *othercert;
X509 *renewal_cert;
X509_REQ *request;
EVP_PKEY *rsa;
EVP_PKEY *renewal_key;
X509_CRL *crl;
FILE *cafile;
FILE *reqfile;
FILE *otherfile;
FILE *crlfile;

/* Fingerprint, signing and encryption algorithms */
EVP_MD *fp_alg;
EVP_MD *sig_alg;
EVP_CIPHER *enc_alg;

/* OpenSSL OID handles */
int nid_messageType;
int nid_pkiStatus;
int nid_failInfo;
int nid_senderNonce;
int nid_recipientNonce;
int nid_transId;
int nid_extensionReq;

/* Global pkistatus */
int pkistatus;

/* Global variables from cmd.h */

/* CA certificate */
int c_flag;
char *c_char;

/* Debug? */
int d_flag;

/* CA encryption certificate */
int e_flag;
char *e_char;

/* Encryption algorithm */
char *E_char; 
int E_flag;

/* Configuration file */
int f_flag;
char *f_char;

/* Fingerprint algorithm */
char *F_char; 
int F_flag;

/* Local certificate  */
char *l_char;
int l_flag;

/* Local selfsigned certificate  (generated automaticatally) */
char *L_char;
int L_flag;

/* CA identifier */
char *i_char;
int i_flag;

/* Private key */
char *k_char;
int k_flag;

/* Private key of already existing certificate */
char *K_char;
int K_flag;

/* Request count */
int n_flag;
int n_num;

/* Already existing certificate (to be renewed) */
char *O_char; 
int O_flag;

/* Proxy */
char *p_char; 
int p_flag;

/* GetCrl CRL file */
char *r_char; 
int r_flag;

/* Resume */
int R_flag;

/* Certificate serial number */
char *s_char; 
int s_flag;

/* Signature algorithm */
char *S_char; 
int S_flag;

/* Polling interval */
int t_num; 
int t_flag;

/* Max polling time */
int T_num; 
int T_flag;

/* URL */
int u_flag;
char *url_char;

/* Verbose? boolean */
int v_flag;

/* GetCert certificate */
int w_flag;
char *w_char;

/* End of command line options */
