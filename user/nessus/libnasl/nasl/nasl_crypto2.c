/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 */
 /*
  * This file contains all the call to OpenSSL functions needed by SSH protocol
  */
#include <includes.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"  

#include "strutils.h"
#include "nasl_packet_forgery.h"
#include "nasl_debug.h"
#include "nasl_misc_funcs.h"
#include "nasl_crypto2.h"

#ifndef MAP_FAILED
#define MAP_FAILED (void*)(-1)
#endif

#ifdef HAVE_SSL

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

#include <openssl/blowfish.h>

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

tree_cell * nasl_bn_cmp(lex_ctxt* lexic)
{
  char		*s1 = NULL,*s2 = NULL;
  tree_cell	*retc = NULL;
  BIGNUM *key1 = NULL, *key2 = NULL;
  int vn;
  long sz1, sz2;

  retc = emalloc(sizeof(tree_cell));
  retc->ref_count = 1;
  retc->type = CONST_INT;
  retc->x.i_val = 1;

  vn = array_max_index(&lexic->ctx_vars);
  /* key1 */
  s1 = get_str_local_var_by_name(lexic, "key1");
  sz1 = get_var_size_by_name(lexic, "key1");

  /* key2 */
  s2 = get_str_local_var_by_name(lexic, "key2");
  sz2 = get_var_size_by_name(lexic, "key2");

 if ( s1 == NULL || s2 == NULL )
   goto fail;
  
  key1 = BN_new();
  key2 = BN_new();

  if (BN_bin2bn((const unsigned char*)s1, sz1, key1) == 0)
    goto fail;
  if (BN_bin2bn((const unsigned char*)s2, sz2, key2) == 0)
    goto fail;

  retc->x.i_val = BN_cmp(key1,key2);
  
 fail:
  BN_free(key1);
  BN_free(key2);
  return retc;
}


tree_cell * nasl_bn_random(lex_ctxt* lexic)
{
  char		*s1 = NULL;
  tree_cell	*retc = NULL;
  BIGNUM *key = NULL;
  long need, needlen, s1len;
  int len;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* p bignum */
  need = get_int_local_var_by_name(lexic, "need", 0);
  needlen = get_var_size_by_name(lexic, "need");

  key = BN_new();
  if (!key)
    goto fail;
  
  if (!BN_rand(key, need, 0, 0))
    goto fail;

  s1len = BN_num_bytes(key);
  s1 = emalloc(s1len);
  if (s1 == NULL)
     goto fail;

  BN_bn2bin(key, (unsigned char*)s1);

  if (s1[0] & 0x80)
    len = 1;
  else 
    len = 0;
  retc->x.str_val = emalloc (s1len+len);
  retc->x.str_val[0] = '\0';
  memcpy(retc->x.str_val+len, s1, s1len);
  retc->size = s1len + len;

  goto ret;
  
fail:
  retc->size = 0;
  retc->x.str_val = emalloc(0);
ret:
  BN_free(key);
  return retc;
  
}


tree_cell * nasl_pem_to(lex_ctxt* lexic, int type)
{
  char		*s1 = NULL, *priv = NULL, *passphrase = NULL;
  tree_cell	*retc = NULL;
  RSA * rsa = NULL;
  DSA * dsa = NULL;
  BIGNUM * key = NULL;
  BIO * bio = NULL;
  long privlen, plen, s1len;
  int len;

  if ( check_authenticated(lexic) < 0 ) return FAKE_CELL;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* priv bignum */
  priv = get_str_local_var_by_name(lexic, "priv");
  privlen = get_var_size_by_name(lexic, "priv");

  if ( priv == NULL )
	goto fail;
  
  /* priv bignum */
  passphrase = get_str_local_var_by_name(lexic, "passphrase");
  plen = get_var_size_by_name(lexic, "passphrase");

  bio = BIO_new_mem_buf(priv, privlen);
  if (!bio)
    goto fail;
  
  if (!type)
    {
      rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, passphrase);
      if (!rsa)
        goto fail;
      key = rsa->d;
    }
  else
    {
      dsa = PEM_read_bio_DSAPrivateKey(bio, NULL, NULL, passphrase);
      if (!dsa)
        goto fail;
      key = dsa->priv_key;
    }
  
  s1len = BN_num_bytes(key);
  s1 = emalloc(s1len);
  if (s1 == NULL)
     goto fail;

  BN_bn2bin(key, (unsigned char*)s1);
  
  if (s1[0] & 0x80)
    len = 1;
  else 
    len = 0;
  retc->x.str_val = emalloc (s1len+len);
  retc->x.str_val[0] = '\0';
  memcpy(retc->x.str_val+len, s1, s1len);
  retc->size = s1len + len;

  goto ret;
  
fail:
  retc->size = 0;
  retc->x.str_val = emalloc(0);
ret:
  BIO_free(bio);
  RSA_free(rsa);
  DSA_free(dsa);
  return retc;
  
}


tree_cell * nasl_pem_to_rsa(lex_ctxt* lexic)
{
  return nasl_pem_to(lexic, 0);
}



tree_cell * nasl_pem_to_dsa(lex_ctxt* lexic)
{
  return nasl_pem_to(lexic, 1);
}


tree_cell * nasl_dh_generate_key(lex_ctxt* lexic)
{
  char		*s1 = NULL,*s2 = NULL,*s3 = NULL,*pub = NULL;
  tree_cell	*retc = NULL;
  DH *dh = NULL;
  long sz1, sz2, sz3, pubsize;
  int len;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* p bignum */
  s1 = get_str_local_var_by_name(lexic, "p");
  sz1 = get_var_size_by_name(lexic, "p");
  
  /* g bignum */
  s2 = get_str_local_var_by_name(lexic, "g");
  sz2 = get_var_size_by_name(lexic, "g");

  /* priv key bignum */
  s3 = get_str_local_var_by_name(lexic, "priv");
  sz3 = get_var_size_by_name(lexic, "priv");

  if ( s1 == NULL || s2 == NULL || s3 == NULL )
     goto fail;

  if ((dh = DH_new()) == NULL)
     goto fail;
 
  dh->p = BN_new();
  dh->g = BN_new();
  dh->priv_key = BN_new();
  

  if (BN_bin2bn((const unsigned char*)s1, sz1, dh->p) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s2, sz2, dh->g) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s3, sz3, dh->priv_key) == 0)
     goto fail;

  if (dh->p == NULL)
    goto fail;

  if (DH_generate_key(dh) == 0)
      goto fail;

  pubsize = BN_num_bytes(dh->pub_key);
  pub = emalloc(pubsize); 
  if (pub == NULL)
     goto fail;
  BN_bn2bin(dh->pub_key, (unsigned char*)pub);

  if (pub[0] & 0x80)
    len = 1;
  else 
    len = 0;
  retc->x.str_val = emalloc (pubsize+len);
  retc->x.str_val[0] = '\0';
  memcpy(retc->x.str_val+len, pub, pubsize);
  retc->size = pubsize + len;

  goto ret;

fail:
  retc->x.str_val = emalloc(0);
  retc->size = 0;
ret:
  DH_free(dh);
  free(pub);
  return retc;
}


tree_cell * nasl_dh_compute_key(lex_ctxt* lexic)
{
  char *s1 = NULL,*s2 = NULL,*s3 = NULL,*s4 = NULL,*s5 = NULL;
  char *kbuf;
  tree_cell	*retc = NULL;
  BIGNUM *dh_server_pub = NULL;
  DH *dh = NULL;
  int kout,klen,len;
  long sz1, sz2, sz3, sz4, sz5;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* p bignum */
  s1 = get_str_local_var_by_name(lexic, "p");
  sz1 = get_var_size_by_name(lexic, "p");
  
  /* g bignum */
  s2 = get_str_local_var_by_name(lexic, "g");
  sz2 = get_var_size_by_name(lexic, "g");

  /* dh_server_pub bignum */
  s3 = get_str_local_var_by_name(lexic, "dh_server_pub");
  sz3 = get_var_size_by_name(lexic, "dh_server_pub");

  /* public key bignum */
  s4 = get_str_local_var_by_name(lexic, "pub_key");
  sz4 = get_var_size_by_name(lexic, "pub_key");

  /* private key bignum */
  s5 = get_str_local_var_by_name(lexic, "priv_key");
  sz5 = get_var_size_by_name(lexic, "priv_key");


  if ( s1 == NULL || s2 == NULL || s3 == NULL || s4 == NULL || s5 == NULL )
     goto fail;

  if ((dh = DH_new()) == NULL)
     goto fail;
 
  dh->p = BN_new();
  dh->g = BN_new();
  dh->pub_key = BN_new();
  dh->priv_key = BN_new();
  dh_server_pub = BN_new();

  if (BN_bin2bn((const unsigned char*)s1, sz1, dh->p) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s2, sz2, dh->g) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s3, sz3, dh_server_pub) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s4, sz4, dh->pub_key) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s5, sz5, dh->priv_key) == 0)
     goto fail;

  klen = DH_size(dh);
  kbuf = emalloc(klen);
  kout = DH_compute_key((unsigned char*)kbuf, dh_server_pub, dh);
 
  if (kbuf[0] & 0x80)
    len = 1;
  else 
    len = 0;
  retc->x.str_val = emalloc (kout+len);
  retc->x.str_val[0] = '\0';
  memcpy(retc->x.str_val+len, kbuf, kout);
  retc->size = kout + len;
  goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = emalloc(0);
ret:
  DH_free(dh);
  BN_free(dh_server_pub);
  return retc;
}


tree_cell * nasl_rsa_public_decrypt(lex_ctxt* lexic)
{
  char *s1 = NULL,*s2 = NULL,*s3 = NULL, *decrypted = NULL;
  tree_cell	*retc = NULL;
  RSA *rsa = NULL;
  int len;
  long sz1, sz2, sz3;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* sig bignum */
  s1 = get_str_local_var_by_name(lexic, "sig");
  sz1 = get_var_size_by_name(lexic, "sig");
  
  /* e bignum */
  s2 = get_str_local_var_by_name(lexic, "e");
  sz2 = get_var_size_by_name(lexic, "e");

  /* n bignum */
  s3 = get_str_local_var_by_name(lexic, "n");
  sz3 = get_var_size_by_name(lexic, "n");

  if ( s1 == NULL || s2 == NULL || s3 == NULL ) 
    goto fail;

  if ((rsa = RSA_new()) == NULL)
    goto fail;
 

  rsa->e = BN_new();
  rsa->n = BN_new();

  if (BN_bin2bn((const unsigned char*)s3, sz3, rsa->n) == 0)
    goto fail;
  if (BN_bin2bn((const unsigned char*)s2, sz2, rsa->e) == 0)
    goto fail;

  decrypted = emalloc(sz1);
  if (!decrypted)
    goto fail;

  if ((len = RSA_public_decrypt(sz1, (unsigned char*)s1, (unsigned char*)decrypted, rsa,
	    RSA_PKCS1_PADDING)) < 0)
    goto fail;

  retc->size = len;
  retc->x.str_val = decrypted;
  goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = emalloc(0);
ret:
  RSA_free(rsa);
  return retc;
}


tree_cell * nasl_rsa_sign(lex_ctxt* lexic)
{
  char *s1 = NULL,*s2 = NULL,*s3 = NULL, *s4 = NULL, *sig = NULL, *signature = NULL;
  tree_cell	*retc = NULL;
  RSA *rsa = NULL;
  int ok;
  long sz1, sz2, sz3, sz4, slen;
  unsigned int len;

  if ( check_authenticated(lexic) < 0 ) return FAKE_CELL;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* sig bignum */
  s1 = get_str_local_var_by_name(lexic, "data");
  sz1 = get_var_size_by_name(lexic, "data");
  
  /* e bignum */
  s2 = get_str_local_var_by_name(lexic, "e");
  sz2 = get_var_size_by_name(lexic, "e");

  /* n bignum */
  s3 = get_str_local_var_by_name(lexic, "n");
  sz3 = get_var_size_by_name(lexic, "n");

  /* d bignum */
  s4 = get_str_local_var_by_name(lexic, "d");
  sz4 = get_var_size_by_name(lexic, "d");

  if ( s1 == NULL || s2 == NULL || s3 == NULL || s4 == NULL )
    goto fail;

  if ((rsa = RSA_new()) == NULL)
    goto fail;
 
  rsa->e = BN_new();
  rsa->n = BN_new();
  rsa->d = BN_new();

  if (BN_bin2bn((const unsigned char*)s3, sz3, rsa->n) == 0)
    goto fail;
  if (BN_bin2bn((const unsigned char*)s2, sz2, rsa->e) == 0)
    goto fail;
  if (BN_bin2bn((const unsigned char*)s4, sz4, rsa->d) == 0)
    goto fail;

  slen = RSA_size(rsa);
  sig = emalloc(slen);
  if (!sig)
    goto fail;

  ok = RSA_sign(NID_sha1, (unsigned char*)s1, sz1, (unsigned char*)sig, &len, rsa);
  if (!ok || len > slen)
    goto fail;
  
  signature = emalloc(len);
  if (!signature)
    goto fail;
  
  memcpy(signature,sig,len);
  retc->size = len;
  retc->x.str_val = signature;
  goto ret;

fail:
  retc->size = 0;
  retc->x.str_val = emalloc(0);
ret:
  RSA_free(rsa);
  free(sig);
  return retc;
}


tree_cell * nasl_bf_cbc(lex_ctxt* lexic, int enc)
{
  char *enckey = NULL,*iv = NULL,*data = NULL,*out = NULL;
  tree_cell	*retc = NULL;
  long enckeylen, ivlen, datalen;
  BF_KEY key;
  anon_nasl_var	v;
  nasl_array	*a;

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
 
  /* sig bignum */
  enckey = get_str_local_var_by_name(lexic, "key");
  enckeylen = get_var_size_by_name(lexic, "key");

  iv = get_str_local_var_by_name(lexic, "iv");
  ivlen = get_var_size_by_name(lexic, "iv");

  data = get_str_local_var_by_name(lexic, "data");
  datalen = get_var_size_by_name(lexic, "data");

  if ( enckey == NULL || data == NULL || iv == NULL )
	goto fail;

  /* key len = 16 : { "blowfish-cbc", 	SSH_CIPHER_SSH2, 8, 16, EVP_bf_cbc }*/
  BF_set_key(&key, 16, (unsigned char*)enckey);

  out = emalloc(datalen);
  if (!out)
    goto fail;

  BF_cbc_encrypt((unsigned char*)data, (unsigned char*)out, datalen, &key, (unsigned char*)iv, enc);

  retc->type = DYN_ARRAY;
  retc->x.ref_val = a = emalloc(sizeof(nasl_array));

  /* first encrypted */
  v.var_type = VAR2_DATA;
  v.v.v_str.s_siz = datalen;
  v.v.v_str.s_val = (unsigned char*)out;
  (void) add_var_to_list(a, 0, &v);
  free(out);

  /* second iv */
  v.var_type = VAR2_DATA;
  v.v.v_str.s_siz = ivlen;
  v.v.v_str.s_val = (unsigned char*)iv;
  (void) add_var_to_list(a, 1, &v);

  goto ret;

fail:
  retc->type = CONST_DATA;
  retc->x.str_val = emalloc(0);
  retc->size = 0;
ret:
  return retc;
}


tree_cell * nasl_dsa_do_verify(lex_ctxt* lexic)
{
  char *p = NULL,*g = NULL,*q = NULL, *pub = NULL,*r = NULL,*s = NULL;
  char * data = NULL;
  tree_cell	*retc = NULL;
  DSA *dsa = NULL;
  DSA_SIG * sig = NULL;
  long plen, glen, qlen, publen, rlen, slen, datalen;

  retc = emalloc(sizeof(tree_cell));
  retc->ref_count = 1;
  retc->type = CONST_INT;
  retc->x.i_val = 0;
 
  /* p bignum */
  p = get_str_local_var_by_name(lexic, "p");
  plen = get_var_size_by_name(lexic, "p");
  
  /* g bignum */
  g = get_str_local_var_by_name(lexic, "g");
  glen = get_var_size_by_name(lexic, "g");

  /* q bignum */
  q = get_str_local_var_by_name(lexic, "q");
  qlen = get_var_size_by_name(lexic, "q");

  /* pub bignum */
  pub = get_str_local_var_by_name(lexic, "pub");
  publen = get_var_size_by_name(lexic, "pub");

  /* r bignum */
  r = get_str_local_var_by_name(lexic, "r");
  rlen = get_var_size_by_name(lexic, "r");

  /* s bignum */
  s = get_str_local_var_by_name(lexic, "s");
  slen = get_var_size_by_name(lexic, "s");

  /* data */
  data = get_str_local_var_by_name(lexic, "data");
  datalen = get_var_size_by_name(lexic, "data");
  if  ( p == NULL || g == NULL || q == NULL || pub == NULL || r == NULL || s == NULL )
	goto fail;

  if ((dsa = DSA_new()) == NULL)
    goto fail;
  
  if ((sig = DSA_SIG_new()) == NULL)
    goto fail;
  
  if (BN_bin2bn((const unsigned char*)p, plen, dsa->p) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)g, glen, dsa->g) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)q, qlen, dsa->q) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)pub, publen, dsa->pub_key) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)r, rlen, sig->r) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)s, slen, sig->s) == 0)
     goto fail;

  if (DSA_do_verify((unsigned char*)data, datalen, sig, dsa))
     retc->x.i_val = 1;
  
fail:
  DSA_free(dsa);
  DSA_SIG_free(sig);
  return retc;
}


tree_cell * nasl_dsa_do_sign(lex_ctxt* lexic)
{
  char *p = NULL,*g = NULL,*q = NULL, *pub = NULL,*priv = NULL;
  char * data = NULL;
  tree_cell	*retc = NULL;
  DSA *dsa = NULL;
  DSA_SIG * sig = NULL;
  char *sigblob;
  long plen, glen, qlen, publen, privlen, rlen, slen, datalen;


  if ( check_authenticated(lexic) < 0 ) return FAKE_CELL;

  retc = emalloc(sizeof(tree_cell));
  retc->ref_count = 1;
  retc->type = CONST_DATA;
  retc->x.i_val = 0;
 
  /* p bignum */
  p = get_str_local_var_by_name(lexic, "p");
  plen = get_var_size_by_name(lexic, "p");
  
  /* g bignum */
  g = get_str_local_var_by_name(lexic, "g");
  glen = get_var_size_by_name(lexic, "g");

  /* q bignum */
  q = get_str_local_var_by_name(lexic, "q");
  qlen = get_var_size_by_name(lexic, "q");

  /* pub bignum */
  pub = get_str_local_var_by_name(lexic, "pub");
  publen = get_var_size_by_name(lexic, "pub");

  /* r bignum */
  priv = get_str_local_var_by_name(lexic, "priv");
  privlen = get_var_size_by_name(lexic, "priv");

  /* data */
  data = get_str_local_var_by_name(lexic, "data");
  datalen = get_var_size_by_name(lexic, "data");

  if ( p == NULL || g == NULL || q == NULL || pub == NULL || priv == NULL || data == NULL )
	goto fail;

  if ((dsa = DSA_new()) == NULL)
    goto fail;
  
  if ((sig = DSA_SIG_new()) == NULL)
    goto fail;

  dsa->p = BN_new();
  dsa->g = BN_new();
  dsa->q = BN_new();
  dsa->pub_key = BN_new();
  dsa->priv_key = BN_new();
  
  if (BN_bin2bn((const unsigned char*)p, plen, dsa->p) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)g, glen, dsa->g) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)q, qlen, dsa->q) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)pub, publen, dsa->pub_key) == 0)
     goto fail;
  if (BN_bin2bn((const unsigned char*)priv, privlen, dsa->priv_key) == 0)
     goto fail;

  sig = DSA_do_sign((unsigned char*)data, datalen, dsa);
  if (!sig)
    goto fail;  

  sigblob = emalloc(SIGBLOB_LEN);
  memset(sigblob, 0, SIGBLOB_LEN);
  rlen = BN_num_bytes(sig->r);
  slen = BN_num_bytes(sig->s);

  if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN)
    goto fail;

  BN_bn2bin(sig->r, (unsigned char*)(sigblob+ SIGBLOB_LEN - INTBLOB_LEN - rlen));
  BN_bn2bin(sig->s, (unsigned char*)(sigblob+ SIGBLOB_LEN - slen));
  
  retc->x.str_val = sigblob;
  retc->size = SIGBLOB_LEN;
  
fail:
  DSA_free(dsa);
  DSA_SIG_free(sig);
  return retc;
}


tree_cell * nasl_bf_cbc_encrypt(lex_ctxt* lexic)
{
  return nasl_bf_cbc(lexic, BF_ENCRYPT);
}


tree_cell * nasl_bf_cbc_decrypt(lex_ctxt* lexic)
{
  return nasl_bf_cbc(lexic, BF_DECRYPT);
}


/*--------------------------------------------------------------*/

char * map_file(char * filename, int * len) 
{
 struct stat st;
 int fd;
 char * map, * ret;

 fd = open(filename, O_RDONLY);
 if ( fd < 0 ) return NULL;
 if ( fstat(fd, &st) < 0 )
 {
  close(fd);
  return NULL;
 }

 map = mmap ( NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0 );
 if ( map == NULL || map == MAP_FAILED ) 
	{
	close(fd);
	return NULL;
	}


 ret = nasl_strndup(map, st.st_size);
 munmap(map, st.st_size);
 close(fd);
 *len = st.st_size;
 return ret;
}


/*----------------------------- Script signature management ------------------------------------------*/

/* 
 * Signs a given script
 */
int generate_signed_script(char * filename)
{
 RSA * rsa = NULL;
 FILE * fp = fopen(NESSUS_STATE_DIR "/nessus/nessus_org.priv.pem", "r");
 unsigned char  * result;
 unsigned int len;
 int i;
 char md[SHA_DIGEST_LENGTH+1];
 int be_len;

 char * msg;
 int  msg_len;


 msg = map_file(filename, &msg_len);
 if ( msg == NULL ) {
	perror("mmap ");
	exit(0);
	}

 /* Append the size of the file at the end of the message */
 msg = erealloc(msg, msg_len + sizeof(msg_len));
 be_len = htonl(msg_len);
 memcpy(msg + msg_len, &be_len, sizeof(msg_len));



 SHA1((unsigned char*)msg, msg_len + sizeof(msg_len), (unsigned char*)md);
 if ( fp == NULL ) 
	{
	perror("open ");
	return -1;
	}
 
 rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
 fclose(fp);
 if ( rsa == NULL ) 
	{
	fprintf(stderr, "PEM_read_RSAPrivateKey() failed\n");
	return -1;
	}

 len = RSA_size(rsa);
 result = emalloc(len);
	
 RSA_sign(NID_sha1, (unsigned char*)md, SHA_DIGEST_LENGTH, (unsigned char*)result, &len, rsa);
 printf("#TRUSTED ");
 for ( i = 0 ; i < len ; i ++ )
 {
  printf("%.2x", result[i]);
 }
 printf("\n", len);
 memset(msg + msg_len, 0, sizeof(msg_len));
 printf("%s", msg);
 fflush(stdout);
 efree(&msg);
 efree(&result);
 RSA_free(rsa);
 
 return 0;
}

 
/* 
 * Verify a script signature
 *
 * Returns :
 *	-1 : if an error occured
 *	 0 : if the signature matches
 *	 1 : if the signature does NOT match
 */
int verify_script_signature(char * filename)
{
 char * msg;
 int msg_len;
 char * t;
 unsigned char md[SHA_DIGEST_LENGTH+1];
 RSA * rsa = NULL;
 FILE * fp = fopen(NESSUS_STATE_DIR "/nessus/nessus_org.pem", "r");
 char sig[16384];
 unsigned char bin_sig[8192];
 int binsz = 0;
 int i;
 int sig_len = 0;
 int res = -1;
 int be_len;


 if ( fp == NULL )
 {
  fprintf(stderr, "Open %s/nessus/nessus_org.pem : %s\n", NESSUS_STATE_DIR, strerror(errno));
  return -1;
 }


 rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
 fclose(fp);
 if ( rsa == NULL ) return -1;

 msg = map_file(filename, &msg_len);
 if ( msg == NULL ) return -1;

 msg = erealloc(msg, msg_len + sizeof(msg_len));
 
 t = strchr(msg, '\n');
 if ( t == NULL ) goto err; 
 t[0] = '\0'; t ++;
 strncpy(sig, msg + strlen("#TRUSTED "), sizeof(sig) - 1 );
 sig[sizeof(sig) - 1] = '\0'; 

 /* Append the size of the message at the end of it */
 msg_len = msg_len - ( (int)t - (int)msg);
 be_len = htonl(msg_len);
 memcpy(t + msg_len, &be_len, sizeof(msg_len));

 SHA1((unsigned char*)t, msg_len + sizeof(msg_len), md);

 sig_len = strlen(sig);

 for ( i = 0 ; i < sig_len ; i += 2 )
 {
  char t[3];
  strncpy(t, sig + i, 2);
  t[2] = '\0';
  bin_sig[binsz] = strtoul(t, NULL, 16);
  binsz ++; 
  if ( binsz >= sizeof(bin_sig) ) goto err; /* Too long signature */
 }
 
 

 res = RSA_verify(NID_sha1, md, SHA_DIGEST_LENGTH, bin_sig, binsz, rsa);
 RSA_free(rsa);
 efree(&msg);
 return res == 1 ? 0 : 1;
 
err:
  RSA_free(rsa);
  efree(&msg);
  return -1;
 
}

#else

int generate_signed_script( char * filename ) 
{
 fprintf(stderr, "generate_script_signature() called without OpenSSL support !\n");
 return -1;
}


int verify_script_signature( char * filename ) 
{
 fprintf(stderr, "verify_script_signature() called without OpenSSL support !\n");
 return -1;
}
#endif
