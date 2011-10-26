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
 */
 /*
  * This file contains all the cryptographic functions NASL
  * has
  */
#include <includes.h>
#include <endian.h>
#ifdef HAVE_SSL
#ifdef HAVE_OPENSSL_MD2_H
#include <openssl/md2.h>
#endif
#ifdef HAVE_OPENSSL_MD4_H
#include <openssl/md4.h>
#endif
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"  

#include "nasl_debug.h"

#include "strutils.h"
#include <assert.h>


/*-------------------[  Std. HASH ]-------------------------------------*/
#ifdef HAVE_OPENSSL_MD2_H
tree_cell * nasl_md2(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[MD2_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 MD2((unsigned char*)data, len, (unsigned char*)md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = nasl_strndup(md, MD2_DIGEST_LENGTH);
 retc->size = MD2_DIGEST_LENGTH;
 return retc;
}
#endif	/* HAVE_OPENSSL_MD2_H */

#ifdef HAVE_OPENSSL_MD4_H
tree_cell * nasl_md4(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[MD4_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 MD4((unsigned char*)data, len, (unsigned char*)md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = nasl_strndup(md, MD4_DIGEST_LENGTH);
 retc->size = MD4_DIGEST_LENGTH;
 return retc;
}
#endif /* HAvE_OPENSSL_MD4_H */

tree_cell * nasl_md5(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[MD5_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 MD5((unsigned char*)data, len, (unsigned char*)md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = nasl_strndup(md, MD5_DIGEST_LENGTH);
 retc->size = MD5_DIGEST_LENGTH;
 return retc;
}

tree_cell * nasl_sha(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[SHA_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 SHA((unsigned char*)data, len, (unsigned char*)md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = nasl_strndup(md, SHA_DIGEST_LENGTH);
 retc->size = SHA_DIGEST_LENGTH;
 return retc;
}


tree_cell * nasl_sha1(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[SHA_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 SHA1((unsigned char*)data, len, (unsigned char*)md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = nasl_strndup(md, SHA_DIGEST_LENGTH);
 retc->size = SHA_DIGEST_LENGTH;
 return retc;
}


tree_cell * nasl_ripemd160(lex_ctxt * lexic)
{
 char * data = get_str_var_by_num(lexic, 0);
 int    len  = get_var_size_by_num(lexic, 0);
 char md[RIPEMD160_DIGEST_LENGTH+1];
 tree_cell * retc;
 
 if(data == NULL)
  return NULL;
 
 RIPEMD160((unsigned char*)data, len, (unsigned char*)md);

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->x.str_val = nasl_strndup(md, RIPEMD160_DIGEST_LENGTH);
 retc->size = RIPEMD160_DIGEST_LENGTH;
 return retc;
}




/*-------------------[  HMAC ]-------------------------------------*/



static tree_cell * nasl_hmac(lex_ctxt * lexic, const EVP_MD * evp_md)
{
 char * data = get_str_local_var_by_name(lexic, "data");
 char * key  = get_str_local_var_by_name(lexic, "key");
 int data_len = get_local_var_size_by_name(lexic, "data");
 int  key_len = get_local_var_size_by_name(lexic, "key");
 char hmac[EVP_MAX_MD_SIZE + 1];
 unsigned int len = 0;
 tree_cell * retc;
 
 /* if(data == NULL || key == NULL)
  {
  nasl_perror(lexic, "[%d] HMAC_* functions syntax is : HMAC(data:<data>, key:<key>)\n", getpid());
  return NULL;
 }
 */
 HMAC(evp_md, key, key_len, (unsigned char*)data, data_len, (unsigned char*)hmac, &len);
 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = len;
 retc->x.str_val = nasl_strndup(hmac, len);
 return retc;
}


#ifdef HAVE_OPENSSL_MD2_H
tree_cell * nasl_hmac_md2(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_md2());
}
#endif


tree_cell * nasl_hmac_md5(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_md5());
}

tree_cell * nasl_hmac_sha(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_sha());
}


tree_cell * nasl_hmac_sha1(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_sha1());
}


tree_cell * nasl_hmac_dss(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_dss());
}


tree_cell * nasl_hmac_ripemd160(lex_ctxt * lexic)
{
 return nasl_hmac(lexic, EVP_ripemd160());
}

#endif /* HAVE_SSL */
