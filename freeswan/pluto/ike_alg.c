/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 
 * ike_alg.c,v 1.1.4.3 2002/05/30 03:26:08 jjo Exp
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "sha1.h"
#include "md5.h"
#include "crypto.h"

#include "state.h"
#include "packet.h"
#include "kernel.h"
#include "log.h"
#include "whack.h"
#include "spdb.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "id.h"
#include "x509.h"
#include "connections.h"

#define return_on(var, val) do { var=val;goto return_out; } while(0);

/*
 * 	Create an OAKLEY proposal based on alg_info and policy
 */
struct db_context *
ike_alg_db_new(struct alg_info_ike *ai , lset_t policy)
{
	struct db_context *db_ctx = NULL;
	struct ike_info *ike_info;
	unsigned ealg, halg, modp, eklen=0;
	struct encrypt_desc *enc_desc;
	int i;

	if (!ai) {
		whack_log(RC_LOG_SERIOUS, "no IKE algorithms "
				"for this connection "
				"(check ike algorithm string)");
		goto fail;
	}
	policy &= POLICY_ID_AUTH_MASK;
	db_ctx = db_prop_new(PROTO_ISAKMP, 8, 8 * 5);

	/* for each group */
	ALG_INFO_IKE_FOREACH(ai, ike_info, i) {
		ealg = ike_info->ike_ealg;
		halg = ike_info->ike_halg;
		modp = ike_info->ike_modp;
		eklen= ike_info->ike_eklen;

		if (!ike_alg_enc_present(ealg)) {
			DBG_log("%s() ike enc ealg=%d not present",
					__FUNCTION__, ealg);
			continue;
		}

		if (!ike_alg_hash_present(halg)) {
			DBG_log("%s() ike hash halg=%d not present",
					__FUNCTION__, halg);
			continue;
		}

		enc_desc = ike_alg_get_encrypter(ealg);
		passert(enc_desc != NULL);

		if (eklen 
		/*
			&& eklen != enc_desc->keydeflen)
		*/
			&& (eklen < enc_desc->keyminlen
				|| eklen >  enc_desc->keymaxlen))
		{
			DBG_log("%s() "
					"ealg=%d (specified) keylen:%d, "
					"not valid "
					/*
					 "keylen != %d"
					 */
					"min=%d, max=%d"
					, __FUNCTION__
					, ealg
					, eklen
					/*
					, enc_desc->keydeflen
					*/
					, enc_desc->keyminlen
					, enc_desc->keymaxlen
					);
			continue;
		}

		if (policy & POLICY_RSASIG) {
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, 
					OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, 
					OAKLEY_HASH_ALGORITHM, halg);
			if (eklen)
				db_attr_add_values(db_ctx, 
						OAKLEY_KEY_LENGTH, eklen);
			db_attr_add_values(db_ctx, 
					OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG);
			db_attr_add_values(db_ctx, 
					OAKLEY_GROUP_DESCRIPTION, modp);
		}
		if (policy & POLICY_PSK) {
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, 
					OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, 
					OAKLEY_HASH_ALGORITHM, halg);
			if (ike_info->ike_eklen) 
				db_attr_add_values(db_ctx, 
						OAKLEY_KEY_LENGTH, ike_info->ike_eklen);
			db_attr_add_values(db_ctx, 
					OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY);
			db_attr_add_values(db_ctx, 
					OAKLEY_GROUP_DESCRIPTION, modp);
		}
	}
fail:
	return db_ctx;
}
/*
 * 	Show registered IKE algorithms
 */
void
ike_alg_show_status(void)
{
	unsigned alg, i;
	struct ike_alg *algo;
	IKE_EALG_FOR_EACH(algo) {
		passert(algo != NULL);
		alg=algo->algo_id;
		whack_log(RC_COMMENT, "algorithm IKE encrypt: id=%d, name=%s, blocksize=%d, keydeflen=%d"
			, alg
			, enum_name(&oakley_enc_names, alg)
			, ((struct encrypt_desc *)algo)->enc_blocksize
			, ((struct encrypt_desc *)algo)->keydeflen
			);
		
	}
	IKE_HALG_FOR_EACH(algo) {
		whack_log(RC_COMMENT, "algorithm IKE hash: id=%d, name=%s, hashsize=%d"
			, algo->algo_id
			, enum_name(&oakley_hash_names, algo->algo_id)
			, ((struct hash_desc *)algo)->hash_digest_size
			);
	}
#define IKE_DH_ALG_FOR_EACH(idx) for(idx = 0; idx != elemsof(oakley_group); idx++)
	IKE_DH_ALG_FOR_EACH(i) {
		const struct oakley_group_desc *gdesc=oakley_group+i;
		whack_log(RC_COMMENT, "algorithm IKE dh group: id=%d, name=%s, bits=%d"
			, gdesc->group
			, enum_name(&oakley_group_names, gdesc->group)
			, gdesc->bytes*BITS_PER_BYTE
			);
	}
}
/*
 * 	Show IKE algorithms for 
 * 	- this connection (result from ike= string)
 * 	- newest SA
 */
void
ike_alg_show_connection(struct connection *c, const char *instance)
{
	char buf[256];
	struct state *st;
	if (c->alg_info_ike) {
		alg_info_snprint(buf, sizeof(buf), 
				(struct alg_info *)c->alg_info_ike);
		whack_log(RC_COMMENT
		    , "\"%s\"%s:   IKE algorithms wanted: %s"
		    , c->name
		    , instance
		    , buf);
	}
	if (c->alg_info_ike) {
		alg_info_snprint_ike(buf, sizeof(buf), c->alg_info_ike);
		whack_log(RC_COMMENT
		    , "\"%s\"%s:   IKE algorithms found:  %s"
		    , c->name
		    , instance
		    , buf);
	}
	st = state_with_serialno(c->newest_isakmp_sa);
	if (st)
		whack_log(RC_COMMENT
		, "\"%s\"%s:   IKE algorithm newest: %s_%d-%s-%s"
		, c->name
		, instance
		, enum_show(&oakley_enc_names, st->st_oakley.encrypt)
		+7 /* strlen("OAKLEY_") */
		/* , st->st_oakley.encrypter->keydeflen */
		, st->st_oakley.enckeylen
		, enum_show(&oakley_hash_names, st->st_oakley.hash)
		+7 /* strlen("OAKLEY_") */
		, enum_show(&oakley_group_names, st->st_oakley.group->group)
		+13 /* strlen("OAKLEY_GROUP_") */
	 );
}
/*==========================================================
 *
 * 	IKE algo list handling
 *
 * 	- registration
 * 	- lookup
 *=========================================================*/
struct ike_alg *ike_alg_base[IKE_ALG_MAX+1] = {NULL, NULL};
/*	check if IKE encrypt algo is present */
bool ike_alg_enc_present(int ealg)
{
	struct encrypt_desc *enc_desc = ike_alg_get_encrypter(ealg);
	return enc_desc ? enc_desc->enc_blocksize : 0;
}
/*	check if IKE hash algo is present */
bool ike_alg_hash_present(int halg)
{
	struct hash_desc *hash_desc = ike_alg_get_hasher(halg);
	return hash_desc ? hash_desc->hash_digest_size : 0;
}
bool ike_alg_enc_ok(int ealg, unsigned key_len, struct alg_info_ike *alg_info_ike, const char **errp)
{
	int ret=TRUE;
	struct encrypt_desc *enc_desc;
	char errbuf[256]="encrypt algo not found";
	/* 
	 * test #1: encrypt algo must be present 
	 */
	enc_desc = ike_alg_get_encrypter(ealg);
	if (!enc_desc) return_on(ret, FALSE);
	/* 
	 * test #2: if key_len specified, it must be in range 
	 */
	if ((key_len) && ((key_len < enc_desc->keyminlen) ||
			 (key_len > enc_desc->keymaxlen))) {
		snprintf(errbuf, sizeof(errbuf),
				"key_len not in range: encalg=%d, "
				"key_len=%d, keyminlen=%d, keymaxlen=%d",
				ealg, key_len,
				enc_desc->keyminlen,
				enc_desc->keymaxlen
		       );
		log ("%s(): %s", __FUNCTION__, errbuf);
		return_on(ret, FALSE);
	} 
	/* 
	 * test #3: if alg_info specified AND strict flag, only
	 * only allow algo iff listed in st->alg_info_esp
	 */
	else if (alg_info_ike && (alg_info_ike->alg_info_flags & ALG_INFO_F_STRICT) ) {
		int i;
		struct ike_info *ike_info;
		ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
			if ((ike_info->ike_ealg == ealg) &&
				((ike_info->ike_eklen==0) || (key_len==0) ||
				 (ike_info->ike_eklen==key_len))) {
				return_on(ret, TRUE);
			}
		}
		snprintf(errbuf, sizeof(errbuf),
				"strict flag and encrypt algorithm "
				"not in transform string list: "
				"ealg=%d, "
				"key_len=%d, keyminbits=%d, keymaxbits=%d",
				ealg, key_len,
				enc_desc->keyminlen,
				enc_desc->keymaxlen
		   );
		log("%s(): %s", __FUNCTION__, errbuf);
		return_on(ret, FALSE);
	}
return_out:
	DBG(DBG_KLIPS, 
		if (ret) 
			DBG_log("%s(ealg=%d,key_len=%d): "
				"blocksize=%d, keyminlen=%d, "
				"keydeflen=%d, keymaxlen=%d, "
				"ret=%d",
				__FUNCTION__,
				ealg, key_len,
				enc_desc->enc_blocksize,
				enc_desc->keyminlen,
				enc_desc->keydeflen,
				enc_desc->keymaxlen,
				ret);
		else 
			DBG_log("%s(ealg=%d,key_len=%d): NO",
				__FUNCTION__, ealg, key_len);
	);
	if (!ret && *errp)
		*errp=errbuf;
	return ret;
}
/*
 * 	return ike_algo object by {type, id}
 */
/* XXX:jjo use keysize */
struct ike_alg *
ike_alg_find(unsigned algo_type, unsigned algo_id, unsigned keysize __attribute__((unused)))
{
	struct ike_alg *e=ike_alg_base[algo_type];
	for(;e!=NULL;e=e->algo_next) {
		if (e->algo_id==algo_id)
			break;
	}

	return e;
}

/*
 * 	Main "raw" ike_alg list adding function
 */
int
ike_alg_add(struct ike_alg* a)
{
	int ret=0;
	const char *ugh="No error";
	if (a->algo_type > IKE_ALG_MAX)
	{
		ugh="Invalid algo_type";
		return_on(ret,-EINVAL);
	}
	if (ike_alg_find(a->algo_type, a->algo_id, 0))
	{
		ugh="Algorithm already exists";
		return_on(ret,-EEXIST);
	}
	if (ret==0) {
		a->algo_next=ike_alg_base[a->algo_type];
		ike_alg_base[a->algo_type]=a;
	}
return_out:
	if (ret) 
		log("%s(): ERROR: %s", __FUNCTION__, ugh);
	return ret;
}

/*
 * 	Validate and register IKE hash algorithm object
 */
int
ike_alg_register_hash(struct hash_desc *hash_desc)
{
	const char *alg_name;
	int ret=0;
	if (hash_desc->algo_id > OAKLEY_HASH_MAX) {
		log ("%s(): hash alg=%d < max=%d",
				__FUNCTION__, hash_desc->algo_id, OAKLEY_HASH_MAX);
		return_on(ret,-EINVAL);
	}
	if (hash_desc->hash_ctx_size > sizeof (union hash_ctx)) {
		log ("%s(): hash alg=%d has "
				"ctx_size=%d > hash_ctx=%d",
				__FUNCTION__,
				hash_desc->algo_id, 
				hash_desc->hash_ctx_size,
				sizeof (union hash_ctx));
		return_on(ret,-EOVERFLOW);
	}
	if (!(hash_desc->hash_init&&hash_desc->hash_update&&hash_desc->hash_final)) {
		log ("%s(): hash alg=%d needs  "
				"hash_init(), hash_update() and hash_final()",
				__FUNCTION__, hash_desc->algo_id);
		return_on(ret,-EINVAL);
	}
	alg_name=enum_name(&oakley_hash_names, hash_desc->algo_id);
	if (!alg_name) {
		log ("%s(): WARNING: hash alg=%d not found in "
				"constants.c:oakley_hash_names  ",
				__FUNCTION__, hash_desc->algo_id);
		alg_name="<NULL>";
	}

return_out:
	if (ret==0)
		ret=ike_alg_add((struct ike_alg *)hash_desc);
	log("%s: Activating %s: %s (ret=%d)", 
			__FUNCTION__,
			alg_name, ret==0? "Ok" : "FAILED", ret);
	return ret;
}

/*
 * 	Validate and register IKE encryption algorithm object
 */
int
ike_alg_register_enc(struct encrypt_desc *enc_desc)
{
	const char *alg_name;
	int ret=0;
	if (enc_desc->algo_id > OAKLEY_ENCRYPT_MAX) {
		log ("%s(): enc alg=%d < max=%d\n",
				__FUNCTION__,
				enc_desc->algo_id, OAKLEY_ENCRYPT_MAX);
		return_on(ret, -EINVAL);
	}
	alg_name=enum_name(&oakley_enc_names, enc_desc->algo_id);
	if (!alg_name) {
		log ("%s(): WARNING: enc alg=%d not found in "
				"constants.c:oakley_enc_names  ",
				__FUNCTION__, enc_desc->algo_id);
		alg_name="<NULL>";
	}
return_out:
	if (ret==0)
		ret=ike_alg_add((struct ike_alg *)enc_desc);
	log("%s: Activating %s: %s (ret=%d)", 
			__FUNCTION__,
			alg_name, ret==0? "Ok" : "FAILED", ret);
	return 0;
}
