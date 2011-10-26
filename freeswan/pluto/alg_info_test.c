#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <freeswan.h>
#define NO_PLUTO
#include "alg_info.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#define STR_EXAMPLE_ESP "3des, aes128-sha1"
#define STR_EXAMPLE_IKE "3des, aes128-sha, aes128-sha2_256-modp2048"
static void setup_debugging(void) {
	log_to_stderr=TRUE;
	log_to_syslog=FALSE;
	init_log();
	cur_debugging=~0;
}
static int doit(unsigned protoid, const char *str)
{
	struct alg_info *ai;
	enum_names *enames, *anames, *gnames;
	const char *err;
	int i;
	switch (protoid) {
		case PROTO_IPSEC_ESP: {
			struct alg_info_esp *ai_esp;
			struct esp_info *esp_info;
			enames=&esp_transformid_names;
			anames=&auth_alg_names;
			gnames=NULL;
			log("doit - 1");
			ai_esp=alg_info_esp_create_from_str(str, &err);
			ai = (struct alg_info *) ai_esp;
			if (!ai) goto err;
			log("doit - 2");
			alg_info_addref(ai);
			ALG_INFO_ESP_FOREACH(ai_esp, esp_info, i) {
				printf("(%d = \"%s\" [%d], ", 
					esp_info->esp_ealg_id, 
					enum_name(enames, esp_info->esp_ealg_id),
					esp_info->esp_ealg_keylen);
				printf("%d = \"%s\" [%d])\n", 
					esp_info->esp_aalg_id,
					enum_name(anames, esp_info->esp_aalg_id),
					esp_info->esp_aalg_keylen);
			}
			break;
		}
		case PROTO_ISAKMP: {
			struct alg_info_ike *ai_ike;
			struct ike_info *ike_info;
			enames=&oakley_enc_names;
			anames=&oakley_hash_names;
			gnames=&oakley_group_names;
			ai_ike = alg_info_ike_create_from_str(str, &err);
			ai = (struct alg_info *) ai_ike;
			log("doit - 3");
			if (!ai) goto err;
			log("doit - 4");
			alg_info_addref(ai);
			ALG_INFO_IKE_FOREACH(ai_ike, ike_info, i) {
				printf("(%d = \"%s\" [%d], ", 
					ike_info->ike_ealg, 
					enum_name(enames, ike_info->ike_ealg),
					ike_info->ike_eklen);
				printf("%d = \"%s\" [%d], ", 
					ike_info->ike_halg,
					enum_name(anames, ike_info->ike_halg),
					ike_info->ike_hklen);
				printf("%d = \"%s\")\n", 
					ike_info->ike_modp,
					ike_info->ike_modp ?
					  enum_name(gnames, ike_info->ike_modp):
					  "<default>");
			}
			break;
		}
	}
	log("doit - 5");
	if (!ai) goto err;
	{
		char buf[256];
		log("doit - 6");
		alg_info_snprint(buf, sizeof(buf), ai);
		puts(buf);
	}
	log("doit - 7);
	alg_info_delref(&ai);
	log("doit - 8");
	return 0;
err:
	if (err) 
		fprintf(stderr, "ERROR: %s\n", err);
	return 1;
}
int main(int argc, char *argv[])
{
	int c=0;
	int protoid=0;
	char *str;
	while (1) {
		c = getopt(argc, (char**)argv, "ie");
		if (c == -1)
			break;
		switch (c) {
			case 'i':
				protoid=PROTO_ISAKMP;
				break;
			case 'e':
				protoid=PROTO_IPSEC_ESP;
				break;
		}
	}
	if (!protoid || optind ==(argc)) {
		fprintf(stderr, "usage: %s {-i|-e} algo string, eg: \n", 
				argv[0]);
		fprintf(stderr, "       -i " STR_EXAMPLE_IKE "\n");
		fprintf(stderr, "       -e " STR_EXAMPLE_ESP "\n" );
		return 1;
	}
	str=argv[optind];

	setup_debugging();
	log("main - alg_info_test");
	doit(protoid, str);
	return 0;
}
/* 
 * 	Fake to allow build
 */
#define FUNC_NOT_CALLED(func) \
int func(void); int func(void) { abort(); }
FUNC_NOT_CALLED(ike_alg_init);
FUNC_NOT_CALLED(MD5Init);
FUNC_NOT_CALLED(MD5Update);
FUNC_NOT_CALLED(MD5Final);
FUNC_NOT_CALLED(SHA1Init);
FUNC_NOT_CALLED(SHA1Update);
FUNC_NOT_CALLED(SHA1Final);
FUNC_NOT_CALLED(state_with_serialno);
void exit_pluto(int st) {
    exit(st);
}
void
fmt_conn_instance(const struct connection *c __attribute__ ((unused)), char *buf __attribute__ ((unused)));
void fmt_conn_instance(const struct connection *c __attribute__ ((unused)), char *buf __attribute__ ((unused))) {
} 
