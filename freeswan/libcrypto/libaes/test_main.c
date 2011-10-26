#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "aes_cbc.h"
#define AES_BLOCK_SIZE	16
#define KEY_SIZE 	128	/* bits */
#define KEY 		"1234567890123456"
#define STR 		"hola guaso como estaisss ... 012"
#define STRSZ		(sizeof(STR)-1)

#define EMT_AESCBC_BLKLEN AES_BLOCK_SIZE
#define AES_CONTEXT_T  aes_context
#define EMT_ESPAES_KEY_SZ 16
static int pretty_print(const unsigned char *buf, int count) {
	int i=0;
	for (;i<count;i++) printf ("%02hhx ", buf[i]);
	putchar('\n');
	return i;
}
//#define SIZE STRSZ/2
#define SIZE STRSZ
int main() {
	int ret;
	char buf0[SIZE+1], buf1[SIZE+1];
	char IV[AES_BLOCK_SIZE];
	aes_context ac;	
	AES_set_key(&ac, KEY, KEY_SIZE);
	memset(buf0, 0, sizeof (buf0));
	memset(buf1, 0, sizeof (buf1));
	pretty_print(STR, SIZE);
	ret=AES_cbc_encrypt(&ac, STR, buf0, SIZE, IV, 1);
	pretty_print(buf0, SIZE);
	printf("size=%d ret=%d\n%s\n", SIZE, ret, buf0);
	ret=AES_cbc_encrypt(&ac, buf0, buf1, SIZE, IV, 0);
	printf("size=%d ret=%d\n%s\n", SIZE, ret, buf1);
	return 0;
}
