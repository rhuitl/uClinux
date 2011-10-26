#include <stdio.h>
#include "hmacmd5.h"

main(int argc, char *argv[])
{
    HMACMD5_CTX ctx;
    unsigned char hash[16];
    unsigned char buf[64];
    int count;

    if (argc != 2) {
	printf("Usage: hmacmd5 <key>\n");
	exit(1);
    }

    HMACMD5Init(&ctx, argv[1], strlen(argv[1]));

    do {
	count = fread(buf, 1, 64, stdin);
	HMACMD5Update(&ctx, buf, count);
    } while (count == 64);

    HMACMD5Final(hash, &ctx);

    fwrite(hash, 16, 1, stdout);

    return 0;
}
