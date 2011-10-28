#include <stdio.h>
#include <openssl/pem.h>

int load_private_key(const char* keyfilename, RSA** rsa_key)
{
	FILE* keyfile = fopen(keyfilename, "r");
	if(!keyfile) {
		perror("Cannot open keyfile");
		return 1;
	}

	int ret = 0;
	if(!PEM_read_RSAPrivateKey(keyfile, rsa_key, NULL, NULL)) {
		printf("Cannot read private key\n");
		ret = 1;
	}
	fclose(keyfile);
	return ret;
}
int main(int argc, char** argv)
{
  printf("Hello crypttest\n");
  RSA* key;
  load_private_key("/etc/private.pem", &key);
  printf("Bye crypttest\n");
  return 0;
}
