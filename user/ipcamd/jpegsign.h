#pragma once

#include <openssl/rsa.h>

int load_private_key(const char* keyfilename, RSA** rsa_key);
void encode_sig(void* sig, int sig_sz);
int sign_data(void* jpeg_data, size_t jpeg_sz, RSA* rsa_key);
