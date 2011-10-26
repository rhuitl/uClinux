#ifndef AES_WRAP_H
#define AES_WRAP_H

void aes_wrap(u8 *kek, int n, u8 *plain, u8 *cipher);
int aes_unwrap(u8 *kek, int n, u8 *cipher, u8 *plain);

#endif /* AES_WRAP_H */
