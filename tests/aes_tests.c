#include "aes.h"

/* Self test return cases
 *   0: no error
 *   1: encryption failed
 *   2: decryption failed
 *   3: both failed
 */
int aes128_self_test(void) {
    uint8_t plain[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    uint8_t enc_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t cipher[] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
    uint8_t computed_cipher[16];
    uint8_t computed_plain[16];
    int out = 0;
    __m128i key_schedule[20];
    aes128_load_key(enc_key, key_schedule);
    aes128_enc(key_schedule, plain, computed_cipher);
    aes128_dec(key_schedule, cipher, computed_plain);
    if (memcmp(cipher, computed_cipher, sizeof(cipher))) out = 1;
    if (memcmp(plain, computed_plain, sizeof(plain))) out |= 2;
    return out;
}

#ifdef TESTING_AES

#include <stdio.h>
#include <stdlib.h>
#include <string.h>     //for memcmp

int main() {
    uint8_t input[16]; memset(input, 0, 16); input[0] = 'A';
    uint8_t output[16];
    uint8_t keyText[16] = "This is my key.";

    __m128i key[20];

    aes128_load_key(keyText, key);
    aes128_enc(key, input, output);

    for (unsigned int i = 0; i < 16; i++)
        printf("%02X", output[i]);

    getchar();
    return 0;
}
#endif
