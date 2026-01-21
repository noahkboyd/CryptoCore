#ifndef __AES_H__
#define __AES_H__

/* AES for 128, 192 & 256 bits keys
 * Checks for AES ISA extension(amd64) & auto uses them
 * Features:
 *  - Key & schedule types (encryption-only & full (encryption & decryption) schedules)
 *  - Helper macros for typed key literals
 *  - Key schedule generators
 *  - Block transform functions (encrypt/decrypt)
 * Inspiration: https://stackoverflow.com/questions/50491807/aes-ni-intrinsics-with-192-and-256-bits-keys
 */

#include <stdint.h> /* for uint8_t */

/* ----- PUBLIC API -----
 * Guide:
 *   1. Use a key to generate the corresponding schedule (encryption-only or full (both encryption & decryption))
 *   2. Use schedules to individual transform plaintext/ciphertext blocks
 */

/* --- Key types --- */
typedef uint8_t aes128_key_t[16];
typedef uint8_t aes192_key_t[24];
typedef uint8_t aes256_key_t[32];
/* Helper macros to build typed key literals (16, 24, 32 bytes) */
#define AES128_KEY(...) ((const aes128_key_t){__VA_ARGS__})
#define AES192_KEY(...) ((const aes192_key_t){__VA_ARGS__})
#define AES256_KEY(...) ((const aes256_key_t){__VA_ARGS__})

/* --- Full Key schedule types --- (for encryption & decryption) */
typedef uint8_t aes128_sched_full_t[320]; /* 20 round keys = 176 bytes (128b rnd key=16B) */
typedef uint8_t aes192_sched_full_t[384]; /* 24 round keys = 208 bytes */
typedef uint8_t aes256_sched_full_t[448]; /* 28 round keys = 240 bytes */
/* --- Encryption-only schedule types --- */
typedef uint8_t aes128_sched_enc_t[176];  /* 11 round keys = 176 bytes */
typedef uint8_t aes192_sched_enc_t[208];  /* 13 round keys = 208 bytes */
typedef uint8_t aes256_sched_enc_t[240];  /* 15 round keys = 240 bytes */

/* --- Key schedule generators --- (writes to provided array) */
void aes128_load_key(const aes128_key_t key, aes128_sched_full_t schedule);
void aes192_load_key(const aes192_key_t key, aes192_sched_full_t schedule);
void aes256_load_key(const aes256_key_t key, aes256_sched_full_t schedule);
void aes128_load_key_enc_only(const aes128_key_t key, aes128_sched_enc_t schedule);
void aes192_load_key_enc_only(const aes192_key_t key, aes192_sched_enc_t schedule);
void aes256_load_key_enc_only(const aes256_key_t key, aes256_sched_enc_t schedule);

/* --- Encrypt block transforms --- (plaintext pointer can be equal to ciphertext pointer) */
void aes128_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const aes128_sched_enc_t schedule);
void aes192_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const aes192_sched_enc_t schedule);
void aes256_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const aes256_sched_enc_t schedule);
/* --- Decrypt block transforms --- (plaintext pointer can be equal to ciphertext pointer) */
void aes128_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const aes128_sched_full_t schedule);
void aes192_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const aes192_sched_full_t schedule);
void aes256_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const aes256_sched_full_t schedule);

/* Self test return cases
 *   0: no error
 *   1: encryption failed
 *   2: decryption failed
 *   3: both failed
 */
int aes128_self_test(void);

#endif // __AES_H__
