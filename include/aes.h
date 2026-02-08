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
#include <stdbool.h>

/* Aggressive inline macro for low-cost wrappers */
#ifndef INLINE
#if defined(_MSC_VER)
    // Microsoft Visual C++
    #define INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
    // GCC or Clang
    #define INLINE inline __attribute__((always_inline))
#else
    // Fallback for other compilers
    #define INLINE inline
#endif
#endif

/* ----- PUBLIC API -----
 * Guide:
 *   1. Declare & initialize a key with the provided types.
 *   2. Use the key to generate the corresponding schedule (encryption-only or full)
 *   3. Use schedules with data to encrypt/decrypt.
 */

/* --- Key types --- */
typedef struct { uint8_t bytes[16]; } aes128_key_t;
typedef struct { uint8_t bytes[24]; } aes192_key_t;
typedef struct { uint8_t bytes[32]; } aes256_key_t;
/* Helper macros to build typed key literals (16, 24, 32 bytes) */
#define AES128_KEY(...) ((const aes128_key_t){ .bytes = { __VA_ARGS__ } })
#define AES192_KEY(...) ((const aes192_key_t){ .bytes = { __VA_ARGS__ } })
#define AES256_KEY(...) ((const aes256_key_t){ .bytes = { __VA_ARGS__ } })

/* --- Full schedule types --- (for encryption & decryption) */
typedef struct { uint8_t bytes[320]; } aes128_sched_full_t; /* 20 round keys = 320 bytes (128b rnd key=16B) */
typedef struct { uint8_t bytes[384]; } aes192_sched_full_t; /* 24 round keys = 384 bytes */
typedef struct { uint8_t bytes[448]; } aes256_sched_full_t; /* 28 round keys = 448 bytes */
/* --- Encryption-only schedule types --- */
typedef struct { uint8_t bytes[176]; } aes128_sched_enc_t;  /* 11 round keys = 176 bytes */
typedef struct { uint8_t bytes[208]; } aes192_sched_enc_t;  /* 13 round keys = 208 bytes */
typedef struct { uint8_t bytes[240]; } aes256_sched_enc_t;  /* 15 round keys = 240 bytes */

/* --- Key schedule generators --- (writes to provided array) */
void aes128_load_key_internal(const aes128_key_t* key, aes128_sched_full_t* schedule, bool full);
void aes192_load_key_internal(const aes192_key_t* key, aes192_sched_full_t* schedule, bool full);
void aes256_load_key_internal(const aes256_key_t* key, aes256_sched_full_t* schedule, bool full);

INLINE void aes128_load_key(const aes128_key_t* key, aes128_sched_full_t* schedule)         { aes128_load_key_internal(key, schedule, true ); }
INLINE void aes192_load_key(const aes192_key_t* key, aes192_sched_full_t* schedule)         { aes192_load_key_internal(key, schedule, true ); }
INLINE void aes256_load_key(const aes256_key_t* key, aes256_sched_full_t* schedule)         { aes256_load_key_internal(key, schedule, true ); }
INLINE void aes128_load_key_enc_only(const aes128_key_t* key, aes128_sched_enc_t* schedule) { aes128_load_key_internal(key, schedule, false); }
INLINE void aes192_load_key_enc_only(const aes192_key_t* key, aes192_sched_enc_t* schedule) { aes192_load_key_internal(key, schedule, false); }
INLINE void aes256_load_key_enc_only(const aes256_key_t* key, aes256_sched_enc_t* schedule) { aes256_load_key_internal(key, schedule, false); }

/* --- Encrypt blocks transforms --- (in-place operation allowed) */
void aes128_encrypt_blocks(const aes128_sched_enc_t*  schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks);
void aes192_encrypt_blocks(const aes192_sched_enc_t*  schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks);
void aes256_encrypt_blocks(const aes256_sched_enc_t*  schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks);
/* --- Decrypt blocks transforms --- (in-place operation allowed) */
void aes128_decrypt_blocks(const aes128_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks);
void aes192_decrypt_blocks(const aes192_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks);
void aes256_decrypt_blocks(const aes256_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks);

/* --- Encrypt block transforms --- (in-place operation allowed) */
INLINE void aes128_encrypt_block(const aes128_sched_enc_t*  schedule, const uint8_t plain[16], uint8_t cipher[16]) { aes128_encrypt_blocks(schedule, (const uint8_t (*)[16])plain,  (uint8_t (*)[16])cipher, 1); }
INLINE void aes192_encrypt_block(const aes192_sched_enc_t*  schedule, const uint8_t plain[16], uint8_t cipher[16]) { aes192_encrypt_blocks(schedule, (const uint8_t (*)[16])plain,  (uint8_t (*)[16])cipher, 1); }
INLINE void aes256_encrypt_block(const aes256_sched_enc_t*  schedule, const uint8_t plain[16], uint8_t cipher[16]) { aes256_encrypt_blocks(schedule, (const uint8_t (*)[16])plain,  (uint8_t (*)[16])cipher, 1); }
/* --- Decrypt block transforms --- (in-place operation allowed) */
INLINE void aes128_decrypt_block(const aes128_sched_full_t* schedule, const uint8_t cipher[16], uint8_t plain[16]) { aes128_decrypt_blocks(schedule, (const uint8_t (*)[16])cipher, (uint8_t (*)[16])plain, 1); }
INLINE void aes192_decrypt_block(const aes192_sched_full_t* schedule, const uint8_t cipher[16], uint8_t plain[16]) { aes192_decrypt_blocks(schedule, (const uint8_t (*)[16])cipher, (uint8_t (*)[16])plain, 1); }
INLINE void aes256_decrypt_block(const aes256_sched_full_t* schedule, const uint8_t cipher[16], uint8_t plain[16]) { aes256_decrypt_blocks(schedule, (const uint8_t (*)[16])cipher, (uint8_t (*)[16])plain, 1); }

/* Self test return cases
 *   0: no error
 *   1: encryption failed
 *   2: decryption failed
 *   3: both failed
 */
int aes128_self_test(void);

#endif // __AES_H__
