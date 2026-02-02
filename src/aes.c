/* AES for 128, 192 & 256 bits keys
 * Checks for AES ISA extension(amd64) & auto uses them
 * Features:
 *  - Key & schedule types (encryption-only & full (encryption & decryption) schedules)
 *  - Helper macros for typed key literals
 *  - Key schedule generators
 *  - Block transform functions (encrypt/decrypt)
 * Inspiration: https://stackoverflow.com/questions/50491807/aes-ni-intrinsics-with-192-and-256-bits-keys
 */

#include "aes.h"
#include <wmmintrin.h> /* for intrinsics for AES-NI */

/* Aggressive inline macro for low-cost wrappers */
#ifndef(INLINE)
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

/* --- Key schedule generators --- (writes to provided array) */

/* AES key expansion || next 4 words in generation cycle
    - shared macro for 128, 256 bit keys
    - (keygen assist needs const imm8 values -> macro) */
#define AES_KX_NXT4(above_words, last_word, rcon) \
    aes_key_expansion_next4words(above_words, _mm_aeskeygenassist_si128(last_word, rcon))

static __m128i aes_key_expansion_next4words(__m128i key, __m128i keygen) {
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); // xor's of: 0, 1 offsets
    key = _mm_xor_si128(key, _mm_slli_si128(key, 8)); // xor's of: 0, 1, 2, 3 offsets
    return _mm_xor_si128(key, keygen);
}

/* AES key expansion || next 4 words in generation cycle
    - macro for 192 bit keys
    - (keygen assist needs const imm8 values -> macro) */
#define AES_KX_NXT4_192(above_words, last_word, rcon) \
    aes_key_expansion_next4words_192(above_words, _mm_aeskeygenassist_si128(last_word, rcon))

static __m128i aes_key_expansion_next4words_192(__m128i key, __m128i keygen) {
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(1, 1, 1, 1));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); // xor's of: 0, 1 offsets
    key = _mm_xor_si128(key, _mm_slli_si128(key, 8)); // xor's of: 0, 1, 2, 3 offsets
    return _mm_xor_si128(key, keygen);
}

/* AES key expansion || 5th-6th in generation cycle */
static __m128i AES_KX_GEN_5_6(__m128i above_words, __m128i last_word) {
    __m128i keygen = _mm_aeskeygenassist_si128(last_word, 0x00);
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(2, 2, 2, 2));
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 4)); // xor's of: 0, 1 offsets
    return _mm_xor_si128(above_words, keygen);
}

/* AES key expansion || 5th-8th in generation cycle */
static __m128i AES_KX_GEN_5_8(__m128i above_words, __m128i last_word) {
    __m128i keygen = _mm_aeskeygenassist_si128(last_word, 0x00);
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(2, 2, 2, 2));
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 4)); // xor's of: 0, 1 offsets
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 8)); // xor's of: 0, 1, 2, 3 offsets
    return _mm_xor_si128(above_words, keygen);
}

void aes128_load_key_enc_only(const aes128_key_t key, aes128_sched_enc_t schedule) {
    __m128i *s = (__m128i *) schedule;
    __m128i last = _mm_loadu_si128((const __m128i*) key);
    _mm_storeu_si128(s++, last); // First 4 words = original key

    #define internal(rcon) last = AES_KX_NXT4(last, last, rcon); _mm_storeu_si128(s++, last);
    internal(0x01);
    internal(0x02);
    internal(0x04);
    internal(0x08);
    internal(0x10);
    internal(0x20);
    internal(0x40);
    internal(0x80);
    internal(0x1B);
    _mm_storeu_si128(s, AES_KX_NXT4(last, last, 0x36));
    #undef internal
}

void aes192_load_key_enc_only(const aes192_key_t key, aes192_sched_enc_t schedule) {
    uint32_t *ks = (uint32_t*) schedule;
    __m128i prev_f4 = _mm_loadu_si128((const __m128i*) key);
    __m128i prev_n2 = _mm_loadl_epi64((const __m128i*) (key + 4));
    _mm_storeu_si128((const __m128i*) ks, prev_f4); ks += 4; // First 6 words = original key
    _mm_storeu_si128((const __m128i*) ks, prev_n2); ks += 2;

    #define internal(rcon) \
        prev_f4 = AES_KX_NXT4_192(prev_f4, prev_n2, rcon); \
        prev_n2 = AES_KX_GEN_5_6(prev_n2, prev_f4); \
        _mm_storeu_si128((const __m128i*) ks, prev_f4); ks += 4; \
        _mm_storel_epi64((__m128i*)ks, prev_n2); ks += 2;
    internal(0x01);
    internal(0x02);
    internal(0x04);
    internal(0x08);
    internal(0x10);
    internal(0x20);
    internal(0x40);
    _mm_storeu_si128((const __m128i*) ks, AES_KX_NXT4_192(prev_f4, prev_n2, 0x80));
    #undef internal
}

void aes256_load_key_enc_only(const aes256_key_t key, aes256_sched_enc_t schedule) {
    __m128i *s = (__m128i * ) schedule;
    __m128i a = _mm_loadu_si128((const __m128i*) key);
    __m128i b = _mm_loadu_si128((const __m128i*) (key + 16));
    _mm_storeu_si128(s++, a); // First 8 words = original key
    _mm_storeu_si128(s++, b);

    #define internal(rcon) \
        a = AES_KX_NXT4(a, b, rcon); _mm_storeu_si128(s++, a); \
        b = AES_KX_GEN_5_8(b, a); _mm_storeu_si128(s++, b);
    internal(0x01);
    internal(0x02);
    internal(0x04);
    internal(0x08);
    internal(0x10);
    internal(0x20);
    a = AES_KX_NXT4(a, b, 0x40); _mm_storeu_si128(s++, a);
    _mm_storeu_si128(s, AES_KX_GEN_5_8(b, a));
    #undef internal
}

/* Generate decryption keys in reverse order.
 * k[N-1] shared by last encryption & first decryption rounds
 * k[0] shared by first encryption & last decryption round (is the original user key)
 */

 void aes128_load_key(const aes128_key_t key, aes128_sched_full_t schedule) {
    __m128i *ks = schedule;
    aes128_load_key_enc_only(key, ks);

    ks[11] = _mm_aesimc_si128(ks[9]);
    ks[12] = _mm_aesimc_si128(ks[8]);
    ks[13] = _mm_aesimc_si128(ks[7]);
    ks[14] = _mm_aesimc_si128(ks[6]);
    ks[15] = _mm_aesimc_si128(ks[5]);
    ks[16] = _mm_aesimc_si128(ks[4]);
    ks[17] = _mm_aesimc_si128(ks[3]);
    ks[18] = _mm_aesimc_si128(ks[2]);
    ks[19] = _mm_aesimc_si128(ks[1]);
}

void aes192_load_key(const aes192_key_t key, aes192_sched_full_t schedule) {
    __m128i *ks = schedule;
    aes192_load_key_enc_only(key, ks);

    ks[13] = _mm_aesimc_si128(ks[11]);
    ks[14] = _mm_aesimc_si128(ks[10]);
    ks[15] = _mm_aesimc_si128(ks[9]);
    ks[16] = _mm_aesimc_si128(ks[8]);
    ks[17] = _mm_aesimc_si128(ks[7]);
    ks[18] = _mm_aesimc_si128(ks[6]);
    ks[19] = _mm_aesimc_si128(ks[5]);
    ks[20] = _mm_aesimc_si128(ks[4]);
    ks[21] = _mm_aesimc_si128(ks[3]);
    ks[22] = _mm_aesimc_si128(ks[2]);
    ks[23] = _mm_aesimc_si128(ks[1]);
}

void aes256_load_key(const aes256_key_t key, aes256_sched_full_t schedule) {
    __m128i *ks = schedule;
    aes256_load_key_enc_only(key, ks);

    ks[15] = _mm_aesimc_si128(ks[13]);
    ks[16] = _mm_aesimc_si128(ks[12]);
    ks[17] = _mm_aesimc_si128(ks[11]);
    ks[18] = _mm_aesimc_si128(ks[10]);
    ks[19] = _mm_aesimc_si128(ks[9]);
    ks[20] = _mm_aesimc_si128(ks[8]);
    ks[21] = _mm_aesimc_si128(ks[7]);
    ks[22] = _mm_aesimc_si128(ks[6]);
    ks[23] = _mm_aesimc_si128(ks[5]);
    ks[24] = _mm_aesimc_si128(ks[4]);
    ks[25] = _mm_aesimc_si128(ks[3]);
    ks[26] = _mm_aesimc_si128(ks[2]);
    ks[27] = _mm_aesimc_si128(ks[1]);
}

/* --- Block transform internal --- */

#define AES_AGNOS_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, ROUND) \
    m = _mm_xor_si128   (m, k0); \
    m = ROUND           (m, k1); \
    m = ROUND           (m, k2); \
    m = ROUND           (m, k3); \
    m = ROUND           (m, k4); \
    m = ROUND           (m, k5); \
    m = ROUND           (m, k6); \
    m = ROUND           (m, k7); \
    m = ROUND           (m, k8); \
    m = ROUND           (m, k9);
#define AES_ENC_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9) \
    AES_AGNOS_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, _mm_aesenc_si128)
#define AES_DEC_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9) \
    AES_AGNOS_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, _mm_aesdec_si128)


static INLINE __m128i aes128_do_enc_block_amd64(__m128i m, __m128i k0, __m128i k1, __m128i k2, __m128i k3, __m128i k4, __m128i k5, __m128i k6, __m128i k7, __m128i k8, __m128i k9, __m128i k10) {
    AES_ENC_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9)
    return _mm_aesenclast_si128(m, k10);
}

static INLINE __m128i aes192_do_enc_block_amd64(__m128i m, __m128i k0, __m128i k1, __m128i k2, __m128i k3, __m128i k4, __m128i k5, __m128i k6, __m128i k7, __m128i k8, __m128i k9, __m128i k10, __m128i k11, __m128i k12) {
    AES_ENC_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9)
    m = _mm_aesenc_si128       (m, k10);
    m = _mm_aesenc_si128       (m, k11);
    return _mm_aesenclast_si128(m, k12);
}

static INLINE __m128i aes256_do_enc_block_amd64(__m128i m, __m128i k0, __m128i k1, __m128i k2, __m128i k3, __m128i k4, __m128i k5, __m128i k6, __m128i k7, __m128i k8, __m128i k9, __m128i k10, __m128i k11, __m128i k12, __m128i k13, __m128i k14) {
    AES_ENC_ROUNDS_0_9_AMD64(m, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9)
    m = _mm_aesenc_si128       (m, k10);
    m = _mm_aesenc_si128       (m, k11);
    m = _mm_aesenc_si128       (m, k12);
    m = _mm_aesenc_si128       (m, k13);
    return _mm_aesenclast_si128(m, k14);
}

static INLINE __m128i aes128_do_dec_block_amd64(__m128i m, __m128i k0, __m128i k10, __m128i k11, __m128i k12, __m128i k13, __m128i k14, __m128i k15, __m128i k16, __m128i k17, __m128i k18, __m128i k19) {
    AES_DEC_ROUNDS_0_9_AMD64(m, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19)
    return _mm_aesdeclast_si128(m, k0);
}

static INLINE __m128i aes192_do_dec_block_amd64(__m128i m, __m128i k0, __m128i k12, __m128i k13, __m128i k14, __m128i k15, __m128i k16, __m128i k17, __m128i k18, __m128i k19, __m128i k20, __m128i k21, __m128i k22, __m128i k23) {
    AES_DEC_ROUNDS_0_9_AMD64(m, k12, k13, k14, k15, k16, k17, k18, k19, k20, k21)
    m = _mm_aesdec_si128       (m, k22);
    m = _mm_aesdec_si128       (m, k23);
    return _mm_aesdeclast_si128(m, k0);
}

static INLINE __m128i aes256_do_dec_block_amd64(__m128i m, __m128i k0, __m128i k14, __m128i k15, __m128i k16, __m128i k17, __m128i k18, __m128i k19, __m128i k20, __m128i k21, __m128i k22, __m128i k23, __m128i k24, __m128i k25, __m128i k26, __m128i k27) {
    AES_DEC_ROUNDS_0_9_AMD64(m, k14, k15, k16, k17, k18, k19, k20, k21, k22, k23)
    m = _mm_aesdec_si128       (m, k24);
    m = _mm_aesdec_si128       (m, k25);
    m = _mm_aesdec_si128       (m, k26);
    m = _mm_aesdec_si128       (m, k27);
    return _mm_aesdeclast_si128(m, k0);
}

/* --- Encrypt block transforms --- (plaintext pointer can be equal to ciphertext pointer) */

#define S(i) _mm_loadu_si128(((__m128i *) schedule) + i)
void aes128_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const aes128_sched_enc_t schedule) {
    __m128i m = _mm_loadu_si128((__m128i *) plaintext);
    m = aes128_do_enc_block_amd64(m, S(0), S(1), S(2), S(3), S(4), S(5), S(6), S(7), S(8), S(9), S(10));
    _mm_storeu_si128((__m128i *) ciphertext, m);
}
void aes192_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const aes192_sched_enc_t schedule) {
    __m128i m = _mm_loadu_si128((__m128i *) plaintext);
    m = aes192_do_enc_block_amd64(m, S(0), S(1), S(2), S(3), S(4), S(5), S(6), S(7), S(8), S(9), S(10), S(11), S(12));
    _mm_storeu_si128((__m128i *) ciphertext, m);
}
void aes256_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const aes256_sched_enc_t schedule) {
    __m128i m = _mm_loadu_si128((__m128i *) plaintext);
    m = aes256_do_enc_block_amd64(m, S(0), S(1), S(2), S(3), S(4), S(5), S(6), S(7), S(8), S(9), S(10), S(11), S(12), S(13), S(14));
    _mm_storeu_si128((__m128i *) ciphertext, m);
}

/* --- Decrypt block transforms --- (plaintext pointer can be equal to ciphertext pointer) */
void aes128_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const aes128_sched_full_t schedule) {
    __m128i m = _mm_loadu_si128((__m128i *) ciphertext);
    m = aes128_do_dec_block_amd64(m, S(0), S(10), S(11), S(12), S(13), S(14), S(15), S(16), S(17), S(18), S(19));
    _mm_storeu_si128((__m128i *) plaintext, m);
}
void aes192_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const aes192_sched_full_t schedule) {
    __m128i m = _mm_loadu_si128((__m128i *) ciphertext);
    m = aes128_do_dec_block_amd64(m, S(0), S(12), S(13), S(14), S(15), S(16), S(17), S(18), S(19), S(20), S(21), S(22), S(23));
    _mm_storeu_si128((__m128i *) plaintext, m);
}
void aes256_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const aes256_sched_full_t schedule) {
    __m128i m = _mm_loadu_si128((__m128i *) ciphertext);
    m = aes128_do_dec_block_amd64(m, S(0), S(14), S(15), S(16), S(17), S(18), S(19), S(20), S(21), S(22), S(23), S(24), S(25), S(26), S(27));
    _mm_storeu_si128((__m128i *) plaintext, m);
}
#undef S

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
