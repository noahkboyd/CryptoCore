/* AES for 128, 192 & 256 bits keys
 * Checks for AES ISA extension(amd64) & auto uses them
 * Features:
 *  - Key & schedule types (encryption-only & full (encryption & decryption) schedules)
 *  - Helper macros for typed key literals
 *  - Key schedule generators
 *  - Block transform functions (encrypt/decrypt)
 * Inspiration: https://stackoverflow.com/questions/50491807/aes-ni-intrinsics-with-192-and-256-bits-keys
 */

/* Table of Contents
 *  --- Startup Code ---
 *  --- Key schedule generators --- (writes to provided array)
 *  --- Transform rounds internal ---
 *  --- Encrypt blocks transforms --- (in-place operation allowed)
 *  --- Decrypt blocks transforms --- (in-place operation allowed)
 *  --- Encrypt block transforms --- (in-place operation allowed)
 *  --- Decrypt block transforms --- (in-place operation allowed)
 */

#include "aes.h"
#include <wmmintrin.h> /* for intrinsics for AES-NI */

#if !defined(CPUID) && !defined(CPUIDEX)
#ifdef _MSC_VER
    // Windows (MSVC) - Use <intrin.h>
    #include <intrin.h>
    #define CPUID(output, func)              __cpuid(output, func)
    #define CPUIDEX(output, func, subfunc)    __cpuidex(output, func, subfunc)
#elif defined(__GNUC__) || defined(__clang__)
    // Linux/macOS (GCC/Clang) - Use <cpuid.h>
    #include <cpuid.h>
    #define CPUID(output, func)              __cpuid((func), (output)[0], (output)[1], (output)[2], (output)[3])
    #define CPUIDEX(output, func, subfunc)   __cpuid_count((func), (subfunc), (output)[0], (output)[1], (output)[2], (output)[3])
#else
    #error "Unsupported compiler (only MSVC, GCC, and Clang are supported)"
#endif
#endif

/* --- Multi-platform Startup Macro --- */
#ifndef INITIALIZER
#if defined(__GNUC__) || defined(__clang__)
    // For GCC/Clang: Use the constructor attribute
    #define INITIALIZER(f) \
        static void f(void) __attribute__((constructor)); \
        static void f(void)
#elif defined(_MSC_VER)
    // For MSVC: Use pragma section "magic"
    // .CRT$XCU is the "User" initializer segment
    #pragma section(".CRT$XCU", read)
    #define INITIALIZER(f) \
        static void f(void); \
        __declspec(allocate(".CRT$XCU")) void (*f##_ptr)(void) = f; \
        static void f(void)
#else
    #error "Unknown compiler. Please add a constructor implementation."
#endif
#endif

/* AES hardware acceleration (SSE2, AES) */
bool aes_support = false;

INITIALIZER(startup) {
    uint32_t nIds_, ecx, edx;
    uint32_t cpui[4];

    // Calling CPUID with 0x0 as the function_id argument
    // gets the number of the highest valid function ID.
    CPUID(cpui, 0);
    nIds_ = cpui[0];

    // load bitset with flags for function 0x00000001
    if (nIds_ >= 1) {
        CPUIDEX(cpui, 1, 0);
        ecx = cpui[2];
        edx = cpui[3];
    } else {
        ecx = 0; edx = 0;
    }

    bool aes  = (ecx >> 25) & 1;
    bool sse2 = (edx >> 26) & 1;

    aes_support = aes && sse2;
}

/* --- Key schedule generators --- (writes to provided array)
 * keygenassist needs const imm8 values - makes it interesting
 * Generate decryption keys in reverse order.
 * k[N-1] shared by last encryption & first decryption rounds
 * k[0] shared by first encryption & last decryption round (is the original user key)
 */

#define AES_KEY_EXP_ITER_FIRST4(above_words, keygen) \
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 4)); /* xor's of: 0, 1       offsets */ \
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 8)); /* xor's of: 0, 1, 2, 3 offsets */ \
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(3, 3, 3, 3)); /* Copy last word to all 4 words in keygen */   \
    above_words = _mm_xor_si128(above_words, keygen);

void aes128_load_key_internal(const aes128_key_t* key, aes128_sched_full_t* schedule, bool full) {
    if (aes_support) {
        __m128i *s = (__m128i *) (schedule->bytes);
        __m128i last = _mm_loadu_si128((const __m128i*) (key->bytes));
        _mm_storeu_si128(s, last); // First 4 words = original key

        __m128i keygen = _mm_aeskeygenassist_si128(last, 0x01);
        uint8_t next_case = 0;

        rcon_cases_loop:
        // key expansion part || 4 words at a time (1 round key)
        AES_KEY_EXP_ITER_FIRST4(last, keygen)
        _mm_storeu_si128(++s, last); // move pointer before store

        switch (next_case) {
            #define case_block(THIS_CASE, NEXT_CASE, rcon)          \
                case THIS_CASE: next_case = NEXT_CASE;              \
                    keygen = _mm_aeskeygenassist_si128(last, rcon); \
                    goto rcon_cases_loop;
            case_block(0, 1, 0x02)
            case_block(1, 2, 0x04)
            case_block(2, 3, 0x08)
            case_block(3, 4, 0x10)
            case_block(4, 5, 0x20)
            case_block(5, 6, 0x40)
            case_block(6, 7, 0x80)
            case_block(7, 8, 0x1B)
            case_block(8, 9, 0x36)
            #undef case_block
            case 9: return;
        }

        if (full) {
            __m128i *ks = schedule->bytes;
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
        return;
    }
    /* C implementation */
}

void aes192_load_key_internal(const aes192_key_t* key, aes192_sched_full_t* schedule, bool full) {
    if (aes_support) {
        uint32_t *s = (uint32_t*) (schedule->bytes);
        __m128i last_f4 = _mm_loadu_si128((const __m128i*) (key->bytes));
        __m128i last_56 = _mm_loadl_epi64(((const __m128i*) (key->bytes)) + 1);
        _mm_storeu_si128((const __m128i*) s, last_f4); s += 4; // First 6 words = original key
        _mm_storel_epi64((const __m128i*) s, last_56); s += 2; 

        __m128i keygen = _mm_aeskeygenassist_si128(last_56, 0x01);
        __m128i subword;
        uint8_t next_case = 0;
        goto first_four;

        rcon_cases_loop:
        // key expansion part || 6 words at a time || here for last two (5-6)
        subword = _mm_aeskeygenassist_si128(last_f4, 0x00);
        subword = _mm_shuffle_epi32(subword, _MM_SHUFFLE(2, 2, 2, 2)); // Copy 3rd word to all 4 words of subword
        last_56 = _mm_xor_si128(last_56, _mm_slli_si128(last_56, 4)); // xor's of: 0, 1 offsets
        last_56 =  _mm_xor_si128(last_56, subword);
        _mm_storel_epi64((__m128i*)s, last_56); s += 2; 
        first_four:
        AES_KEY_EXP_ITER_FIRST4(last_f4, keygen)
        _mm_storeu_si128((const __m128i*) s, last_f4); s += 4;

        switch (next_case) {
            #define case_block(THIS_CASE, NEXT_CASE, rcon)             \
                case THIS_CASE: next_case = NEXT_CASE;                 \
                    keygen = _mm_aeskeygenassist_si128(last_56, rcon); \
                    goto rcon_cases_loop;
            case_block(0, 1, 0x02)
            case_block(1, 2, 0x04)
            case_block(2, 3, 0x08)
            case_block(3, 4, 0x10)
            case_block(4, 5, 0x20)
            case_block(5, 6, 0x40)
            #undef case_block
            case 6: next_case = 7; // last iteration only needs 4 words
                keygen = _mm_aeskeygenassist_si128(last_56, 0x80);
                goto first_four;
            case 7: return;
        }

        if (full) {
            __m128i *ks = schedule->bytes;
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
        return;
    }
    /* C implementation */
}

void aes256_load_key_internal(const aes256_key_t* key, aes256_sched_full_t* schedule, bool full) {
    if (aes_support) {
        __m128i *s = (__m128i * ) (schedule->bytes);
        __m128i a = _mm_loadu_si128((const __m128i*) (key->bytes));
        __m128i b = _mm_loadu_si128(((const __m128i*) (key->bytes)) + 1);
        _mm_storeu_si128(s++, a); // First 8 words = original key
        _mm_storeu_si128(s, b);

        __m128i keygen = _mm_aeskeygenassist_si128(b, 0x01);
        __m128i subword;
        uint8_t next_case = 0;
        goto first_four;

        rcon_cases_loop:
        // key expansion part || 8 words at a time (2 round keys)
        // last four (5-8)
        subword = _mm_aeskeygenassist_si128(a, 0x00);
        subword = _mm_shuffle_epi32(subword, _MM_SHUFFLE(2, 2, 2, 2));
        b = _mm_xor_si128(b, _mm_slli_si128(b, 4)); // xor's of: 0, 1 offsets
        b = _mm_xor_si128(b, _mm_slli_si128(b, 8)); // xor's of: 0, 1, 2, 3 offsets
        b = _mm_xor_si128(b, subword);
        _mm_storeu_si128(++s, b);
        first_four:
        AES_KEY_EXP_ITER_FIRST4(a, keygen)
        _mm_storeu_si128(++s, a);
        
        switch (next_case) {
            #define case_block(THIS_CASE, NEXT_CASE, rcon)       \
                case THIS_CASE: next_case = NEXT_CASE;           \
                    keygen = _mm_aeskeygenassist_si128(b, rcon); \
                    goto rcon_cases_loop;
            case_block(0, 1, 0x02)
            case_block(1, 2, 0x04)
            case_block(2, 3, 0x08)
            case_block(3, 4, 0x10)
            case_block(4, 5, 0x20)
            #undef case_block
            case 5: next_case = 6; // last iteration only needs 4 words (1 round keys)
                keygen = _mm_aeskeygenassist_si128(b, 0x40);
                goto first_four;
            case 6: return;
        }

        if (full) {
            __m128i *ks = schedule->bytes;
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
        return;
    }
    /* C implementation*/
}

/* --- Transform rounds internal --- */

/* Agnostic internal shared round operations */
/* This define concats arg token k with 0-9 for k0-k9 */
#define AES_AGNOS_ENC_ROUNDS_0_9_AMD64(m, k) \
    m = _mm_xor_si128   (m, k##0); \
    m = _mm_aesenc_si128(m, k##1); \
    m = _mm_aesenc_si128(m, k##2); \
    m = _mm_aesenc_si128(m, k##3); \
    m = _mm_aesenc_si128(m, k##4); \
    m = _mm_aesenc_si128(m, k##5); \
    m = _mm_aesenc_si128(m, k##6); \
    m = _mm_aesenc_si128(m, k##7); \
    m = _mm_aesenc_si128(m, k##8); \
    m = _mm_aesenc_si128(m, k##9);
/* This define concats arg token k with i0-i9 (int literals - not macros themselves) for ki0-ki9 */
#define AES_AGNOS_DEC_ROUNDS_0_9_AMD64(m, k, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9) \
    m = _mm_xor_si128   (m, k##i0); \
    m = _mm_aesdec_si128(m, k##i1); \
    m = _mm_aesdec_si128(m, k##i2); \
    m = _mm_aesdec_si128(m, k##i3); \
    m = _mm_aesdec_si128(m, k##i4); \
    m = _mm_aesdec_si128(m, k##i5); \
    m = _mm_aesdec_si128(m, k##i6); \
    m = _mm_aesdec_si128(m, k##i7); \
    m = _mm_aesdec_si128(m, k##i8); \
    m = _mm_aesdec_si128(m, k##i9);

/* Main work operations for encryption/decryption -> define for inling */
/* Expects k0-k10 as existing round keys in scope, m and round keys are __m128i */
#define AES128_ENC_BLOCK_AMD64(m, k) {   \
    AES_AGNOS_ENC_ROUNDS_0_9_AMD64(m, k) \
    m = _mm_aesenclast_si128(m, k##10);  \
}
/* Expects k0-k12 as existing round keys in scope, m and round keys are __m128i */
#define AES192_ENC_BLOCK_AMD64(m, k) {   \
    AES_AGNOS_ENC_ROUNDS_0_9_AMD64(m, k) \
    m = _mm_aesenc_si128   (m, k##10);   \
    m = _mm_aesenc_si128   (m, k##11);   \
    m= _mm_aesenclast_si128(m, k##12);   \
}
/* Expects k0-k14 as existing round keys in scope, m and round keys are __m128i */
#define AES256_ENC_BLOCK_AMD64(m, k) {   \
    AES_AGNOS_ENC_ROUNDS_0_9_AMD64(m, k) \
    m = _mm_aesenc_si128    (m, k##10);  \
    m = _mm_aesenc_si128    (m, k##11);  \
    m = _mm_aesenc_si128    (m, k##12);  \
    m = _mm_aesenc_si128    (m, k##13);  \
    m = _mm_aesenclast_si128(m, k##14);  \
}
/* Expects k0, k10-k19 as existing round keys in scope, m and round keys are __m128i */
#define AES128_DEC_BLOCK_AMD64(m, k) { \
    AES_AGNOS_DEC_ROUNDS_0_9_AMD64(m, k, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19) \
    m = _mm_aesdeclast_si128(m, k##0); \
}
/* Expects k0, k12-k23 as existing round keys in scope, m and round keys are __m128i */
#define AES192_DEC_BLOCK_AMD64(m, k) { \
    AES_AGNOS_DEC_ROUNDS_0_9_AMD64(m, k, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21) \
    m = _mm_aesdec_si128    (m, k##22); \
    m = _mm_aesdec_si128    (m, k##23); \
    m = _mm_aesdeclast_si128(m, k##0);  \
}
/* Expects k0, k14-k27 as existing round keys in scope, m and round keys are __m128i */
#define AES256_DEC_BLOCK_AMD64(m, k) { \
    AES_AGNOS_DEC_ROUNDS_0_9_AMD64(m, k, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23) \
    m = _mm_aesdec_si128    (m, k##24); \
    m = _mm_aesdec_si128    (m, k##25); \
    m = _mm_aesdec_si128    (m, k##26); \
    m = _mm_aesdec_si128    (m, k##27); \
    m = _mm_aesdeclast_si128(m, k##0);  \
}


/* Helper macros for keys */
#define get_key(k, i, schedule_ptr) __m128i k##i = _mm_loadu_si128(((__m128i *) schedule_ptr) + i)
#define get_11_keys(k, schedule_ptr, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10) \
    get_key(k,  i0, schedule_ptr); \
    get_key(k,  i1, schedule_ptr); \
    get_key(k,  i2, schedule_ptr); \
    get_key(k,  i3, schedule_ptr); \
    get_key(k,  i4, schedule_ptr); \
    get_key(k,  i5, schedule_ptr); \
    get_key(k,  i6, schedule_ptr); \
    get_key(k,  i7, schedule_ptr); \
    get_key(k,  i8, schedule_ptr); \
    get_key(k,  i9, schedule_ptr); \
    get_key(k, i10, schedule_ptr);
#define get_keys_0_10(k, schedule_ptr) get_11_keys(k, schedule_ptr, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

/* --- Encrypt blocks transforms --- (in-place operation allowed) */
void aes128_encrypt_blocks(const aes128_sched_enc_t* schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    get_keys_0_10(k, s)

    const uint8_t (*stop)[16] = plain + num_blocks;
    while (plain < stop) {
        __m128i m = _mm_loadu_si128((__m128i *) plain++);
        AES128_ENC_BLOCK_AMD64(m, k)
        _mm_storeu_si128((__m128i *) cipher++, m);
    }
}
void aes192_encrypt_blocks(const aes192_sched_enc_t* schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    get_keys_0_10(k, s)
    get_key(k, 11, s);
    get_key(k, 12, s);

    const uint8_t (*stop)[16] = plain + num_blocks;
    while (plain < stop) {
        __m128i m = _mm_loadu_si128((__m128i *) plain++);
        AES192_ENC_BLOCK_AMD64(m, k)
        _mm_storeu_si128((__m128i *) cipher++, m);
    }
}
void aes256_encrypt_blocks(const aes256_sched_enc_t* schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    get_keys_0_10(k, s)
    get_key(k, 11, s);
    get_key(k, 12, s);
    get_key(k, 13, s);
    get_key(k, 14, s);

    const uint8_t (*stop)[16] = plain + num_blocks;
    while (plain < stop) {
        __m128i m = _mm_loadu_si128((__m128i *) plain++);
        AES256_ENC_BLOCK_AMD64(m, k)
        _mm_storeu_si128((__m128i *) cipher++, m);
    }
}
/* --- Decrypt blocks transforms --- (in-place operation allowed) */
void aes128_decrypt_blocks(const aes128_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    get_11_keys(k, s, 0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19)

    const uint8_t (*stop)[16] = plain + num_blocks;
    while (plain < stop) {
        __m128i m = _mm_loadu_si128((__m128i *) cipher++);
        AES128_DEC_BLOCK_AMD64(m, k)
        _mm_storeu_si128((__m128i *) plain++, m);
    }
}
void aes192_decrypt_blocks(const aes192_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    get_11_keys(k, s, 0, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)
    get_key(k, 22, s);
    get_key(k, 23, s);

    const uint8_t (*stop)[16] = plain + num_blocks;
    while (plain < stop) {
        __m128i m = _mm_loadu_si128((__m128i *) cipher++);
        AES192_DEC_BLOCK_AMD64(m, k)
        _mm_storeu_si128((__m128i *) plain++, m);
    }
}
void aes256_decrypt_blocks(const aes256_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    get_11_keys(k, s, 0, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
    get_key(k, 24, s);
    get_key(k, 25, s);
    get_key(k, 26, s);
    get_key(k, 27, s);

    const uint8_t (*stop)[16] = plain + num_blocks;
    while (plain < stop) {
        __m128i m = _mm_loadu_si128((__m128i *) cipher++);
        AES256_DEC_BLOCK_AMD64(m, k)
        _mm_storeu_si128((__m128i *) plain++, m);
    }
}

#undef get_key
#undef get_11_keys
#undef get_keys_0_10

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
