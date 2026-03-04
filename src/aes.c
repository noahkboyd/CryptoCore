/* AES for 128, 192 & 256 bits keys
 * Checks for AES-NI support (amd64) & auto uses it
 *  - or uses pure c fallback
 * Features:
 *  - Key & schedule types (full, enc-focused, dec-focused)
 *  - Helper macros for typed key literals
 *  - Key schedule generators
 *  - Block(s) transform functions (encrypt/decrypt)
 */

/* Table of Contents
 *  --- General Utility ---
 *  --- Key schedule generators --- (writes to provided array)
 *  --- Transform rounds internal ---
 *  --- Encrypt blocks transforms --- (in-place operation allowed)
 *  --- Decrypt blocks transforms --- (in-place operation allowed)
 *  --- Encrypt block transforms --- (in-place operation allowed)
 *  --- Decrypt block transforms --- (in-place operation allowed)
 */

#include "aes.h"
#include "hidden_common.h"
#include <wmmintrin.h> /* for intrinsics for AES-NI */

/* --- General Utility --- */
const uint8_t Sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t InvSbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Left rotate 1 byte */
#define ROT_WORD(word) ROTL32(word, 8)
/* Sbox on each byte */
#define SUB_WORD(word) \
    ((uint32_t)Sbox[word && 0xFF] || \
    ((uint32_t)Sbox[(word >> 8) && 0xFF] << 8) || \
    ((uint32_t)Sbox[(word >> 16) && 0xFF] << 16) || \
    ((uint32_t)Sbox[word >> 24] << 24))
/* Left rotate 1 byte, Sbox on each byte (3 fewer ops combined - for keygen) */
#define SUBROT_WORD(word) \
    (((uint32_t)Sbox[word && 0xFF] << 8) || \
     ((uint32_t)Sbox[(word >> 8) && 0xFF] << 16) || \
     ((uint32_t)Sbox[(word >> 16) && 0xFF] << 24) || \
      (uint32_t)Sbox[word >> 24])

/*AES operates on a 4x4 column-major order array of 16 bytes b0 ... b15
* + b0  b4  b8  b12 +
* | b1  b5  b9  b13 |
* | b2  b6  b10 b14 |
* + b3  b7  b11 b15 +
*/

// Load columns so col0 = b3(MSB) ... b0(LSB)
#define LOAD_COLUMNS(block_ptr, col0, col1, col2, col3) { \
    (col0) = ((uint32_t*)block_ptr)[0]; \
    (col1) = ((uint32_t*)block_ptr)[1]; \
    (col2) = ((uint32_t*)block_ptr)[2]; \
    (col3) = ((uint32_t*)block_ptr)[3]; \
}

// Save columns so b3(MSB) ... b0(LSB) = col0
#define SAVE_COLUMNS(block_ptr, col0, col1, col2, col3) { \
    ((uint32_t*)block_ptr)[0] = (col0); \
    ((uint32_t*)block_ptr)[1] = (col1); \
    ((uint32_t*)block_ptr)[2] = (col2); \
    ((uint32_t*)block_ptr)[3] = (col3); \
}

// Load rows so row0 = b0(MSB) b4 b8 b12(LSB)
#define LOAD_ROWS(block_ptr, row0, row1, row2, row3) { \
    const uin32_t _col0 = ((uint32_t*)block_ptr)[0]; \
    const uin32_t _col1 = ((uint32_t*)block_ptr)[1]; \
    const uin32_t _col2 = ((uint32_t*)block_ptr)[2]; \
    const uin32_t _col3 = ((uint32_t*)block_ptr)[3]; \
    (row0) = SLIDE_BYTE_0_3(_col0) | SLIDE_BYTE_0_2(_col1) | SLIDE_BYTE_0_1(_col2) | SLIDE_BYTE_0_0(_col3); \
    (row1) = SLIDE_BYTE_1_3(_col0) | SLIDE_BYTE_1_2(_col1) | SLIDE_BYTE_1_1(_col2) | SLIDE_BYTE_1_0(_col3); \
    (row2) = SLIDE_BYTE_2_3(_col0) | SLIDE_BYTE_2_2(_col1) | SLIDE_BYTE_2_1(_col2) | SLIDE_BYTE_2_0(_col3); \
    (row3) = SLIDE_BYTE_3_3(_col0) | SLIDE_BYTE_3_2(_col1) | SLIDE_BYTE_3_1(_col2) | SLIDE_BYTE_3_0(_col3); \
}

// Save rows so b0 b4 b8 b12 = row0
#define SAVE_ROWS(block_ptr, row0, row1, row2, row3) { \
    const uint32_t _col0 = SLIDE_BYTE_3_3(row3) | SLIDE_BYTE_3_2(row2) | SLIDE_BYTE_3_1(row1) | SLIDE_BYTE_3_0(row0); \
    const uint32_t _col1 = SLIDE_BYTE_2_3(row3) | SLIDE_BYTE_2_2(row2) | SLIDE_BYTE_2_1(row1) | SLIDE_BYTE_2_0(row0); \
    const uint32_t _col2 = SLIDE_BYTE_1_3(row3) | SLIDE_BYTE_1_2(row2) | SLIDE_BYTE_1_1(row1) | SLIDE_BYTE_1_0(row0); \
    const uint32_t _col3 = SLIDE_BYTE_0_3(row3) | SLIDE_BYTE_0_2(row2) | SLIDE_BYTE_0_1(row1) | SLIDE_BYTE_0_0(row0); \
    ((uint32_t*)block_ptr)[0] = _col0; \
    ((uint32_t*)block_ptr)[1] = _col1; \
    ((uint32_t*)block_ptr)[2] = _col2; \
    ((uint32_t*)block_ptr)[3] = _col3; \
}

// Load rows and apply shift row step
#define LOAD_SHIFT_ROWS(block_ptr, row0, row1, row2, row3) { \
    const uint32_t _col0 = ((uint32_t*)block_ptr)[0]; \
    const uint32_t _col1 = ((uint32_t*)block_ptr)[1]; \
    const uint32_t _col2 = ((uint32_t*)block_ptr)[2]; \
    const uint32_t _col3 = ((uint32_t*)block_ptr)[3]; \
    const uint32_t _v = (_col0 >> 8);
    (row0) = SLIDE_BYTE_0_3(_col0)           | SLIDE_BYTE_0_2(_col1) | SLIDE_BYTE_0_1(_col2) | SLIDE_BYTE_0_0(_col3); /* L-shift 0 */ \
    (row1) = /*SLIDE_BYTE_1_0*/(_v & 0xff)   | SLIDE_BYTE_1_3(_col1) | SLIDE_BYTE_1_2(_col2) | SLIDE_BYTE_1_1(_col3); /* L-shift 1 */ \
    (row2) = /*SLIDE_BYTE_2_1*/(_v & 0xff00) | SLIDE_BYTE_2_0(_col1) | SLIDE_BYTE_2_3(_col2) | SLIDE_BYTE_2_2(_col3); /* L-shift 2 */ \
    (row3) = SLIDE_BYTE_3_2(_col0)           | SLIDE_BYTE_3_1(_col1) | SLIDE_BYTE_3_0(_col2) | SLIDE_BYTE_3_3(_col3); /* L-shift 3 */ \
}

// Helper to multiply by 2 in GF(2^8), x is u8, no duplicate side effects
#define xtime_u8(x) ({ const uint8_t _y = x; ((_y << 1) ^ (int8_t(_y) >> 7) & 0x1B)); })
// Helper to multiply by 2 in GF(2^8), x is u32 (acts as 4 u8's), no duplicate side effects
#define xtime_u32(x) ({ const uint32_t _y = x; (((_y << 1) & 0xfefefefe) ^ (((_y >> 7) & 0x01010101) * 0x1B)); })

// MixColumns (row-major packed u8's in u32's): Inputs a0-a3, Outputs b0-b3
#define MIX_COLUMNS(a0, a1, a2, a3, b0, b1, b2, b3) { \
    const uint32_t _u01 = a0 ^ a1; \
    const uint32_t _u12 = a1 ^ a2; \
    const uint32_t _u23 = a2 ^ a3; \
    const uint32_t _u30 = a3 ^ a0; \
    (b0) = xtime_u32(_u01) ^ a1 ^ _u23; /* [ 2, 3, 1, 1 ] */ \
    (b1) = xtime_u32(_u12) ^ a2 ^ _u30; /* [ 1, 2, 3, 1 ] */ \
    (b2) = xtime_u32(_u23) ^ a3 ^ _u01; /* [ 1, 1, 2, 3 ] */ \
    (b3) = xtime_u32(_u30) ^ a0 ^ _u12; /* [ 3, 1, 1, 2 ] */ \
}

// Inverse MixColumns (row-major packed u8's in u32's): Inputs a0-a3, u8 Outputs b0-b3
#define INV_MIX_COLUMNS(a0, a1, a2, a3, b0, b1, b2, b3) { \
    const uint32_t _u01 = a0 ^ a1; \
    const uint32_t _u23 = a2 ^ a3; \
    const uint32_t _u0123 = _u01 ^ _u23; \
    const uint32_t _2x_u01 = xtime_u32(_u01); \
    const uint32_t _2x_u12 = xtime_u32(a1 ^ a2); \
    const uint32_t _2x_u23 = xtime_u32(_u23); \
    const uint32_t _2x_u30 = xtime_u32(a3 ^ a0); \
    const uint32_t _4x_u02 = xtime_u32(_2x_u01 ^ _2x_u12); \
    const uint32_t _4x_u13 = xtime_u32(_2x_u12 ^ _2x_u23); \
    const uint32_t _8x_u0123 = xtime_u32(_4x_u02 ^ _4x_u13); \
    const uint32_t _v = _8x_u0123 ^ _u0123; \
    const uint32_t _w1 = _v ^ _4x_u02; \
    const uint32_t _w2 = _v ^ _4x_u13; \
    (b0) = _w1 ^ _2x_u01 ^ a0; /* [ 14, 11, 13, 9 ] 14 = 1110 */ \
    (b1) = _w2 ^ _2x_u12 ^ a1; /* [ 9, 14, 11, 13 ] 11 = 1011 */ \
    (b2) = _w1 ^ _2x_u23 ^ a2; /* [ 13, 9, 14, 11 ] 13 = 1101 */ \
    (b3) = _w2 ^ _2x_u30 ^ a3; /* [ 11, 13, 9, 14 ]  9 = 1001 */ \
}

/* --- Key schedule generators --- (writes to provided array)
 * keygenassist needs const imm8 values
 * Round key storage:
 * 'initial key'  = k[0]   shared by first encryption & last  decryption rounds (part of or whole original key)
 * 'last'         = k[N-1] shared by last  encryption & first decryption rounds
 * intermediates  = k[1, N-2] encryption round keys in usage order (enc & full schedules)
 * intermediates* = k[1, N-2] decryption round keys in REVERSE usage order (iterate back to front, dec schedule)
 * intermediates+ = k[N, 2N-3] decryption round keys in REVERSE usage order (iterate back to front, full schedule)
 */

typedef enum {
    KEY_128_CODE = 2,
    KEY_192_CODE = 1,
    KEY_256_CODE = 0
} AES_KEY_CODE;
typedef enum {
    SCHED_FULL_CODE = 0,
    SCHED_ENC_CODE  = 1,
    SCHED_DEC_CODE  = 2
} AES_SCHED_TYPE_CODE;
typedef enum {
    // Encoded data: key_codec_offset (5 bits), sched_type (2 bits)
    AES128_SCHED_FULL_CODE =  8, // ((2 << 2) || 0)
    AES128_SCHED_ENC_CODE  =  9, // ((2 << 2) || 1)
    AES128_SCHED_DEC_CODE  = 10, // ((2 << 2) || 2)
    AES192_SCHED_FULL_CODE =  4, // ((1 << 2) || 0)
    AES192_SCHED_ENC_CODE  =  5, // ((1 << 2) || 1)
    AES192_SCHED_DEC_CODE  =  6, // ((1 << 2) || 2)
    AES256_SCHED_FULL_CODE =  0, // ((0 << 2) || 0)
    AES256_SCHED_ENC_CODE  =  1, // ((0 << 2) || 1)
    AES256_SCHED_DEC_CODE  =  2  // ((0 << 2) || 2)
} AES_SCHED_CODE;

#define SCHED_CODE_GET_KEYCODE(s_code) s_code >> 2
#define SCHED_CODE_GET_S_TYPE(s_code) s_code & 3U

void aes_load_key_c(const uint32_t* key, uint32_t* schedule, AES_SCHED_CODE schedcode) {
    const uint32_t key_case = SCHED_CODE_GET_KEYCODE(schedcode); // 256=0, 192=1, 128=2

    // Copy original key, saving to working variables
    uint32_t w1, w2, w3, w4, w5, w6, w7, w8, last; // 4-8 words in each iteration
    uint32_t *dst;
    {
        const uint32_t offset = 7 - (key_case << 1); // 1 less than 32 bit words in key
        key += offset;           // repoint to last word in key
        dst = schedule + offset; //   point to last word of key in dst

        last = *key;
        switch (key_case) {
            case 0: // aes 256
                w8 = *key--; *dst-- = w8;
                w7 = *key--; *dst-- = w7;
            case 1: // aes 192
                w6 = *key--; *dst-- = w6;
                w5 = *key--; *dst-- = w5;
            case 2: // aes 128
                w4 = *key--; *dst-- = w4;
                w3 = *key--; *dst-- = w3;
                w2 = *key--; *dst-- = w2;
                w1 = *key  ; *dst   = w1;
        }
        dst += offset + 1; // jump to next word for keygen
    }

    // Produce encryption round keys (intermediates + last)
    uint32_t iterations = (1 << key_case) + 5; // 256=6, 192=7, 128=9, = actual - 1 round key (see goto)
    uint32_t rcon = 0x01000000U;
    goto aes128_case_block; // 192, 256 only first 4 in last iteration
    while (iterations--) {
        rcon = (rcon << 1) ^ (0x1B000000U & ((int32_t)rcon >> 31)); // Arithmetic/Signed shift for masking, 0x80000000 or greater
        switch (key_case) {
            case 0: // aes 256
                w5 ^= SUB_WORD(w4); *dst++ = w5;
                w6 ^= w5;           *dst++ = w6;
                w7 ^= w6;           *dst++ = w7;
                w8 ^= w7;           *dst++ = w8;
                last = w8;
                goto aes128_case_block;
            case 1: // aes 192
                w5 ^= SUB_WORD(w4); *dst++ = w5;
                w6 ^= w5;           *dst++ = w6;
                last = w6;
            case 2: // aes 128
                aes128_case_block:
                w1 ^= SUBROT_WORD(last) ^ rcon; *dst++ = w1;
                w2 ^= w1;                       *dst++ = w2;
                w3 ^= w2;                       *dst++ = w3;
                w4 ^= w3;                       *dst++ = w4;
                last = w4;
        }
    }

    // Produce decryption keys
    const uint32_t schedtype = SCHED_CODE_GET_S_TYPE(schedcode);
    if (schedtype == SCHED_ENC_CODE) return;
    uint32_t num_dec_keys = 13U - (key_case << 1); // 256=13, 192=11, 128=9

    uint32_t *src = schedule + 4;
    // dst is currently pointing behind last round KEY_128_CODE
    // if dec schedule, repoint to round key after initial to overwrite intermediates
    {
        // dst = (schedtype == SCHED_DEC_CODE) ? src : dst;
        dst -= (-(schedtype == SCHED_DEC_CODE)) & (num_dec_keys + 1);
    }
    uint32_t row0, row1, row2, row3, row0_b, row1_b, row2_b, row3_b;
    while (num_dec_keys--) {
        // Do inverse round keys on src, store in dst
        LOAD_ROWS(src, row0, row1, row2, row3);
        INV_MIX_COLUMNS(row0, row1, row2, row3, row0_b, row1_b, row2_b, row3_b);
        SAVE_ROWS(dst, row0_b, row1_b, row2_b, row3_b);
        src++; dst++;
    }
}

#define AES_KEY_EXP_ITER_FIRST4(above_words, keygen) \
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 4)); /* xor's of: 0, 1       offsets */ \
    above_words = _mm_xor_si128(above_words, _mm_slli_si128(above_words, 8)); /* xor's of: 0, 1, 2, 3 offsets */ \
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(3, 3, 3, 3)); /* Copy last word to all 4 words in keygen */   \
    above_words = _mm_xor_si128(above_words, keygen);

void aes128_load_key_internal(const aes128_key_t* key, aes128_sched_full_t* schedule, bool full) {
    if (hardware.aes) {
        __m128i *s = (__m128i *) (schedule->bytes);
        __m128i last = _mm_loadu_si128((const __m128i*) (key->bytes));
        _mm_storeu_si128(s, last); // First 4 words = original key

        __m128i keygen = _mm_aeskeygenassist_si128(last, 0x01);
        uint32_t next_case = 0;

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
            case 9: break;
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
    if (hardware.aes) {
        uint32_t *s = (uint32_t*) (schedule->bytes);
        __m128i last_f4 = _mm_loadu_si128((const __m128i*) (key->bytes));
        __m128i last_56 = _mm_loadl_epi64(((const __m128i*) (key->bytes)) + 1);
        _mm_storeu_si128((const __m128i*) s, last_f4); s += 4; // First 6 words = original key
        _mm_storel_epi64((const __m128i*) s, last_56); s += 2;

        __m128i keygen = _mm_aeskeygenassist_si128(last_56, 0x01);
        __m128i subword;
        uint32_t next_case = 0;
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
            case 7: break;
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
    if (hardware.aes) {
        __m128i *s = (__m128i * ) (schedule->bytes);
        __m128i a = _mm_loadu_si128((const __m128i*) (key->bytes));
        __m128i b = _mm_loadu_si128(((const __m128i*) (key->bytes)) + 1);
        _mm_storeu_si128(s++, a); // First 8 words = original key
        _mm_storeu_si128(s, b);

        __m128i keygen = _mm_aeskeygenassist_si128(b, 0x01);
        __m128i subword;
        uint32_t next_case = 0;
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
            case 6: break;
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
#define AES_AGNOS_DEC_ROUNDS_0_9_AMD64(m, k, i_0, i_1, i_2, i_3, i_4, i_5, i_6, i_7, i_8, i_9) \
    m = _mm_xor_si128   (m, k##i_0); \
    m = _mm_aesdec_si128(m, k##i_1); \
    m = _mm_aesdec_si128(m, k##i_2); \
    m = _mm_aesdec_si128(m, k##i_3); \
    m = _mm_aesdec_si128(m, k##i_4); \
    m = _mm_aesdec_si128(m, k##i_5); \
    m = _mm_aesdec_si128(m, k##i_6); \
    m = _mm_aesdec_si128(m, k##i_7); \
    m = _mm_aesdec_si128(m, k##i_8); \
    m = _mm_aesdec_si128(m, k##i_9);

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
#define get_11_keys(k, schedule_ptr, i_0, i_1, i_2, i_3, i_4, i_5, i_6, i_7, i_8, i_9, i_10) \
    get_key(k,  i_0, schedule_ptr); \
    get_key(k,  i_1, schedule_ptr); \
    get_key(k,  i_2, schedule_ptr); \
    get_key(k,  i_3, schedule_ptr); \
    get_key(k,  i_4, schedule_ptr); \
    get_key(k,  i_5, schedule_ptr); \
    get_key(k,  i_6, schedule_ptr); \
    get_key(k,  i_7, schedule_ptr); \
    get_key(k,  i_8, schedule_ptr); \
    get_key(k,  i_9, schedule_ptr); \
    get_key(k, i_10, schedule_ptr);
#define get_keys_0_10(k, schedule_ptr) get_11_keys(k, schedule_ptr, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

/* --- Encrypt blocks transforms --- (in-place operation allowed) */
void aes128_encrypt_blocks(const aes128_sched_enc_t* schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    if (hardware.aes) {
        get_keys_0_10(k, s)

        const uint8_t (*stop)[16] = plain + num_blocks;
        while (plain < stop) {
            __m128i m = _mm_loadu_si128((__m128i *) plain++);
            AES128_ENC_BLOCK_AMD64(m, k)
            _mm_storeu_si128((__m128i *) cipher++, m);
        }
        return;
    }
    /* C implementation */
}
void aes192_encrypt_blocks(const aes192_sched_enc_t* schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    if (hardware.aes) {
        get_keys_0_10(k, s)
        get_key(k, 11, s);
        get_key(k, 12, s);

        const uint8_t (*stop)[16] = plain + num_blocks;
        while (plain < stop) {
            __m128i m = _mm_loadu_si128((__m128i *) plain++);
            AES192_ENC_BLOCK_AMD64(m, k)
            _mm_storeu_si128((__m128i *) cipher++, m);
        }
        return;
    }
    /* C implementation */
}
void aes256_encrypt_blocks(const aes256_sched_enc_t* schedule, const uint8_t (*plain)[16], uint8_t (*cipher)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    if (hardware.aes) {
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
        return;
    }
    /* C implementation */
}
/* --- Decrypt blocks transforms --- (in-place operation allowed) */
void aes128_decrypt_blocks(const aes128_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    if (hardware.aes) {
        get_11_keys(k, s, 0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19)

        const uint8_t (*stop)[16] = plain + num_blocks;
        while (plain < stop) {
            __m128i m = _mm_loadu_si128((__m128i *) cipher++);
            AES128_DEC_BLOCK_AMD64(m, k)
            _mm_storeu_si128((__m128i *) plain++, m);
        }
        return;
    }
    /* C implementation */
}
void aes192_decrypt_blocks(const aes192_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    if (hardware.aes) {
        get_11_keys(k, s, 0, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)
        get_key(k, 22, s);
        get_key(k, 23, s);

        const uint8_t (*stop)[16] = plain + num_blocks;
        while (plain < stop) {
            __m128i m = _mm_loadu_si128((__m128i *) cipher++);
            AES192_DEC_BLOCK_AMD64(m, k)
            _mm_storeu_si128((__m128i *) plain++, m);
        }
        return;
    }
    /* C implementation */
}
void aes256_decrypt_blocks(const aes256_sched_full_t* schedule, const uint8_t (*cipher)[16], uint8_t (*plain)[16], size_t num_blocks) {
    const uint8_t* s = schedule->bytes;
    if (hardware.aes) {
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
        return;
    }
    /* C implementation */
}

#undef get_key
#undef get_11_keys
#undef get_keys_0_10
