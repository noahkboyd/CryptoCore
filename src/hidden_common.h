#ifndef HIDDEN_COMMON_H
#define HIDDEN_COMMON_H

/* Rotate macros */
#if defined(_MSC_VER) || true
    #include <intrin.h>
    // MSVC Intrinsics also GCC/Clang?
    #define ROTL8(x, n) _rotl8((x), (n))
    #define ROTR8(x, n) _rotr8((x), (n))
    #define ROTL16(x, n) _rotl16((x), (n))
    #define ROTR16(x, n) _rotr16((x), (n))

    #define ROTL32(x, n) _rotl((x), (n))
    #define ROTR32(x, n) _rotr((x), (n))
    #define ROTL64(x, n) _rotl64((x), (n))
    #define ROTR64(x, n) _rotr64((x), (n))
#endif

/* Get byte from u32 & slide to specified byte index. Index is as u32 3(MSB) ... 0(LSB)} */
// SLIDE_BYTE_(src index)_(dst index)
// select lowest byte & move
#define SLIDE_BYTE_0_0(word) (word & 0xff)
#define SLIDE_BYTE_0_1(word) ((word & 0xff) << 8)
#define SLIDE_BYTE_0_2(word) ((word & 0xff) << 16)
#define SLIDE_BYTE_0_3(word) (word << 24)
// select 2nd lowest byte & move
#define SLIDE_BYTE_1_0(word) ((word >> 8) & 0xff)
#define SLIDE_BYTE_1_1(word) (word & 0xff00)
#define SLIDE_BYTE_1_2(word) (word & 0xff00) << 8
#define SLIDE_BYTE_1_3(word) (word >> 8) << 24
// select 2nd highest byte & move
#define SLIDE_BYTE_2_0(word) ((word >> 16) & 0xff)
#define SLIDE_BYTE_2_1(word) ((word >> 8) & 0xff00)
#define SLIDE_BYTE_2_2(word) (word & 0xff0000)
#define SLIDE_BYTE_2_3(word) ((word >> 16) << 24)
// select highest byte & move
#define SLIDE_BYTE_3_0(word) (word >> 24)
#define SLIDE_BYTE_3_1(word) ((word >> 24) << 8)
#define SLIDE_BYTE_3_2(word) ((word >> 24) << 16)
#define SLIDE_BYTE_3_3(word) ((word >> 24) << 24)

#endif // HIDDEN_COMMON_H
