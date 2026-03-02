#ifndef HIDDEN_COMMON_H
#define HIDDEN_COMMON_H

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

/* AES hardware acceleration (SSE2, AES) */
/* Hardware support */
struct {
    _Bool aes;
} hardware;

#endif // HIDDEN_COMMON_H
