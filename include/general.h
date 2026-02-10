#ifndef GENERAL_H
#define GENERAL_H

/* Contains general macros, shared values and some startup code */

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

#endif // GENREAL_H