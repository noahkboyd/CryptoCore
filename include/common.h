#ifndef COMMON_H
#define COMMON_H

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

#endif // COMMON_H
