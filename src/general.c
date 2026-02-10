/* General startup code */

#include <stdint.h>
#include "general.h"

/* CPU info macros */
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

    _Bool aes  = (ecx >> 25) & 1;
    _Bool sse2 = (edx >> 26) & 1;

    hardware.aes = aes && sse2;
}