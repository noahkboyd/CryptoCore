NOTICE: PROJECT IS IN PROGRESS, MISSING FEATURES AND IS BROKEN/UNTESTED.
PLEASE REVIEW YOURSELF OR WAIT FOR ME TO FINISH PROJECT.

Features & Usage:
- AES for 128, 192 & 256 bits keys
- Checks for AES ISA extension(amd64) & auto uses them
- Features:
  - Key & schedule types (encryption-only & full (encryption & decryption) schedules)
  - Helper macros for typed key literals
  - Key schedule generators
  - Block transform functions (encrypt/decrypt)
- Usage Guide:
  - 1. Use a key to generate the corresponding schedule (encryption-only or full (both encryption & decryption))
  - 2. Use schedules to individual transform plaintext/ciphertext blocks
- Compilation Guide:
  - For library:
``` gcc -c my_aes.c -o my_aes.o -g -O0 -Wall -msse2 -msse -march=native -maes ```
  - For testing:
``` gcc -DTESTING_AES my_aes.c -o my_test ```

Modes - ECB CBC OFB CFB CTR GCM
ECB	(Electronic Codebook)   - 🟥 Insecure (Same input -> Same output)
CBC	(Cipher Block Chaining) - 🟩 Chains blocks w/ Initial Value
OFB	(Output Feedback)       - 🟨 Like Stream Cipher
CFB	(Cipher Feedback)	    - 🟩 Like Stream Cipher
CTR	(Counter)               - 🟨 Like Stream Cipher, Parallelizable
GCM	(Galois/Counter Mode)   - 🟨 Combines CTR w/ authentication (AEAD)

Notes:
- Key size -> num rounds:
  - 128 bit key -> 10 rounds
  - 192 bit key -> 12 rounds
  - 256 bit key -> 14 rounds
- General Instructions
  - AESENC          | Perform one round of an AES encryption flow
  - AESENCLAST      | Perform the last round of an AES encryption flow
  - AESDEC          | Perform one round of an AES decryption flow
  - AESDECLAST      | Perform the last round of an AES decryption flow
  - AESKEYGENASSIST | Assist in AES round key generation[note 1]
  - AESIMC          | Assist in AES decryption round key generation. Applies Inverse Mix Columns to round keys.
- x86/amd64 Instructions
  - __m128i _mm_aesdec_si128 (__m128i a, __m128i RoundKey)
  - __m128i _mm_aesdeclast_si128 (__m128i a, __m128i RoundKey)
  - __m128i _mm_aesenc_si128 (__m128i a, __m128i RoundKey)
  - __m128i _mm_aesenclast_si128 (__m128i a, __m128i RoundKey)
  - __m128i _mm_aesimc_si128 (__m128i a)
  - __m128i _mm_aeskeygenassist_si128 (__m128i a, const int imm8)

Reference sites:
- AES Documentation
  - https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm
  - https://en.wikipedia.org/wiki/AES_instruction_set#x86_architecture_processors
  - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
- Intel intrinsics
  - https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
  - https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=aes&othertechs=AES

Reference implementations:
- Stack Overflow
  - https://stackoverflow.com/questions/50491807/aes-ni-intrinsics-with-192-and-256-bits-keys
- Github
  - https://github.com/mrdcvlsc/AES
