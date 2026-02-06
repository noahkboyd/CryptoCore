To-Do:
AES:
  - Pure C implementation - no intrinsics
  - Check that everything works
  - System checking
    - Add check for AES, SSE2, etc extensions
      - Figure out each extension that is used
      - Each for the public api should check for hardware acceleration
    - Add macros for different architectures
  - Add support for modes
  - multi-threading
  - fix self-test
SHA:
  - SHA256:
    - Incremental Hashing Interface
MD5: