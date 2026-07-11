set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_ASM_COMPILER x86_64-w64-mingw32-gcc)

# MinGW cross builds cannot reliably use the Windows NASM / ADX assembly path.
# Force OPENSSL_NO_ASM so fiat_p256_adx_* symbols are not referenced.
set(OPENSSL_NO_ASM ON CACHE BOOL "Disable BoringSSL assembly for MinGW cross builds" FORCE)
