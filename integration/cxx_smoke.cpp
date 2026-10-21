// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

// Proves the header parses as C++ and that the archive links and runs from C++.

#include <cstdio>
#include <cstring>

#include "shawncore.h"

static_assert(SHAWNCORE_VERSION_MAJOR >= 0, "version macros must be defined");

extern "C" void no_op_cache_callback(const uint8_t *, size_t) {}

int main()
{
    shawncore_crypto_register_cache_flush(no_op_cache_callback);

    if (shawncore_crypto_self_test() != SHAWNCORE_CRYPTO_SUCCESS) {
        return 1;
    }

    // HMAC-SHA384 against a vector computed with Python's hmac module.
    uint8_t key[32];
    for (size_t i = 0; i < sizeof key; i++) {
        key[i] = static_cast<uint8_t>(i);
    }
    const uint8_t message[] = "ShawnCore C++ smoke";
    uint8_t mac[48];
    if (shawncore_crypto_hmac_sha384(key, message, sizeof message - 1, mac) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 2;
    }
    static const uint8_t expected_prefix[16] = {0x37, 0xcb, 0x9b, 0xcc, 0x81, 0xdd, 0x36, 0x55,
                                                0x0b, 0xf2, 0xe0, 0x02, 0x6b, 0x86, 0x68, 0x75};
    if (std::memcmp(mac, expected_prefix, sizeof expected_prefix) != 0) {
        return 3;
    }

    if (std::strcmp(SHAWNCORE_VERSION_STRING, "") == 0 || shawncore_crypto_session_manager_sizeof() == 0) {
        return 4;
    }

    std::puts("shawncore C++ smoke: ok");
    return 0;
}
