#pragma once

#include <openssl/evp.h>

#include <cstdint>
#include <vector>
#include <memory>

class SARC4
{
public:
    SARC4(const std::vector<std::uint8_t> &key);

    void Decrypt(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out);

private:
    static constexpr size_t ExpectedKeySize = 16;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx;
};