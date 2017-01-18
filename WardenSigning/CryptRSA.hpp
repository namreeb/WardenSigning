#pragma once

#include <openssl/bn.h>

#include <cstdint>
#include <memory>
#include <vector>

class CryptRSA
{
public:
    using PBIGNUM = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

private:
    std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)> ctx;

    PBIGNUM n;
    PBIGNUM e;

public:
    CryptRSA(const std::uint8_t *modulus, size_t modulusSize, const std::uint8_t *exponent, size_t exponentSize);

    void Process(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out) const;

    void Sign(const std::vector<std::uint8_t> &generated) const;
};
