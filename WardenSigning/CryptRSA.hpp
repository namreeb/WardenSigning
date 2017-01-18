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

    PBIGNUM m;
    PBIGNUM n;
    PBIGNUM e;

public:
    CryptRSA(const std::uint8_t *modulus, size_t modulusSize, const std::uint8_t *exponent, size_t exponentSize);

    // determine if the current module is properly signed
    void Process(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out);

    // analyze a correct signature to output hopefully useful information
    void Analyze(const std::vector<std::uint8_t> &generated, std::vector<std::uint8_t> &d) const;

    // sign an arbitrary block of data
    void Sign(const std::vector<std::uint8_t> &generated) const;
};
