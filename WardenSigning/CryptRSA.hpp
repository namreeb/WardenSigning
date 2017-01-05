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
    PBIGNUM modulus;
    PBIGNUM exponent;

public:
    CryptRSA(const std::uint8_t *modulus, size_t modulusSize, const std::uint8_t *exponent, size_t exponentSize);

    void Process(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out) const;

    // check if the generated fingerprint bignum is less than the blizzard supplied modulus
    bool CheckGenerated(std::vector<std::uint8_t> const &generated) const;
};
