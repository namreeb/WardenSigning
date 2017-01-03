#include "CryptRSA.hpp"

#include <openssl/bn.h>

#include <cstdint>
#include <vector>
#include <iostream>
#include <exception>
#include <algorithm>
#include <iterator>

namespace
{
// wow bignum functions are little endian whereas openssl is big endian
void WOW_BN_bin2bn(const std::uint8_t *data, size_t size, CryptRSA::PBIGNUM &bn)
{
    if (!bn)
        throw std::runtime_error("WOW_BN_bin2bn received null unique ptr");

    std::vector<std::uint8_t> rData;
    std::reverse_copy(data, data + size, std::back_inserter(rData));

    BN_bin2bn(&rData[0], static_cast<int>(size), bn.get());
}

void WOW_BN_bn2bin(CryptRSA::PBIGNUM &bn, std::vector<std::uint8_t> &out)
{
    out.clear();
    out.resize(BN_num_bytes(bn.get()), 0);

    BN_bn2bin(bn.get(), &out[0]);

    std::reverse(out.begin(), out.end());
}
}

CryptRSA::CryptRSA(const std::uint8_t* modulus, size_t modulusSize, const std::uint8_t* exponent, size_t exponentSize) :
    modulus(::BN_new(), &::BN_free), exponent(::BN_new(), &::BN_free)
{
    WOW_BN_bin2bn(modulus, modulusSize, this->modulus);
    WOW_BN_bin2bn(exponent, exponentSize, this->exponent);
}

void CryptRSA::Process(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out) const
{
    std::unique_ptr<BIGNUM, decltype(&::BN_free)> src(::BN_new(), &::BN_free);
    WOW_BN_bin2bn(&in[0], in.size(), src);

    std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)> ctx(::BN_CTX_new(), &::BN_CTX_free);

    std::unique_ptr<BIGNUM, decltype(&::BN_free)> dst(::BN_new(), &::BN_free);
    BN_mod_exp(dst.get(), src.get(), exponent.get(), modulus.get(), ctx.get());

    WOW_BN_bn2bin(dst, out);
}