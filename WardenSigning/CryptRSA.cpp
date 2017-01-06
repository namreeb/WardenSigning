#include "CryptRSA.hpp"

#include <openssl/bn.h>

#include <cstdint>
#include <vector>
#include <exception>
#include <algorithm>
#include <iterator>
#include <iostream>

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

    if (!out.size())
        throw std::runtime_error("WOW_BN_bn2bin attempted to convert empty BIGNUM");

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

void CryptRSA::Process(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out, const std::vector<std::uint8_t> &generated) const
{
    std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)> ctx(::BN_CTX_new(), &::BN_CTX_free);

    std::unique_ptr<BIGNUM, decltype(&::BN_free)> src(::BN_new(), &::BN_free);
    WOW_BN_bin2bn(&in[0], in.size(), src);

    std::cout << "a is " << BN_num_bits(src.get()) << " bits" << std::endl;
    std::cout << "a is " << (BN_is_prime(src.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::cout << "exponent is " << BN_num_bits(this->exponent.get()) << " bits" << std::endl;
    std::cout << "exponent is " << (BN_is_prime(this->exponent.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::cout << "m is " << BN_num_bits(this->modulus.get()) << " bits" << std::endl;
    std::cout << "m is " << (BN_is_prime(this->modulus.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::unique_ptr<BIGNUM, decltype(&::BN_free)> dst(::BN_new(), &::BN_free);
    BN_mod_exp(dst.get(), src.get(), exponent.get(), modulus.get(), ctx.get());

    WOW_BN_bn2bin(dst, out);
}