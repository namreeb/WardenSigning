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
    ctx(::BN_CTX_new(), &::BN_CTX_free), m(nullptr, &::BN_free), n(::BN_new(), &::BN_free), e(::BN_new(), &::BN_free)
{
    WOW_BN_bin2bn(modulus, modulusSize, n);
    WOW_BN_bin2bn(exponent, exponentSize, e);
}

void CryptRSA::Process(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out)
{
    m.reset(::BN_new());
    WOW_BN_bin2bn(&in[0], in.size(), m);

    std::cout << "m is " << BN_num_bits(m.get()) << " bits" << std::endl;
    std::cout << "m is " << (BN_is_prime(m.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::cout << "e is " << BN_num_bits(e.get()) << " bits" << std::endl;
    std::cout << "e is " << (BN_is_prime(e.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::cout << "n is " << BN_num_bits(n.get()) << " bits" << std::endl;
    std::cout << "n is " << (BN_is_prime(n.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::unique_ptr<BIGNUM, decltype(&::BN_free)> dst(::BN_new(), &::BN_free);
    BN_mod_exp(dst.get(), m.get(), e.get(), n.get(), ctx.get());

    WOW_BN_bn2bin(dst, out);
}

void CryptRSA::Analyze(const std::vector<std::uint8_t> &generated, std::vector<std::uint8_t> &nprime) const
{
    if (!m)
        throw std::runtime_error("m has not yet been calculated");

    // in CryptRSA::Sign() it is explained that for a validated module, the following expression is true for an unknown integer n':
    // m^e = n * n' + generated

    // the same expression, rewritten to isolate n':
    // n' = (m^e - generated) / n

    // compute n' for the current context

    PBIGNUM g(::BN_new(), &::BN_free);

    WOW_BN_bin2bn(&generated[0], generated.size(), g);

    PBIGNUM nPrime(::BN_new(), &::BN_free);

    auto const start = time(nullptr);

    BN_exp(nPrime.get(), m.get(), e.get(), ctx.get());
    BN_sub(nPrime.get(), nPrime.get(), g.get());
    BN_div(nPrime.get(), nullptr, nPrime.get(), n.get(), ctx.get());

    auto const stop = time(nullptr);

    std::vector<std::uint8_t> dbytes;
    
    std::cout << "n' is " << BN_num_bits(nPrime.get()) << " bits" << std::endl;

    std::cout << "resolving n' took " << (stop - start) << " seconds" << std::endl;

    nprime.clear();
    nprime.resize(BN_num_bytes(nPrime.get()));
    BN_bn2bin(nPrime.get(), &nprime[0]);
}

void CryptRSA::Sign(const std::vector<std::uint8_t> &generated) const
{
    // to sign our own modules, we need to produce an integer 'm' which satisfies:
    // m^e % n = generated

    // e and n are hard-coded into the client, and therefore fixed across all warden modules

    // it can be said that if a % b = c, we know there exists an integer d where:
    // a = b * d + c

    // applying this to our situation, we know there exists an integer d where:
    // m^e = n * d + generated

    // to future readers, good luck with this! trololol

    std::cout << "e is " << BN_num_bits(e.get()) << " bits" << std::endl;
    std::cout << "e is " << (BN_is_prime(e.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;

    std::cout << "n is " << BN_num_bits(n.get()) << " bits" << std::endl;
    std::cout << "n is " << (BN_is_prime(n.get(), BN_prime_checks, nullptr, ctx.get(), nullptr) ? "" : "NOT ") << "prime" << std::endl;
}
