#include "SARC4.hpp"

#include <openssl/evp.h>

#include <cstdint>
#include <vector>
#include <memory>
#include <iostream>
#include <exception>

SARC4::SARC4(const std::vector<std::uint8_t> &key) : ctx(EVP_CIPHER_CTX_new(), &::EVP_CIPHER_CTX_free)
{
    if (key.size() != ExpectedKeySize)
        std::cerr << "WARNING: Expected key length of size " << ExpectedKeySize << ".  Actual key length = " << key.size() << std::endl;

    if (!key.size())
        throw std::runtime_error("Empty SARC4 key");

    auto const ctx = this->ctx.get();

    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_rc4(), nullptr, &key[0], nullptr);
    EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size()));
}

void SARC4::Decrypt(const std::vector<std::uint8_t> &in, std::vector<std::uint8_t> &out)
{
    out.resize(in.size());
    int outSize;
    EVP_DecryptUpdate(ctx.get(), &out[0], &outSize, &in[0], static_cast<int>(in.size()));

    if (outSize != out.size())
        throw std::runtime_error("Failed to decrypt entire module");
}
