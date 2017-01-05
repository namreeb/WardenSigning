#pragma once

#include <openssl/sha.h>

#include <cstdint>
#include <vector>

class SSignatureData
{
private:
    static constexpr std::uint32_t ModulusSize = 256;
    static constexpr std::uint32_t ExponentSize = 4;
    static constexpr std::uint32_t Signature = 'SIGN';

public:
    explicit SSignatureData(std::uint32_t modulusSize = ModulusSize, std::uint32_t exponentSize = ExponentSize);

    void Update(const std::uint8_t *data, size_t size);
    void Update(const char *string);

    void BuildFingerprint(const std::uint8_t *modulus, const std::uint8_t *exponent, std::vector<std::uint8_t> &out);

    bool Verify(const std::uint8_t *modulus, const std::uint8_t *exponent);

    const std::uint32_t modulusSize;
    const std::uint32_t exponentSize;

    size_t magicBufferUsed;
    std::vector<std::uint8_t> magicBuffer;

    SHA_CTX sha;
};