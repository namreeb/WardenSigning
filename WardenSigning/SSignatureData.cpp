#include "SSignatureData.hpp"
#include "CryptRSA.hpp"

#include <openssl/sha.h>

#include <cstdint>
#include <vector>
#include <cstring>
#include <iostream>

#pragma comment(lib, "libcrypto.lib")

SSignatureData::SSignatureData(std::uint32_t modulusSize, std::uint32_t exponentSize) :
    modulusSize(modulusSize), exponentSize(exponentSize), magicBufferUsed(0), magicBuffer(modulusSize + 4)
{
    SHA1_Init(&sha);
}

void SSignatureData::Update(const std::uint8_t *data, size_t size)
{
    // if we are writing a 'small' chunk of data, use the buffer
    if (size < magicBuffer.size())
    {
        // how far past the end of the buffer will this go?
        auto const overrun = magicBufferUsed + size - magicBuffer.size();
        
        // if this will write past the end of the buffer, compute how much space we need to make it fit, hash that chunk, then shift the buffer
        if (overrun > 0)
        {
            // hash the data that is about to be overwritten
            SHA1_Update(&sha, &magicBuffer[0], overrun);
            magicBufferUsed -= overrun;

            // shift buffer by necessary amount
            memmove(&magicBuffer[0], &magicBuffer[overrun], magicBufferUsed);
        }

        // at this point, data is guaranteed to fit
        memcpy(&magicBuffer[magicBufferUsed], data, size);
        magicBufferUsed += size;
    }
    // otherwise, hash the existing buffer, hash the incoming data, then reset the buffer
    else
    {
        // hash whatever data we have, if any
        if (magicBufferUsed)
            SHA1_Update(&sha, &magicBuffer[0], magicBufferUsed);

        auto const overrun = size - magicBuffer.size();

        // hash whatever leftover data there would be once the buffer fills, if any.  note that this seems counter-intuitive for a streaming signature check.
        if (overrun)
            SHA1_Update(&sha, data, overrun);

        memcpy(&magicBuffer[0], &data[overrun], magicBuffer.size());
        magicBufferUsed = magicBuffer.size();
    }
}

void SSignatureData::Update(const char* string)
{
    Update(reinterpret_cast<const std::uint8_t *>(string), strlen(string));
}

void SSignatureData::BuildFingerprint(const std::uint8_t *modulus, const std::uint8_t *exponent, std::vector<std::uint8_t> &out)
{
    out.clear();
    out.resize(ModulusSize + ExponentSize);

    *reinterpret_cast<std::uint32_t *>(&out[0]) = Signature;

    std::vector<std::uint8_t> generated(modulusSize, 0xBB);
    generated[generated.size() - 1] = 0x0B;     // most significant 

    SHA1_Final(&generated[0], &sha);

    CryptRSA encoder(modulus, modulusSize, exponent, exponentSize);

    // we want to produce a BIGNUM 'a' which satisfies:
    // generated = a^exponent % modulus

    // the easiest way to do this is to compute 'a' which satisfies:
    // generated = a^exponent
    // but this only works when generated < modulus, so let's check that:

    std::cout << "generated < modulus? " << (encoder.CheckGenerated(generated) ? "true" : "false") << std::endl;
    
    // 'exponent' in this case is relatively small, with a value of: 0x10001 (65537)

    // the laws of logarithms tell us:
    // log b^a = a * log(b) ... therefore:
    // log a^exponent = exponent * log(a) = log(generated) ... therefore
    // log(a) = log(generated) / exponent
}

bool SSignatureData::Verify(const std::uint8_t *modulus, const std::uint8_t *exponent)
{
    if (!modulus)
        throw std::runtime_error("modulus == nullptr");

    if (!exponent)
        throw std::runtime_error("exponent == nullptr");

    if (magicBufferUsed != magicBuffer.size())
        return false;

    if (*reinterpret_cast<const std::uint32_t *>(&magicBuffer[0]) != Signature)
        return false;

    std::cout << "Signature check PASSED" << std::endl;

    std::vector<std::uint8_t> generated(modulusSize, 0xBB);
    generated[generated.size() - 1] = 0x0B;

    if (generated.size() < SHA_DIGEST_LENGTH)
        throw std::runtime_error("Fingerprint was too small");

    // note that at this point, the current contents of magicBuffer (the fingerprint) have NOT been (and WILL NOT be) hashed!
    SHA1_Final(&generated[0], &sha);

    CryptRSA decoder(modulus, modulusSize, exponent, exponentSize);

    std::vector<std::uint8_t> stored(modulusSize);
    memcpy(&stored[0], &magicBuffer[sizeof(std::uint32_t)], stored.size()); // offset 4 bytes into magicBuffer to skip signature

    std::vector<std::uint8_t> computed;
    decoder.Process(stored, computed);

    return !memcmp(&generated[0], &computed[0], generated.size());
}
