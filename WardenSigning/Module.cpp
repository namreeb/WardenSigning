#include "Module.hpp"
#include "SARC4.hpp"

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <exception>

Module::Module(std::string const &binary, std::string const &key)
{
    std::ifstream b(binary, std::ios::binary | std::ios::ate);
    if (b.tellg() < SignatureSize + 4)
        throw std::runtime_error("Warden module too small.  Must be at least 264 bytes.");

    std::vector<std::uint8_t> encrypted(b.tellg());
    b.seekg(0, std::ios::beg);

    if (!b.read(reinterpret_cast<char *>(&encrypted[0]), encrypted.size()))
        throw std::runtime_error("Failed to open: " + binary);

    b.close();

    // some (all?) of the key files are 20 bytes instead of 16.
    // this seems to be because the first four bytes specify the modules encrypted length.
    // therefore, use the last 16 bytes
    std::ifstream k(key, std::ios::binary | std::ios::ate);

    if (k.tellg() < 16)
        throw std::runtime_error("Key file " + key + " is too small!");

    std::vector<std::uint8_t> keyData(16);
    k.seekg(-16, std::ios::end);

    if (!k.read(reinterpret_cast<char *>(&keyData[0]), keyData.size()))
        throw std::runtime_error("Failed to open " + key);

    k.close();

    SARC4 rc4(keyData);

    std::vector<std::uint8_t> decrypted;
    rc4.Decrypt(encrypted, decrypted);

    decompressedSize = static_cast<size_t>(*reinterpret_cast<std::uint32_t *>(&decrypted[0]));

    m_binary.resize(decrypted.size() - SignatureSize);
    memcpy(&m_binary[0], &decrypted[0], m_binary.size());

    m_signature.resize(SignatureSize);
    memcpy(&m_signature[0], &decrypted[m_binary.size()], m_signature.size());
}