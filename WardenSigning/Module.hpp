#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cassert>

class Module
{
private:
    static constexpr size_t SignatureSize = 260;

public:
    Module(std::string const &binary, std::string const &key);


    size_t decompressedSize;
    std::vector<std::uint8_t> m_binary;
    std::vector<std::uint8_t> m_signature;
};