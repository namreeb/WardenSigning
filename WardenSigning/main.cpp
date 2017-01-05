#include "Module.hpp"
#include "SSignatureData.hpp"
#include "ClientKey.hpp"

#include <boost/program_options.hpp>

#include <iostream>
#include <string>
#include <cstdint>
#include <vector>

namespace
{
void BuildRandomData(size_t length, std::vector<std::uint8_t> &out)
{
    out.clear();
    out.reserve(length);

    // do not allow random chars to be 0, so this can also be used for random key generation
    for (auto i = 0u; i < length; ++i)
    {
        do
        {
            const std::uint8_t c = rand() & 0xFF;

            if (!c)
                continue;

            out.push_back(c);
            break;
        } while (true);
    }
}
}

int main(int argc, char *argv[])
{
    std::string binary, key, dll;

    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
        ("binary,b", boost::program_options::value<std::string>(&binary),   "binary file")
        ("key,k", boost::program_options::value<std::string>(&key),         "key file")
        ("dll,d", boost::program_options::value<std::string>(&dll),         "dll file to sign")
        ("help,h",                                                          "display help message");

    boost::program_options::variables_map vm;

    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        boost::program_options::notify(vm);
    }
    catch (boost::program_options::error const &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;

        return EXIT_FAILURE;
    }

    if (vm.count("help"))
    {
        std::cout << desc << std::endl;
        return EXIT_SUCCESS;
    }

    try
    {
        // binary/key mode?
        if (vm.count("binary") && vm.count("key") && !vm.count("dll"))
        {
            // load encrypted data and key files, and decrypt the module
            const Module module(binary, key);

            std::cout << "Loaded module.  Decompressed size = " << module.decompressedSize << " bytes." << std::endl;

            SSignatureData signatureData;

            signatureData.Update(&module.m_binary[0], module.m_binary.size());
            signatureData.Update("MAIEV.MOD");
            signatureData.Update(&module.m_signature[0], module.m_signature.size());

            if (signatureData.Verify(wardenModulus, wardenExponent))
                std::cout << "Module VERIFIED" << std::endl;
            else
                std::cout << "Module fingerprint check FAILED!" << std::endl;
        }
        // dll signing mode?
        else if (vm.count("dll") && !vm.count("binary") && !vm.count("key"))
        {
            std::cout << "Signing binary " << dll << "..." << std::endl;

            std::vector<std::uint8_t> randomData;
            BuildRandomData(29760, randomData);

            // note that the data does not need to be encrypted or decrypted.  once real DLLs are loaded here, the final
            // compressed result will be encrypted.

            SSignatureData signatureData;

            signatureData.Update(&randomData[0], randomData.size());
            signatureData.Update("MAIEV.MOD");
            
            std::vector<std::uint8_t> fingerprint;
            signatureData.BuildFingerprint(wardenModulus, wardenExponent, fingerprint);

            signatureData.Update(&fingerprint[0], fingerprint.size());

            if (signatureData.Verify(wardenModulus, wardenExponent))
                std::cout << "Module VERIFIED" << std::endl;
            else
                std::cout << "Module fingerprint check FAILED!" << std::endl;
        }
        // otherwise, invalid syntax
        else
        {
            std::cerr << "ERROR: Invalid argument combination" << std::endl;
            std::cerr << desc << std::endl;
            return EXIT_FAILURE;
        }
    }
    catch (std::runtime_error const &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}