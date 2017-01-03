#include "Module.hpp"
#include "SSignatureData.hpp"
#include "ClientKey.hpp"

#include <boost/program_options.hpp>

#include <iostream>
#include <string>
#include <cstdint>
#include <vector>

int main(int argc, char *argv[])
{
    std::string binary, key;

    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
        ("binary,b", boost::program_options::value<std::string>(&binary)->required(),   "binary file")
        ("key,k", boost::program_options::value<std::string>(&key)->required(),         "key file")
        ("help,h",                                                                      "display help message");

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
    catch (std::runtime_error const &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}