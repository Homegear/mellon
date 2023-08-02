/* Copyright 2013-2019 Homegear GmbH */

#ifndef USER_HPP_
#define USER_HPP_

#include "Mellon.hpp"

#include <vector>
#include <string>

namespace Mellon
{

class User
{
public:
    ~User();

    static bool writeAesUnlockEncryptionKey(uint8_t* key, size_t size, std::string& passphrase);
    static int32_t addPassphrase(std::string& oldPassphrase, std::string& newPassphrase, bool admin);
    static bool removePassphrase(std::string& passphrase);
    static int32_t login(std::string& passphrase);
    static bool logout();
    static bool writeServerAesEncryptionKey(uint8_t* key, size_t size);
    static bool writeDhParameters(uint8_t* data, size_t size);
    static bool writeUnlockPrivateKey(uint8_t* key, size_t size);
    static bool writeUnlockPublicKey(uint8_t* key, size_t size);
    static std::vector<uint8_t> getUnlockParameters();
    static std::vector<uint8_t> getUnlockResponse(uint8_t* request, size_t size);
    static bool unlock(uint8_t* request, size_t size);
private:
    User() = delete;

    static const std::array<uint8_t, 32> _identifier;

    static std::vector<uint8_t> parsePemPrivate(uint8_t* key, size_t size);
    static std::vector<uint8_t> parsePemPublic(uint8_t* key, size_t size);
    static std::vector<uint8_t> loadUserData(size_t slot);
};

} /* namespace Mellon */

#endif /* USER_HPP_ */
