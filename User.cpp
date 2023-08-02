/* Copyright 2013-2019 Homegear GmbH */

#include "User.hpp"
#include "Uart.hpp"
#include "Aes.hpp"
#include "Flash.hpp"
#include "Trng.hpp"
#include "Time.hpp"

#include "mbedtls/sha256.h"
#include "mbedtls/dhm.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"
#include "mbedtls/pem.h"

namespace Mellon
{

const std::array<uint8_t, 32> User::_identifier{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

bool User::writeAesUnlockEncryptionKey(uint8_t* key, size_t size, std::string& passphrase)
{
    static const size_t slot = 0;
    std::vector<uint8_t> encryptedData;
    bool returnValue = false;

    //{{{ Variables to clean up
    //uint8_t* key;
    //size_t size;
    //std::string& passphrase
    std::array<uint8_t, 32> passphraseHash;
    std::vector<uint8_t> userData;
    //}}}

    if(!Trng::randomDelay(1, 10) || size == 0 || key == nullptr || size != 32 || slot >= FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT || passphrase.size() < 10)
    {
        goto cleanup;
    }

    { //Abort when at least one passphrase exists
        bool abort = false;
        for(int32_t i = 0; i < FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT; i++)
        {
            if(!loadUserData(i).empty() && !abort) abort = true;
        }
        if(abort)
        {
            goto cleanup;
        }
    }

    if(mbedtls_sha256_ret((const uint8_t*)passphrase.c_str(), passphrase.size(), passphraseHash.data(), 0) != 0)
    {
        goto cleanup;
    }

    userData.reserve(68);
    userData.insert(userData.end(), _identifier.begin(), _identifier.end());
    userData.push_back(1); //Admin
    userData.push_back(0); //Reserved
    userData.push_back(0); //Reserved
    userData.push_back(0); //Reserved
    userData.insert(userData.end(), key, key + size);

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(passphraseHash, userData.data(), userData.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(slot, FLASH_UNLOCK_USER_PASSPHRASES_ADDRESS, FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT, FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = true;

cleanup:
    std::fill(key, key + size, 0);
    std::fill(passphrase.begin(), passphrase.end(), 0);
    std::fill(passphraseHash.begin(), passphraseHash.end(), 0);
    std::fill(userData.begin(), userData.end(), 0);
    return returnValue;
}

std::vector<uint8_t> User::loadUserData(size_t slot)
{
    if(slot >= FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT) return std::vector<uint8_t>();

    uint32_t address = FLASH_UNLOCK_USER_PASSPHRASES_ADDRESS + (slot * FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE);
    uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
    if((metadata >> 24) != 1) return std::vector<uint8_t>();
    size_t dataSize = metadata & 0xFFFF;
    if(dataSize == 0 || dataSize > FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE - 4) return std::vector<uint8_t>();
    uint8_t* data = (uint8_t*)(address + 4);

    std::vector<uint8_t> dataVector(dataSize);
    std::copy(data, data + dataSize, dataVector.begin());

    return dataVector;
}

int32_t User::addPassphrase(std::string& oldPassphrase, std::string& newPassphrase, bool admin)
{
    int32_t returnValue = -1;
    int32_t slot = -1;
    std::unique_ptr<Aes> aes = std::make_unique<Aes>();
    std::vector<uint8_t> encryptedData;

    //{{{ Variables to clean up
    //std::string oldPassphrase;
    //std::string newPassphrase;
    std::array<uint8_t, 32> oldPassphraseHash;
    std::array<uint8_t, 32> newPassphraseHash;
    std::vector<uint32_t> oldUserData;
    std::vector<uint8_t> userData;
    //}}}

    if(!Trng::randomDelay(1, 10))
    {
        goto cleanup;
    }

    for(int32_t i = 0; i < FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT; i++)
    {
        if(loadUserData(i).empty() && slot == -1) slot = i;
    }

    if(slot >= FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT || slot < 0 || oldPassphrase.size() < 10 || newPassphrase.size() < 10)
    {
        goto cleanup;
    }

    if(mbedtls_sha256_ret((const uint8_t*)oldPassphrase.c_str(), oldPassphrase.size(), oldPassphraseHash.data(), 0) != 0)
    {
        goto cleanup;
    }

    if(mbedtls_sha256_ret((const uint8_t*)newPassphrase.c_str(), newPassphrase.size(), newPassphraseHash.data(), 0) != 0)
    {
        goto cleanup;
    }

    {
        bool alreadyExists = false;
        for(int32_t i = 0; i < FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT; i++)
        {
            auto userDataTemp = loadUserData(i);
            auto decryptedData = aes->decrypt(oldPassphraseHash, userDataTemp.data(), userDataTemp.size());
            auto decryptedData2 = aes->decrypt(newPassphraseHash, userDataTemp.data(), userDataTemp.size());
            if(!decryptedData2.empty() && std::equal(_identifier.begin(), _identifier.end(), decryptedData2.begin()))
            {
                alreadyExists = true;
            }
            if(!decryptedData.empty() && std::equal(_identifier.begin(), _identifier.end(), decryptedData.begin()) && oldUserData.empty() && (decryptedData.at(_identifier.size()) & 1))
            {
                oldUserData.insert(oldUserData.end(), decryptedData.begin(), decryptedData.end());
            }
            std::fill(decryptedData.begin(), decryptedData.end(), 0);
            std::fill(decryptedData2.begin(), decryptedData2.end(), 0);
        }
        if(oldUserData.empty() || alreadyExists)
        {
            goto cleanup;
        }
    }

    userData.reserve(68);
    userData.insert(userData.end(), _identifier.begin(), _identifier.end());
    userData.push_back((uint8_t)admin); //Admin
    userData.push_back(0); //Reserved
    userData.push_back(0); //Reserved
    userData.push_back(0); //Reserved
    userData.insert(userData.end(), oldUserData.begin() + 36, oldUserData.end());

    encryptedData = aes->encrypt(newPassphraseHash, userData.data(), userData.size());
    if(encryptedData.empty())
    {
        goto cleanup;
    }

    if(!Flash::writeSlot(slot, FLASH_UNLOCK_USER_PASSPHRASES_ADDRESS, FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT, FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = slot;

cleanup:
    std::fill(oldPassphrase.begin(), oldPassphrase.end(), 0);
    std::fill(newPassphrase.begin(), newPassphrase.end(), 0);
    std::fill(oldPassphraseHash.begin(), oldPassphraseHash.end(), 0);
    std::fill(newPassphraseHash.begin(), newPassphraseHash.end(), 0);
    std::fill(oldUserData.begin(), oldUserData.end(), 0);
    std::fill(userData.begin(), userData.end(), 0);

    return returnValue;
}

bool User::removePassphrase(std::string& passphrase)
{
    bool returnValue = false;
    int32_t slot = -1;
    std::unique_ptr<Aes> aes = std::make_unique<Aes>();

    //{{{ Variables to clean up
    //std::string passphrase;
    std::array<uint8_t, 32> passphraseHash;
    //}}}

    if(!Trng::randomDelay(1, 10))
    {
        goto cleanup;
    }

    if(passphrase.size() < 10)
    {
        goto cleanup;
    }

    if(mbedtls_sha256_ret((const uint8_t*)passphrase.c_str(), passphrase.size(), passphraseHash.data(), 0) != 0)
    {
        goto cleanup;
    }

    for(int32_t i = 0; i < FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT; i++)
    {
        auto userData = loadUserData(i);
        auto decryptedData = aes->decrypt(passphraseHash, userData.data(), userData.size());
        if(!decryptedData.empty() && std::equal(_identifier.begin(), _identifier.end(), decryptedData.begin()) && slot == -1)
        {
            slot = i;
        }
        std::fill(decryptedData.begin(), decryptedData.end(), 0);
    }
    if(slot == -1)
    {
        goto cleanup;
    }

    returnValue = Flash::eraseSlot(slot, FLASH_UNLOCK_USER_PASSPHRASES_ADDRESS, FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT, FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE);

cleanup:
    std::fill(passphrase.begin(), passphrase.end(), 0);
    std::fill(passphraseHash.begin(), passphraseHash.end(), 0);

    return returnValue;
}

int32_t User::login(std::string& passphrase)
{
    int32_t returnValue = -1;
    int32_t slot = -1;
    std::unique_ptr<Aes> aes = std::make_unique<Aes>();

    //{{{ Variables to clean up
    //std::string passphrase;
    std::array<uint8_t, 32> passphraseHash;
    //}}}

    if(!Trng::randomDelay(1, 10))
    {
        goto cleanup;
    }

    if(passphrase.size() < 10)
    {
        goto cleanup;
    }


    if(mbedtls_sha256_ret((const uint8_t*)passphrase.c_str(), passphrase.size(), passphraseHash.data(), 0) != 0)
    {
        goto cleanup;
    }

    logout();
    for(int32_t i = 0; i < FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT; i++)
    {
        auto userData = loadUserData(i);
        auto decryptedData = aes->decrypt(passphraseHash, userData.data(), userData.size());
        if(!decryptedData.empty() && std::equal(_identifier.begin(), _identifier.end(), decryptedData.begin()) && !GD::loggedIn)
        {
            std::copy(decryptedData.begin() + 36, decryptedData.end(), GD::unlockKey.begin());
            GD::adminMode = (decryptedData.at(_identifier.size()) & 1);
            GD::loggedIn = true;
            slot = i;
        }
        std::fill(decryptedData.begin(), decryptedData.end(), 0);
    }

    returnValue = slot;

cleanup:
    std::fill(passphrase.begin(), passphrase.end(), 0);
    std::fill(passphraseHash.begin(), passphraseHash.end(), 0);

    return returnValue;
}

bool User::logout()
{
    std::fill(GD::encryptionKey.begin(), GD::encryptionKey.end(), 0);
    GD::encryptionKeySet = false;
    std::fill(GD::unlockKey.begin(), GD::unlockKey.end(), 0);
    if(GD::dhParams.len > 0) mbedtls_dhm_free(&GD::dhParams);
    GD::adminMode = false;
    bool returnValue = GD::loggedIn;
    GD::loggedIn = false;
    return returnValue;
}

bool User::writeServerAesEncryptionKey(uint8_t* key, size_t size)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    if(size == 0 || key == nullptr || size != 32 || !GD::loggedIn || !GD::adminMode)
    {
        goto cleanup;
    }

    {
        int32_t keySum = 0;
        for(auto byte : GD::unlockKey)
        {
            keySum += byte;
        }
        if(keySum == 0)
        {
            goto cleanup;
        }
    }

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::unlockKey, key, size);
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(0, FLASH_SERVER_ENCRYPTION_KEY_ADDRESS, FLASH_SERVER_ENCRYPTION_KEY_SLOT_COUNT, FLASH_SERVER_ENCRYPTION_KEY_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = true;

cleanup:
    std::fill(key, key + size, 0);
    return returnValue;
}

bool User::writeDhParameters(uint8_t* data, size_t size)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    //{{{ Variables to clean up
    //uint8_t* data;
    std::vector<uint8_t> mpiBuffer;
    //}}}

    if(data == nullptr || size == 0)
    {
        goto cleanup;
    }

    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);

    if(mbedtls_dhm_parse_dhm(&dhm, data, size) != 0)
    {
        goto cleanup;
    }

    if(dhm.len > DHPARAMS_MAX_SIZE)
    {
        goto cleanup;
    }

    {
        size_t plen = dhm.P.n * sizeof(mbedtls_mpi_uint); //sizeof(mbedtls_mpi_uint) is equivalent to ciL
        size_t glen = dhm.G.n * sizeof(mbedtls_mpi_uint); //sizeof(mbedtls_mpi_uint) is equivalent to ciL
        mpiBuffer.resize(2 + plen + 2 + glen, 0);
        I16_TO_U8CARRAY(mpiBuffer, 0, plen);
        if(mbedtls_mpi_write_binary(&dhm.P, mpiBuffer.data() + 2, plen) != 0)
        {
            goto cleanup;
        }

        I16_TO_U8CARRAY(mpiBuffer, 2 + plen, glen);
        if(mbedtls_mpi_write_binary(&dhm.G, mpiBuffer.data() + 2 + plen + 2, glen) != 0)
        {
            goto cleanup;
        }
    }

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::unlockKey, mpiBuffer.data(), mpiBuffer.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(0, FLASH_DH_PARAMS_ADDRESS, FLASH_DH_PARAMS_SLOT_COUNT, FLASH_DH_PARAMS_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = true;

cleanup:
    mbedtls_dhm_free(&dhm);

    std::fill(data, data + size, 0);
    std::fill(mpiBuffer.begin(), mpiBuffer.end(), 0);

    return returnValue;
}

std::vector<uint8_t> User::parsePemPrivate(uint8_t* key, size_t size)
{
    int ret = 0;
    size_t lengthOutput = 0;
    mbedtls_pem_context pem;
    std::vector<uint8_t> buffer;

    if(size == 0 || key == nullptr) return buffer;

    mbedtls_pem_init(&pem);

    if(key[size - 1] != '\0') return buffer;

    ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", key, nullptr, 0, &lengthOutput);
    if(ret == 0)
    {
        buffer = std::vector<uint8_t>(pem.buf, pem.buf + pem.buflen);
        mbedtls_pem_free(&pem);
        return buffer;
    }
    else if(ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH ||
            ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED ||
            ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
    {
        mbedtls_pem_free(&pem);
        return buffer;
    }

    ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", key, nullptr, 0, &lengthOutput);
    if(ret == 0)
    {
        buffer = std::vector<uint8_t>(pem.buf, pem.buf + pem.buflen);
        mbedtls_pem_free(&pem);
        return buffer;
    }
    else if(ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH ||
                ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED ||
                ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
    {
        mbedtls_pem_free(&pem);
        return buffer;
    }

    ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", key, nullptr, 0, &lengthOutput);
    if(ret == 0)
    {
        buffer = std::vector<uint8_t>(pem.buf, pem.buf + pem.buflen);
        mbedtls_pem_free(&pem);
        return buffer;
    }
    else if(ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
    {
        mbedtls_pem_free(&pem);
        return buffer;
    }

    mbedtls_pem_free(&pem);
    return buffer;
}

std::vector<uint8_t> User::parsePemPublic(uint8_t* key, size_t size)
{
    int ret = 0;
    size_t lengthOutput = 0;
    mbedtls_pem_context pem;
    std::vector<uint8_t> buffer;

    if(size == 0 || key == nullptr) return buffer;

    mbedtls_pem_init(&pem);

    if(key[size - 1] != '\0') return buffer;

    ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----", key, nullptr, 0, &lengthOutput);
    if(ret == 0)
    {
        buffer = std::vector<uint8_t>(pem.buf, pem.buf + pem.buflen);
        mbedtls_pem_free(&pem);
        return buffer;
    }
    else if(ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
    {
        mbedtls_pem_free(&pem);
        return buffer;
    }

    ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", key, nullptr, 0, &lengthOutput);
    if(ret == 0)
    {
        buffer = std::vector<uint8_t>(pem.buf, pem.buf + pem.buflen);
        mbedtls_pem_free(&pem);
        return buffer;
    }
    else if(ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
    {
        mbedtls_pem_free(&pem);
        return buffer;
    }

    mbedtls_pem_free(&pem);
    return buffer;
}

bool User::writeUnlockPrivateKey(uint8_t* key, size_t size)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    //{{{ Variables to clean up
    //uint8_t* key;
    std::vector<uint8_t> derKey;
    //}}}

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    if(size == 0 || key == nullptr || size > MAX_PEM_KEY_SIZE)
    {
        goto cleanup;
    }

    derKey = parsePemPrivate(key, size);
    if(derKey.empty())
    {
        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&pk, key, size, nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
    }
    else
    {
        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&pk, derKey.data(), derKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
    }
    if(mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA || mbedtls_pk_get_len(&pk) > 512)
    {
        goto cleanup;
    }
    mbedtls_pk_free(&pk);

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::unlockKey, derKey.data(), derKey.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(0, FLASH_UNLOCK_PRIVATE_KEY_ADDRESS, FLASH_UNLOCK_PRIVATE_KEY_SLOT_COUNT, FLASH_UNLOCK_PRIVATE_KEY_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = true;

cleanup:
    mbedtls_pk_free(&pk);
    std::fill(key, key + size, 0);
    std::fill(derKey.begin(), derKey.end(), 0);
    return returnValue;
}

bool User::writeUnlockPublicKey(uint8_t* key, size_t size)
{
    if(size == 0 || key == nullptr || size > MAX_PEM_KEY_SIZE) return false;

    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    //{{{ Variables to clean up
    //uint8_t* key;
    std::vector<uint8_t> derKey;
    //}}}

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    derKey = parsePemPublic(key, size);
    if(derKey.empty())
    {
        if(mbedtls_pk_parse_public_key(&pk, key, size) != 0)
        {
            goto cleanup;
        }
    }
    else
    {
        if(mbedtls_pk_parse_public_key(&pk, derKey.data(), derKey.size()) != 0)
        {
            goto cleanup;
        }
    }
    if(mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA || mbedtls_pk_get_len(&pk) > 512)
    {
        goto cleanup;
    }


    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::unlockKey, derKey.data(), derKey.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(0, FLASH_UNLOCK_PUBLIC_KEY_ADDRESS, FLASH_UNLOCK_PUBLIC_KEY_SLOT_COUNT, FLASH_UNLOCK_PUBLIC_KEY_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = true;

cleanup:
    mbedtls_pk_free(&pk);
    std::fill(key, key + size, 0);
    std::fill(derKey.begin(), derKey.end(), 0);
    return returnValue;
}

std::vector<uint8_t> User::getUnlockParameters()
{
    if(!Trng::isReady()) return std::vector<uint8_t>();

    size_t minBufferSize = 0;
    size_t signatureSize = 0;
    size_t dhmPrimeSize = 0;
    std::vector<uint8_t> output;

    //{{{ Variables to clean up
    std::vector<uint8_t> decryptedData;
    auto buffer = std::make_unique<std::vector<uint8_t>>();
    std::array<uint8_t, MBEDTLS_MPI_MAX_SIZE> signature;
    //}}}

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_dhm_free(&GD::dhParams);
    mbedtls_dhm_init(&GD::dhParams);

    { //Read private key
        uint32_t address = FLASH_UNLOCK_PRIVATE_KEY_ADDRESS;
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* key = nullptr;
        size_t keySize = 0;
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        if((metadata >> 24) != 1)
        {
            GD::uart->sendOutput("Error: No private key set. Please write one to this Mellon.");
            goto cleanup;
        }
        keySize = metadata & 0xFFFF;
        if(keySize == 0 || keySize > FLASH_UNLOCK_PRIVATE_KEY_SLOT_SIZE - 4)
        {
            goto cleanup;
        }
        key = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::unlockKey, key, keySize);

        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&pk, decryptedData.data(), decryptedData.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }

        std::fill(decryptedData.begin(), decryptedData.end(), 0);
    }

    { //Read Diffie-Hellman parameters
        uint32_t address = FLASH_DH_PARAMS_ADDRESS;
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* params = nullptr;
        size_t paramsSize = 0;
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        if((metadata >> 24) != 1)
        {
            GD::uart->sendOutput("Error: No Diffie-Hellman parameters set. Please write them to this Mellon.");
            goto cleanup;
        }
        paramsSize = metadata & 0xFFFF;
        if(paramsSize == 0 || paramsSize > FLASH_DH_PARAMS_SLOT_SIZE - 4)
        {
            goto cleanup;
        }
        params = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::unlockKey, params, paramsSize);

        size_t plen = U8VECTOR_TO_I16(decryptedData, 0);
        size_t glen = U8VECTOR_TO_I16(decryptedData, 2 + plen);
        if(mbedtls_mpi_read_binary(&GD::dhParams.P, decryptedData.data() + 2, plen) != 0 ||
           mbedtls_mpi_read_binary(&GD::dhParams.G, decryptedData.data() + 2 + plen, glen) != 0)
        {
            goto cleanup;
        }

        dhmPrimeSize = decryptedData.size() - 1;
        std::fill(decryptedData.begin(), decryptedData.end(), 0);
    }

    minBufferSize = (dhmPrimeSize * 2) + 1 + 6; //From the documentation: "This must be a writable buffer of sufficient size to hold the reduced binary presentation of the modulus, the generator and the public key, each wrapped with a 2-byte length field." The public key is never larger than the modulus.
    minBufferSize += 128; //Add a little more space just to be on the safe side.
    buffer->resize(minBufferSize, 0);

    { //Setup the Diffie-Hellman parameters
        GD::uart->sendOutput("Setting up Diffie-Hellman parameters...");
        size_t paramsLength = 0;
        if(mbedtls_dhm_make_params(&GD::dhParams, (int)mbedtls_mpi_size(&GD::dhParams.P), buffer->data(), &paramsLength, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
        buffer->resize(paramsLength);
    }

    { //Sign the parameters
        GD::uart->sendOutput("Hashing Diffie-Hellman parameters...");
        std::array<uint8_t, 32> digest;
        if(mbedtls_sha256_ret(buffer->data(), buffer->size(), digest.data(), 0) != 0)
        {
            goto cleanup;
        }

        GD::uart->sendOutput("Signing Diffie-Hellman parameters...");
        if(mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, digest.data(), digest.size(), signature.data(), &signatureSize, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }

        std::fill(digest.begin(), digest.end(), 0);
    }

    output.reserve(4 + buffer->size() + 2 + signatureSize);
    I16_TO_U8VECTOR(output, 2 + buffer->size() + 2 + signatureSize);
    I16_TO_U8VECTOR(output, buffer->size());
    output.insert(output.end(), buffer->begin(), buffer->end());
    I16_TO_U8VECTOR(output, signatureSize);
    output.insert(output.end(), signature.begin(), signature.begin() + signatureSize);

    GD::dhParamsGenerationTime = Time::get();

cleanup:
    mbedtls_pk_free(&pk);
    if(output.empty()) mbedtls_dhm_free(&GD::dhParams);
    std::fill(decryptedData.begin(), decryptedData.end(), 0);
    std::fill(buffer->begin(), buffer->end(), 0);
    std::fill(signature.begin(), signature.end(), 0);

    return output;
}

std::vector<uint8_t> User::getUnlockResponse(uint8_t* request, size_t size)
{
    bool finished = false;
    size_t dhParamsSize = 0;
    size_t signatureSize = 0;
    size_t bufferPos = 0;
    bool valid = false;
    static const size_t secretRandomBytesSize = 32;

    //{{{ Variables to clean up
    //uint8_t* request;
    std::vector<uint8_t> encryptedData;
    std::vector<uint8_t> decryptedData;
    std::vector<uint8_t> output;
    std::vector<uint8_t> publicValue;
    std::array<uint8_t, 32> sharedSecret;
    std::array<uint8_t, 32> serverEncryptionKey;
    //}}}

    mbedtls_pk_context pk;
    mbedtls_dhm_context dhm;
    mbedtls_pk_init(&pk);
    mbedtls_dhm_init(&dhm);

    auto secretRandomBytes = Trng::generateRandomBytes(secretRandomBytesSize, valid);
    if(!valid)
    {
        goto cleanup;
    }

    if(request == nullptr || size == 0 || !Trng::isReady())
    {
        goto cleanup;
    }

    { //Read public key
        uint32_t address = FLASH_UNLOCK_PUBLIC_KEY_ADDRESS;
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        size_t dataSize = 0;
        uint8_t* data = nullptr;
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        if((metadata >> 24) != 1)
        {
            GD::uart->sendOutput("Error: No public key set. Please write one to this Mellon...");
            goto cleanup;
        }
        dataSize = metadata & 0xFFFF;
        if(dataSize == 0 || dataSize > FLASH_UNLOCK_PUBLIC_KEY_SLOT_SIZE - 4)
        {
            goto cleanup;
        }
        data = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::unlockKey, data, dataSize);

        if(mbedtls_pk_parse_public_key(&pk, decryptedData.data(), decryptedData.size()) != 0 || mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA)
        {
            goto cleanup;
        }

        std::fill(decryptedData.begin(), decryptedData.end(), 0);
        decryptedData.clear();
        decryptedData.shrink_to_fit();
    }

    { //Verify sizes
        size_t requestSize = U8CARRAY_TO_I16(request, size, 0);
        if(requestSize != size - 2 || 4 > size)
        {
            goto cleanup;
        }

        dhParamsSize = U8CARRAY_TO_I16(request, size, 2);
        if(4 + dhParamsSize + 2 > size)
        {
            goto cleanup;
        }
        signatureSize = U8CARRAY_TO_I16(request, size, 4 + dhParamsSize);
        if(4 + dhParamsSize + 2 + signatureSize > size)
        {
            goto cleanup;
        }
    }

    { //Read DH params from request
        GD::uart->sendOutput("Reading Diffie-Hellman parameters...");
        uint8_t* requestPointer = request + 4;
        if(mbedtls_dhm_read_params(&dhm, &requestPointer, request + 4 + dhParamsSize) != 0)
        {
            goto cleanup;
        }

        if(dhm.len < 64 || dhm.len > DHPARAMS_MAX_SIZE)
        {
            goto cleanup;
        }
    }

    { //Verify signature
        GD::uart->sendOutput("Verifying signature of Diffie-Hellman parameters...");
        std::array<uint8_t, 32> digest;
        if(mbedtls_sha256_ret(request + 4, dhParamsSize, digest.data(), 0) != 0)
        {
            goto cleanup;
        }

        if(mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest.data(), digest.size(), request + 4 + dhParamsSize + 2, signatureSize) != 0)
        {
            goto cleanup;
        }
    }

    //Request fully read, overwrite with 0
    std::fill(request, request + size, 0);

    publicValue.resize(dhm.len + 2, 0); //From the documentation: "This must be at least equal to ctx->len (the size of P)." (ctx->len is dhm.len) plus two length bytes.
    { //Get public value (needs to be send to server Mellon)
        GD::uart->sendOutput("Generating public Diffie-Hellman value...");
        if(mbedtls_dhm_make_public(&dhm, (int)dhm.len, publicValue.data() + 2, publicValue.size() - 2, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
        I16_TO_U8CARRAY(publicValue, 0, dhm.len);
    }

    { //Derive the shared secret
        GD::uart->sendOutput("Deriving shared secret...");
        //From the documentation: "This must be at least the size of ctx->len (the size of P)." (ctx->len is dhm.len). Add 32 bytes for random value.
        auto sharedSecretBuffer = std::make_unique<std::vector<uint8_t>>(dhm.len + secretRandomBytesSize, 0);
        std::copy(secretRandomBytes.begin(), secretRandomBytes.begin() + secretRandomBytesSize, sharedSecretBuffer->begin());
        size_t bytesWritten = 0;
        if(mbedtls_dhm_calc_secret(&dhm, sharedSecretBuffer->data() + secretRandomBytesSize, sharedSecretBuffer->size() - secretRandomBytesSize, &bytesWritten, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
        int ret = mbedtls_sha256_ret(sharedSecretBuffer->data(), bytesWritten + secretRandomBytesSize, sharedSecret.data(), 0);
        if(ret != 0)
        {
            goto cleanup;
        }
        std::fill(sharedSecretBuffer->begin(), sharedSecretBuffer->end(), 0);
    }

    //Diffie-Hellman operations are completed, free memory
    mbedtls_dhm_free(&dhm);

    { //Read server encryption key
        uint32_t address = FLASH_SERVER_ENCRYPTION_KEY_ADDRESS;
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* data = nullptr;
        size_t dataSize = 0;
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        if((metadata >> 24) != 1)
        {
            GD::uart->sendOutput("Error: No server encryption key set. Please set one and try again.");
            goto cleanup;
        }
        dataSize = metadata & 0xFFFF;
        if(dataSize == 0 || dataSize > FLASH_SERVER_ENCRYPTION_KEY_SLOT_SIZE - 4)
        {
            goto cleanup;
        }
        data = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::unlockKey, data, dataSize);

        if(decryptedData.size() != 32)
        {
            goto cleanup;
        }

        std::copy(decryptedData.begin(), decryptedData.end(), serverEncryptionKey.begin());
        std::fill(decryptedData.begin(), decryptedData.end(), 0);
        decryptedData.clear();
        decryptedData.shrink_to_fit();
    }

    { //Encrypt data with shared secret
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(sharedSecret, serverEncryptionKey.begin(), serverEncryptionKey.size());
        std::fill(sharedSecret.begin(), sharedSecret.end(), 0);
        std::fill(serverEncryptionKey.begin(), serverEncryptionKey.end(), 0);
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    publicValue.reserve(publicValue.size() + 2 + secretRandomBytesSize + 2 + encryptedData.size());
    I16_TO_U8VECTOR(publicValue, secretRandomBytesSize);
    publicValue.insert(publicValue.end(), secretRandomBytes.begin(), secretRandomBytes.begin() + secretRandomBytesSize);
    I16_TO_U8VECTOR(publicValue, encryptedData.size());
    publicValue.insert(publicValue.end(), encryptedData.begin(), encryptedData.end());

    output.resize(2048, 0);
    bufferPos = 0;
    {
        GD::uart->sendOutput("Encrypting response...");
        size_t maxBlockSize = mbedtls_pk_get_len(&pk) - 12;
        for(int32_t i = 0; i < publicValue.size(); i += maxBlockSize)
        {
            if(bufferPos + 2 >= output.size())
            {
                goto cleanup;
            }
            size_t bytesWritten = 0;
            size_t publicValueSize = (i + maxBlockSize > publicValue.size()) ? publicValue.size() - i : maxBlockSize;
            if(mbedtls_pk_encrypt(&pk, publicValue.data() + i, publicValueSize, output.data() + bufferPos + 2, &bytesWritten, output.size() - bufferPos - 2, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
            {
                goto cleanup;
            }
            I16_TO_U8CARRAY(output, bufferPos, bytesWritten);
            bufferPos += bytesWritten + 2;
        }
    }

    output.resize(bufferPos);
    finished = true;

cleanup:
    mbedtls_dhm_free(&dhm);
    mbedtls_pk_free(&pk);
    if(!finished)
    {
        std::fill(output.begin(), output.end(), 0);
        output.clear();
    }
    std::fill(request, request + size, 0);
    std::fill(encryptedData.begin(), encryptedData.end(), 0);
    std::fill(decryptedData.begin(), decryptedData.end(), 0);
    std::fill(publicValue.begin(), publicValue.end(), 0);
    std::fill(sharedSecret.begin(), sharedSecret.end(), 0);
    std::fill(serverEncryptionKey.begin(), serverEncryptionKey.end(), 0);

    return output;
}

bool User::unlock(uint8_t* request, size_t size)
{
    static const size_t secretRandomBytesSize = 32;
    size_t blockPos = 0;
    size_t blockSize = 0;
    std::vector<uint8_t> output;

    //{{{ Variables to clean up
    //uint8_t* request;
    std::vector<uint8_t> decryptedData;
    std::vector<uint8_t> decryptedRequest;
    std::vector<uint8_t> secretRandomBytes;
    std::array<uint8_t, 32> sharedSecret;
    //}}}

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    if(request == nullptr || size == 0 || !Trng::isReady() || GD::dhParams.len == 0)
    {
        goto cleanup;
    }

    GD::encryptionKeySet = false;
    std::fill(GD::encryptionKey.begin(), GD::encryptionKey.end(), 0);

    { //Read private key
        uint32_t address = FLASH_UNLOCK_PRIVATE_KEY_ADDRESS;
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* key = nullptr;
        size_t keySize = 0;
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        if((metadata >> 24) != 1)
        {
            goto cleanup;
        }
        keySize = metadata & 0xFFFF;
        if(keySize == 0 || keySize > FLASH_UNLOCK_PRIVATE_KEY_SLOT_SIZE - 4)
        {
            goto cleanup;
        }
        key = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::unlockKey, key, keySize);

        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&pk, decryptedData.data(), decryptedData.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }

        std::fill(decryptedData.begin(), decryptedData.end(), 0);
    }

    { //Decrypt data
        GD::uart->sendOutput("Decrypting response...");
        decryptedRequest.resize(size, 0);
        size_t inPos = 0;
        size_t outPos = 0;
        size_t bytesWritten = 0;
        while(inPos < size)
        {
            blockSize = U8CARRAY_TO_I16(request, size, inPos);
            inPos += 2;
            if(inPos + blockSize > size)
            {
                goto cleanup;
            }
            if(mbedtls_pk_decrypt(&pk, request + inPos, blockSize, decryptedRequest.data() + outPos, &bytesWritten, decryptedRequest.size() - outPos, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
            {
                goto cleanup;
            }
            inPos += blockSize;
            outPos += bytesWritten;
        }
    }

    //PK operations are completed, free memory
    mbedtls_pk_free(&pk);

    { //Read user Mellon's public value
        GD::uart->sendOutput("Reading public Diffie-Hellman value...");
        blockSize = U8VECTOR_TO_I16(decryptedRequest, blockPos);
        blockPos += 2;
        if(blockPos + blockSize > decryptedRequest.size())
        {
            goto cleanup;
        }
        if(mbedtls_dhm_read_public(&GD::dhParams, decryptedRequest.data() + blockPos, blockSize) != 0)
        {
            goto cleanup;
        }
        blockPos += blockSize;
    }

    { //Get random bytes
        blockSize = U8VECTOR_TO_I16(decryptedRequest, blockPos);
        blockPos += 2;
        if(blockSize != secretRandomBytesSize || blockPos + blockSize > decryptedRequest.size())
        {
            goto cleanup;
        }
        secretRandomBytes.insert(secretRandomBytes.end(), decryptedRequest.begin() + blockPos, decryptedRequest.begin() + blockPos + blockSize);
        blockPos += blockSize;
    }

    { //Derive shared secret
        GD::uart->sendOutput("Deriving shared secret...");
        //From the documentation: "This must be at least the size of ctx->len (the size of P)." (ctx->len is dhm.len). Add 32 bytes for random value.
        auto sharedSecretBuffer = std::make_unique<std::vector<uint8_t>>(GD::dhParams.len + secretRandomBytesSize, 0);
        std::copy(secretRandomBytes.begin(), secretRandomBytes.begin() + secretRandomBytesSize, sharedSecretBuffer->begin());
        size_t bytesWritten = 0;
        if(mbedtls_dhm_calc_secret(&GD::dhParams, sharedSecretBuffer->data() + secretRandomBytesSize, sharedSecretBuffer->size() - secretRandomBytesSize, &bytesWritten, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
        int ret = mbedtls_sha256_ret(sharedSecretBuffer->data(), bytesWritten + secretRandomBytesSize, sharedSecret.data(), 0);
        if(ret != 0)
        {
            goto cleanup;
        }
        std::fill(sharedSecretBuffer->begin(), sharedSecretBuffer->end(), 0);
    }

    //Diffie-Hellman operations are completed, free memory
    mbedtls_dhm_free(&GD::dhParams);

    { //Decrypt server encryption key
        blockSize = U8VECTOR_TO_I16(decryptedRequest, blockPos);
        blockPos += 2;
        if(blockPos + blockSize > decryptedRequest.size())
        {
            goto cleanup;
        }
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        decryptedData = aes->decrypt(sharedSecret, decryptedRequest.data() + blockPos, blockSize);
        std::copy(decryptedData.begin(), decryptedData.end(), GD::encryptionKey.begin());
        std::fill(decryptedData.begin(), decryptedData.end(), 0);
    }

    GD::encryptionKeySet = true;
cleanup:
    std::fill(request, request + size, 0);
    std::fill(decryptedData.begin(), decryptedData.end(), 0);
    std::fill(decryptedRequest.begin(), decryptedRequest.end(), 0);
    std::fill(secretRandomBytes.begin(), secretRandomBytes.end(), 0);
    std::fill(sharedSecret.begin(), sharedSecret.end(), 0);

    mbedtls_dhm_free(&GD::dhParams);
    mbedtls_pk_free(&pk);

    return GD::encryptionKeySet;
}

} /* namespace Mellon */
