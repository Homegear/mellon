/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_SIGN_H
#define MELLON_SIGN_H

#include "Mellon.hpp"

#include <vector>
#include <string>

#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"
#include "mbedtls/pem.h"

namespace Mellon
{

class Sign
{
public:
    Sign();
    ~Sign();

    int32_t getErrorCode() { return _errorCode; }

    bool eraseSshHostCaKeySlot(size_t slot);
    bool writeSshHostCaKeyPair(size_t slot, std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey, size_t validity);
    std::vector<uint8_t> getSshHostCaPublicKey(size_t keySlot);
    std::vector<uint8_t> signSshHost(size_t keySlot, const uint8_t* data, size_t size, const std::string& identity, const std::string& principals);

    bool eraseX509CaKeySlot(size_t slot);
    bool writeX509CaKey(size_t slot, std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey, size_t validity);
    std::vector<uint8_t> getX509CaPublicKey(size_t keySlot);
    std::vector<uint8_t> signX509Csr(size_t keySlot, const uint8_t* data, size_t size);

    bool eraseUserCaKeySlot(size_t slot);
    bool writeUserCaKeyPair(size_t slot, std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey, size_t validity);
    std::vector<uint8_t> getUserCaPublicKey(size_t keySlot);
    std::vector<uint8_t> signUser(size_t keySlot, const uint8_t* data, size_t size, const std::string& identity, const std::string& principals, uint8_t permissions, const std::string& forceCommand, const std::string& sourceAddresses);
private:
    int32_t _errorCode = 0;
    bool _issuerKeyInitialized = false;
    mbedtls_pk_context _issuerKey;
    mbedtls_x509_crt _issuerX509Cert;
    std::vector<uint8_t> _issuerSshCert;
    std::string _issuerIdent;
    size_t _validity = 0;
    mbedtls_x509_csr _csr;
    mbedtls_x509write_cert _crt;
    mbedtls_mpi _serial;

    void loadSshHostCaKeyPair(size_t slot);
    void loadX509CaKey(size_t slot);
    void loadUserCaKeyPair(size_t slot);
    std::vector<uint8_t> ecdsaSignatureToSshFormat(const uint8_t* signature, size_t signatureSize);
    std::vector<uint8_t> parsePrivatePem(uint8_t* key, size_t size);
    std::vector<uint8_t> parsePublicPem(uint8_t* key, size_t size);
};

}

#endif
