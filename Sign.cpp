/* Copyright 2013-2019 Homegear GmbH */

#include "Sign.hpp"

#include "Flash.hpp"
#include "Uart.hpp"
#include "Trng.hpp"
#include "Time.hpp"
#include "Aes.hpp"

#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#include <string>
#include <ctime>

namespace Mellon
{

Sign::Sign()
{
    mbedtls_pk_init(&_issuerKey);
    mbedtls_x509_crt_init(&_issuerX509Cert);
    mbedtls_x509_csr_init(&_csr);
    mbedtls_x509write_crt_init(&_crt);
    mbedtls_mpi_init(&_serial);
}

Sign::~Sign()
{
    mbedtls_pk_free(&_issuerKey);
    mbedtls_x509_crt_free(&_issuerX509Cert);
    mbedtls_x509_csr_free(&_csr);
    mbedtls_x509write_crt_free(&_crt);
    mbedtls_mpi_free(&_serial);
}

std::vector<uint8_t> Sign::parsePrivatePem(uint8_t* key, size_t size)
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

std::vector<uint8_t> Sign::parsePublicPem(uint8_t* key, size_t size)
{
    int ret = 0;
    size_t lengthOutput = 0;
    mbedtls_pem_context pem;
    std::vector<uint8_t> buffer;

    if(size == 0 || key == nullptr) return buffer;

    mbedtls_pem_init(&pem);

    if(key[size - 1] != '\0') return buffer;

    ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", key, nullptr, 0, &lengthOutput);
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

    mbedtls_pem_free(&pem);
    return buffer;
}

void Sign::loadSshHostCaKeyPair(size_t slot)
{
    size_t keySize = 0;
    size_t certSize = 0;
    int32_t identSize = 0;

    //{{{ Variables to clean up
    std::vector<uint8_t> decryptedData;
    //}}}

    mbedtls_pk_free(&_issuerKey);
    mbedtls_pk_init(&_issuerKey);

    if(slot >= FLASH_SSH_HOST_CA_SLOT_COUNT || !GD::loggedIn || !GD::encryptionKeySet) goto cleanup;

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        uint32_t address = FLASH_SSH_HOST_CA_ADDRESS + (slot * FLASH_SSH_HOST_CA_SLOT_SIZE);
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* data = nullptr;
        size_t dataSize = 0;
        if((metadata >> 24) != 1) goto cleanup;
        dataSize = metadata & 0xFFFF;
        if(dataSize < 2 || dataSize > FLASH_SSH_HOST_CA_SLOT_SIZE - 4) goto cleanup;
        data = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::encryptionKey, data, dataSize);
    }

    if(2 > decryptedData.size()) goto cleanup;
    keySize = U8VECTOR_TO_I16(decryptedData, 0);
    if(2 + keySize > decryptedData.size()) goto cleanup;
    //Note that f_rng and p_rng were added by us to support TRNG.
    if(mbedtls_pk_parse_key(&_issuerKey, decryptedData.data() + 2, keySize, nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0) goto cleanup;

    if(2 + keySize + 2 > decryptedData.size()) goto cleanup;
    certSize = U8VECTOR_TO_I16(decryptedData, 2 + keySize);
    if(2 + keySize + 2 + certSize > decryptedData.size()) goto cleanup;
    _issuerSshCert = std::vector<uint8_t>(decryptedData.begin() + 2 + keySize + 2, decryptedData.begin() + 2 + keySize + 2 + certSize);

    if(_issuerSshCert.size() < 4) goto cleanup;

    //{{{ Get ident
        identSize = U8VECTOR_TO_I32(_issuerSshCert, 0);
        _issuerIdent = std::string((char*)_issuerSshCert.data() + 4, identSize);
    //}}}

    if(2 + keySize + 2 + certSize + 4 > decryptedData.size()) goto cleanup;
    _validity = U8VECTOR_TO_I32(decryptedData, 2 + keySize + 2 + certSize);

    _issuerKeyInitialized = true;

cleanup:
    if(!_issuerKeyInitialized)
    {
        mbedtls_pk_free(&_issuerKey);

        std::fill(_issuerSshCert.begin(), _issuerSshCert.end(), 0);
        _issuerSshCert.clear();
        _issuerSshCert.shrink_to_fit();
        std::fill(_issuerIdent.begin(), _issuerIdent.end(), 0);
        _issuerIdent.clear();
        _issuerIdent.shrink_to_fit();
    }

    std::fill(decryptedData.begin(), decryptedData.end(), 0);
}

bool Sign::eraseSshHostCaKeySlot(size_t slot)
{
    if(slot >= FLASH_SSH_HOST_CA_SLOT_COUNT || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet) return false;

    return Flash::eraseSlot(slot, FLASH_SSH_HOST_CA_ADDRESS, FLASH_SSH_HOST_CA_SLOT_COUNT, FLASH_SSH_HOST_CA_SLOT_SIZE);
}

bool Sign::writeSshHostCaKeyPair(size_t slot, std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey, size_t validity)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    size_t decodedCertSize = 0;

    //{{{ Variables to clean up
    //std::vector<uint8_t> privateKey
    //std::vector<uint8_t> publicKey
    std::vector<uint8_t> derKey;
    std::vector<uint8_t> decodedPublicCert;
    std::vector<uint8_t> keyPairBuffer;
    //}}}

    mbedtls_pk_free(&_issuerKey);
    mbedtls_pk_init(&_issuerKey);

    if(privateKey.empty() || privateKey.size() > MAX_PEM_KEY_SIZE || publicKey.empty() || publicKey.size() > MAX_PEM_KEY_SIZE || slot >= FLASH_SSH_HOST_CA_SLOT_COUNT || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet)
    {
        goto cleanup;
    }

    derKey = parsePrivatePem(privateKey.data(), privateKey.size());
    if(derKey.empty())
    {
        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&_issuerKey, privateKey.data(), privateKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
    }
    else
    {
        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&_issuerKey, derKey.data(), derKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
    }
    if(mbedtls_pk_get_len(&_issuerKey) > 512)
    {
        goto cleanup;
    }
    mbedtls_pk_free(&_issuerKey);

    {
        if(mbedtls_base64_decode(nullptr, 0, &decodedCertSize, publicKey.data(), publicKey.size() - 1) == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
        {
            goto cleanup;
        }

        decodedPublicCert.resize(decodedCertSize);
        if(mbedtls_base64_decode(decodedPublicCert.data(), decodedPublicCert.size(), &decodedCertSize, publicKey.data(), publicKey.size() - 1) != 0)
        {
            goto cleanup;
        }
        if(decodedPublicCert.empty() || decodedCertSize > 1024)
        {
            goto cleanup;
        }
    }

    keyPairBuffer.reserve(2 + derKey.size() + 2 + decodedCertSize + 4);
    keyPairBuffer.push_back(derKey.size() >> 8);
    keyPairBuffer.push_back(derKey.size() & 0xFF);
    keyPairBuffer.insert(keyPairBuffer.end(), derKey.begin(), derKey.end());
    keyPairBuffer.push_back(decodedCertSize >> 8);
    keyPairBuffer.push_back(decodedCertSize & 0xFF);
    keyPairBuffer.insert(keyPairBuffer.end(), decodedPublicCert.begin(), decodedPublicCert.end());
    I32_TO_U8VECTOR(keyPairBuffer, validity);

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::encryptionKey, keyPairBuffer.data(), keyPairBuffer.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(slot, FLASH_SSH_HOST_CA_ADDRESS, FLASH_SSH_HOST_CA_SLOT_COUNT, FLASH_SSH_HOST_CA_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    loadSshHostCaKeyPair(slot);

    returnValue = _issuerKeyInitialized;

cleanup:
    mbedtls_pk_free(&_issuerKey);
    std::fill(privateKey.begin(), privateKey.end(), 0);
    std::fill(publicKey.begin(), publicKey.end(), 0);
    std::fill(derKey.begin(), derKey.end(), 0);
    std::fill(decodedPublicCert.begin(), decodedPublicCert.end(), 0);
    std::fill(keyPairBuffer.begin(), keyPairBuffer.end(), 0);

    return returnValue;
}

std::vector<uint8_t> Sign::getSshHostCaPublicKey(size_t keySlot)
{
    std::vector<uint8_t> publicKey;

    if(keySlot >= FLASH_SSH_HOST_CA_SLOT_COUNT) return publicKey;

    loadSshHostCaKeyPair(keySlot);
    if(!_issuerKeyInitialized) return publicKey;

    publicKey.resize(8192);
    std::copy(_issuerIdent.begin(), _issuerIdent.end(), publicKey.begin());
    publicKey.at(_issuerIdent.size()) = ' ';

    size_t base64Offset = _issuerIdent.size() + 1;
    size_t base64Size;
    auto ret = mbedtls_base64_encode(publicKey.data() + base64Offset, publicKey.size() - base64Offset, &base64Size, _issuerSshCert.data(), _issuerSshCert.size());
    if(ret != 0 || base64Size + base64Offset > publicKey.size())
    {
        _errorCode = ret;
        return std::vector<uint8_t>();
    }
    publicKey.resize(base64Offset + base64Size);

    return publicKey;
}

std::vector<uint8_t> Sign::signSshHost(size_t keySlot, const uint8_t* data, size_t size, const std::string& identity, const std::string& principals)
{
    _errorCode = 0;
    std::vector<uint8_t> signedCertificate;
    int32_t ret;

    if(keySlot >= FLASH_SSH_HOST_CA_SLOT_COUNT || data == nullptr || size == 0 || identity.empty() || principals.empty()) return signedCertificate;
    if(!Trng::isReady())
    {
        _errorCode = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        return signedCertificate;
    }

    loadSshHostCaKeyPair(keySlot);
    if(!_issuerKeyInitialized) return signedCertificate;

    auto type = mbedtls_pk_get_type(&_issuerKey);
    mbedtls_md_type_t digestType;
    std::string typeString;
    if(type == MBEDTLS_PK_RSA)
    {
        //From OpenSSH source code
        if(_issuerIdent == "ssh-rsa")
        {
            typeString = "ssh-rsa";
            digestType = MBEDTLS_MD_SHA1;
        }
        else if(_issuerIdent == "rsa-sha2-256")
        {
            typeString = "rsa-sha2-256";
            digestType = MBEDTLS_MD_SHA256;
        }
        else if(_issuerIdent == "rsa-sha2-512")
        {
            typeString = "rsa-sha2-512";
            digestType = MBEDTLS_MD_SHA512;
        }
        else
        {
            _errorCode = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            return signedCertificate;
        }

    }
    else if(type == MBEDTLS_PK_ECKEY)
    {
        mbedtls_ecp_group& group = mbedtls_pk_ec(_issuerKey)->grp;
        //See: https://tools.ietf.org/search/rfc4492#page-32 (Equivalent Curves)
        if(group.id == MBEDTLS_ECP_DP_SECP256R1)
        {
            typeString = "ecdsa-sha2-nistp256";
            digestType = MBEDTLS_MD_SHA256;
        }
        else if(group.id == MBEDTLS_ECP_DP_SECP384R1)
        {
            typeString = "ecdsa-sha2-nistp384";
            digestType = MBEDTLS_MD_SHA384;
        }
        else if(group.id == MBEDTLS_ECP_DP_SECP521R1)
        {
            typeString = "ecdsa-sha2-nistp521";
            digestType = MBEDTLS_MD_SHA512;
        }
        else
        {
            _errorCode = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            return signedCertificate; //Unsupported by SSH
        }
    }
    else return std::vector<uint8_t>();

    signedCertificate.reserve(8192);

    //Ident of public user cert, nonce and public certificate
    std::string signedIdent;
    {
        size_t bufferSize;
        ret = mbedtls_base64_decode(nullptr, 0, &bufferSize, data, size);
        if(ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> decodedPublicCert;
        decodedPublicCert.resize(bufferSize);
        ret = mbedtls_base64_decode(decodedPublicCert.data(), decodedPublicCert.size(), &bufferSize, data, size);
        if(ret != 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }
        if(decodedPublicCert.size() < 4) return std::vector<uint8_t>();

        int32_t identSize = U8VECTOR_TO_I32(decodedPublicCert, 0);
        std::string ident((char*)decodedPublicCert.data() + 4, identSize);
        if(ident == "ssh-rsa") signedIdent = "ssh-rsa-cert-v01@openssh.com";
        else if(ident == "rsa-sha2-256") signedIdent = "rsa-sha2-256-cert-v01@openssh.com";
        else if(ident == "rsa-sha2-512") signedIdent = "rsa-sha2-512-cert-v01@openssh.com";
        else if(ident == "ecdsa-sha2-nistp256") signedIdent = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
        else if(ident == "ecdsa-sha2-nistp384") signedIdent = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
        else if(ident == "ecdsa-sha2-nistp521") signedIdent = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
        else if(ident == "ssh-ed25519") signedIdent = "ssh-ed25519-cert-v01@openssh.com";
        else return std::vector<uint8_t>();

        I32_TO_U8VECTOR(signedCertificate, signedIdent.size());
        signedCertificate.insert(signedCertificate.end(), signedIdent.begin(), signedIdent.end());

        //Nonce
        I32_TO_U8VECTOR(signedCertificate, 0x20);
        {
            bool valid = false;
            auto randomNonceBytes = Trng::generateRandomBytes(32, valid);
            if(!valid)
            {
                _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
                return std::vector<uint8_t>();
            }
            signedCertificate.insert(signedCertificate.end(), randomNonceBytes.begin(), randomNonceBytes.begin() + 32);
        }

        //Ident already is inserted before nonce, so ignore it here
        signedCertificate.insert(signedCertificate.end(), decodedPublicCert.begin() + 4 + identSize, decodedPublicCert.end());
    }

    //Insert 64 bit serial
    {
        bool valid = false;
        auto randomBytes = Trng::generateRandomBytes(4, valid);
        if(!valid)
        {
            _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
            return std::vector<uint8_t>();
        }
        uint64_t serial = (((int64_t)Time::get()) << 32) | *((uint32_t*)(randomBytes.data()));
        I64_TO_U8VECTOR(signedCertificate, serial);
    }

    //Insert type
    I32_TO_U8VECTOR(signedCertificate, 2); //1 = SSH_CERT_TYPE_USER, 2 = SSH_CERT_TYPE_HOST

    //Insert identity
    {
        I32_TO_U8VECTOR(signedCertificate, identity.size());
        signedCertificate.insert(signedCertificate.end(), identity.begin(), identity.end());
    }

    //Insert principals
    {
        size_t startPos = signedCertificate.size();
        I32_TO_U8VECTOR(signedCertificate, 0);

        std::string principal;
        int32_t startIndex = 0;
        auto endIndex = principals.find(',', startIndex);
        bool exitLoop = false;
        while(!exitLoop)
        {
            if(endIndex == std::string::npos)
            {
                principal = principals.substr(startIndex);
                exitLoop = true;
            }
            else
            {
                principal = principals.substr(startIndex, endIndex - startIndex);
                startIndex = endIndex + 1;
                endIndex = principals.find(',', startIndex);
            }

            I32_TO_U8VECTOR(signedCertificate, principal.size());
            signedCertificate.insert(signedCertificate.end(), principal.begin(), principal.end());
        }

        I32_TO_U8CARRAY(signedCertificate, startPos, (signedCertificate.size() - startPos - 4));
    }

    //Insert valid from
    I64_TO_U8VECTOR(signedCertificate, (uint64_t)(Time::get() - 3600));

    //Insert valid to
    I64_TO_U8VECTOR(signedCertificate, (uint64_t)(Time::get() + _validity));

    //Insert options (empty)
    I32_TO_U8VECTOR(signedCertificate, 0);

    //Insert permissions (empty)
    I32_TO_U8VECTOR(signedCertificate, 0);

    //Insert NULL
    I32_TO_U8VECTOR(signedCertificate, 0);

    //Insert public CA certificate
    {
        I32_TO_U8VECTOR(signedCertificate, _issuerSshCert.size());
        signedCertificate.insert(signedCertificate.end(), _issuerSshCert.begin(), _issuerSshCert.end());
    }

    std::vector<uint8_t> digest;
    //Calculate digest
    {
        auto mdInfo = mbedtls_md_info_from_type(digestType);
        if(!mdInfo) return std::vector<uint8_t>();
        size_t digestSize = mbedtls_md_get_size(mdInfo);
        digest.resize(digestSize);
        if(digestType == MBEDTLS_MD_SHA1) ret = mbedtls_sha1_ret(signedCertificate.data(), signedCertificate.size(), digest.data());
        else if(digestType == MBEDTLS_MD_SHA256) ret = mbedtls_sha256_ret(signedCertificate.data(), signedCertificate.size(), digest.data(), 0);
        else if(digestType == MBEDTLS_MD_SHA384) ret = mbedtls_sha512_ret(signedCertificate.data(), signedCertificate.size(), digest.data(), 1);
        else if(digestType == MBEDTLS_MD_SHA512) ret = mbedtls_sha512_ret(signedCertificate.data(), signedCertificate.size(), digest.data(), 0);

        if(ret != 0)
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }
    }

    std::array<uint8_t, MBEDTLS_MPI_MAX_SIZE> signature;
    size_t signatureSize = 0;
    //Sign digest
    {
        ret = mbedtls_pk_sign(&_issuerKey, digestType, digest.data(), digest.size(), signature.data(), &signatureSize, Trng::mbedTlsGetRandomNumbers, nullptr);
        if(ret != 0)
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }
    }

    //Insert signature
    {
        if(type == MBEDTLS_PK_ECKEY)
        {
            //Get r and s for ECDSA
            auto rs = ecdsaSignatureToSshFormat(signature.data(), signatureSize);
            I32_TO_U8VECTOR(signedCertificate, 4 + typeString.size() + 4 + rs.size());
            I32_TO_U8VECTOR(signedCertificate, typeString.size());
            signedCertificate.insert(signedCertificate.end(), typeString.begin(), typeString.end());
            I32_TO_U8VECTOR(signedCertificate, rs.size());
            signedCertificate.insert(signedCertificate.end(), rs.begin(), rs.end());
        }
        else
        {
            //RSA signature can be written as it is
            I32_TO_U8VECTOR(signedCertificate, 4 + typeString.size() + 4 + signatureSize);
            I32_TO_U8VECTOR(signedCertificate, typeString.size());
            signedCertificate.insert(signedCertificate.end(), typeString.begin(), typeString.end());
            I32_TO_U8VECTOR(signedCertificate, signatureSize);
            signedCertificate.insert(signedCertificate.end(), signature.begin(), signature.begin() + signatureSize);
        }
    }

    //Calculate and return Base64
    {
        std::vector<uint8_t> base64Buffer;
        base64Buffer.resize(8192);

        size_t base64Offset = signedIdent.size() + 1;
        std::copy(signedIdent.begin(), signedIdent.end(), base64Buffer.begin());
        base64Buffer.at(signedIdent.size()) = (uint8_t)' ';

        size_t base64Size;
        ret = mbedtls_base64_encode(base64Buffer.data() + base64Offset, base64Buffer.size() - base64Offset, &base64Size, signedCertificate.data(), signedCertificate.size());
        if(ret != 0 || base64Size + base64Offset > base64Buffer.size())
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }
        base64Buffer.resize(base64Offset + base64Size);

        return base64Buffer;
    }
}

void Sign::loadX509CaKey(size_t slot)
{
    size_t keySize = 0;
    size_t certSize = 0;

    //{{{ Variables to clean up
    std::vector<uint8_t> decryptedData;
    //}}}

    mbedtls_pk_free(&_issuerKey);
    mbedtls_pk_init(&_issuerKey);
    mbedtls_x509_crt_free(&_issuerX509Cert);
    mbedtls_x509_crt_init(&_issuerX509Cert);

    if(slot >= FLASH_X509_HOST_CA_SLOT_COUNT || !GD::loggedIn || !GD::encryptionKeySet)
    {
        goto cleanup;
    }

    {
        uint32_t address = FLASH_X509_HOST_CA_ADDRESS + (slot * FLASH_X509_HOST_CA_SLOT_SIZE);
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* data = nullptr;
        size_t dataSize = 0;
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        if((metadata >> 24) != 1) goto cleanup;
        dataSize = metadata & 0xFFFF;
        if(dataSize == 0 || dataSize > FLASH_X509_HOST_CA_SLOT_SIZE - 4) goto cleanup;
        data = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::encryptionKey, data, dataSize);
    }

    if(2 > decryptedData.size()) goto cleanup;
    keySize = U8VECTOR_TO_I16(decryptedData, 0);
    if(2 + keySize > decryptedData.size()) goto cleanup;
    //Note that f_rng and p_rng were added by us to support TRNG.
    if(mbedtls_pk_parse_key(&_issuerKey, decryptedData.data() + 2, keySize, nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0) goto cleanup;

    if(2 + keySize + 2 > decryptedData.size()) goto cleanup;
    certSize = U8VECTOR_TO_I16(decryptedData, 2 + keySize);
    if(2 + keySize + 2 + certSize > decryptedData.size()) goto cleanup;
    if(mbedtls_x509_crt_parse_der(&_issuerX509Cert, decryptedData.data() + 2 + keySize + 2, certSize) != 0) goto cleanup;

    if(2 + keySize + 2 + certSize + 4 > decryptedData.size()) goto cleanup;
    _validity = U8VECTOR_TO_I32(decryptedData, 2 + keySize + 2 + certSize);

    _issuerKeyInitialized = true;

cleanup:
    if(!_issuerKeyInitialized)
    {
        mbedtls_pk_free(&_issuerKey);
        mbedtls_x509_crt_free(&_issuerX509Cert);
    }
    std::fill(decryptedData.begin(), decryptedData.end(), 0);
}

bool Sign::eraseX509CaKeySlot(size_t slot)
{
    if(slot >= FLASH_X509_HOST_CA_SLOT_COUNT || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet) return false;

    return Flash::eraseSlot(slot, FLASH_X509_HOST_CA_ADDRESS, FLASH_X509_HOST_CA_SLOT_COUNT, FLASH_X509_HOST_CA_SLOT_SIZE);
}

bool Sign::writeX509CaKey(size_t slot, std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey, size_t validity)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    //{{{ Variables to clean up
    //std::vector<uint8_t> privateKey; (commented in this line, because it is a function argument)
    std::vector<uint8_t> publicDerKey;
    std::vector<uint8_t> privateDerKey;
    std::vector<uint8_t> keyPairBuffer;
    //}}}

    mbedtls_pk_free(&_issuerKey);
    mbedtls_pk_init(&_issuerKey);
    mbedtls_x509_crt_free(&_issuerX509Cert);
    mbedtls_x509_crt_init(&_issuerX509Cert);

    if(privateKey.empty() || publicKey.empty() || privateKey.size() > MAX_PEM_KEY_SIZE || publicKey.size() > MAX_PEM_KEY_SIZE || slot >= FLASH_X509_HOST_CA_SLOT_COUNT || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet)
    {
        goto cleanup;
    }

    //{{{ Parse private certificate
        privateDerKey = parsePrivatePem(privateKey.data(), privateKey.size());
        if(privateDerKey.empty())
        {
            //Note that f_rng and p_rng were added by us to support TRNG.
            if(mbedtls_pk_parse_key(&_issuerKey, privateKey.data(), privateKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
            {
                goto cleanup;
            }
        }
        else
        {
            //Note that f_rng and p_rng were added by us to support TRNG.
            if(mbedtls_pk_parse_key(&_issuerKey, privateDerKey.data(), privateDerKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
            {
                goto cleanup;
            }
        }
        if(mbedtls_pk_get_len(&_issuerKey) > 512)
        {
            goto cleanup;
        }
    //}}}

    //{{{ Parse public certificate
        publicDerKey = parsePublicPem(publicKey.data(), publicKey.size());
        if(publicDerKey.empty())
        {
            if(mbedtls_x509_crt_parse_der(&_issuerX509Cert, publicKey.data(), publicKey.size()) != 0)
            {
                goto cleanup;
            }
        }
        else
        {
            if(mbedtls_x509_crt_parse_der(&_issuerX509Cert, publicDerKey.data(), publicDerKey.size()) != 0)
            {
                goto cleanup;
            }
        }
    //}}}

    //{{{ Check if key and issuer certificate match
        if(mbedtls_pk_check_pair(&_issuerX509Cert.pk, &_issuerKey) != 0)
        {
            goto cleanup;
        }

        mbedtls_pk_free(&_issuerKey);
        mbedtls_x509_crt_free(&_issuerX509Cert);
    //}}}

    keyPairBuffer.reserve(2 + privateDerKey.size() + 2 + publicDerKey.size() + 4);
    keyPairBuffer.push_back(privateDerKey.size() >> 8);
    keyPairBuffer.push_back(privateDerKey.size() & 0xFF);
    keyPairBuffer.insert(keyPairBuffer.end(), privateDerKey.begin(), privateDerKey.end());
    keyPairBuffer.push_back(publicDerKey.size() >> 8);
    keyPairBuffer.push_back(publicDerKey.size() & 0xFF);
    keyPairBuffer.insert(keyPairBuffer.end(), publicDerKey.begin(), publicDerKey.end());
    I32_TO_U8VECTOR(keyPairBuffer, validity);

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::encryptionKey, keyPairBuffer.data(), keyPairBuffer.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(slot, FLASH_X509_HOST_CA_ADDRESS, FLASH_X509_HOST_CA_SLOT_COUNT, FLASH_X509_HOST_CA_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    loadX509CaKey(slot);

    returnValue = _issuerKeyInitialized;

cleanup:
    mbedtls_pk_free(&_issuerKey);
    std::fill(privateKey.begin(), privateKey.end(), 0);
    std::fill(publicDerKey.begin(), publicDerKey.end(), 0);
    std::fill(privateDerKey.begin(), privateDerKey.end(), 0);
    std::fill(keyPairBuffer.begin(), keyPairBuffer.end(), 0);
    return returnValue;
}

std::vector<uint8_t> Sign::getX509CaPublicKey(size_t keySlot)
{
    std::vector<uint8_t> publicKey;

    if(keySlot >= FLASH_X509_HOST_CA_SLOT_COUNT) return publicKey;

    loadX509CaKey(keySlot);
    if(!_issuerKeyInitialized) return publicKey;

    publicKey.resize(8192);
    size_t publicKeySize = 0;
    if(mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", _issuerX509Cert.raw.p, _issuerX509Cert.raw.len, publicKey.data(), publicKey.size(), &publicKeySize) != 0)
    {
        publicKey.clear();
        publicKey.shrink_to_fit();
        return publicKey;
    }
    publicKey.resize(publicKeySize);
    if(publicKey.back() == 0) publicKey.resize(publicKey.size() - 1);

    return publicKey;
}

std::vector<uint8_t> Sign::signX509Csr(size_t keySlot, const uint8_t* data, size_t size)
{
    _errorCode = 0;
    std::vector<uint8_t> signedCertificate;
    int32_t ret;

    if(keySlot >= FLASH_X509_HOST_CA_SLOT_COUNT || data == nullptr || size == 0) return signedCertificate;
    if(!Trng::isReady())
    {
        _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
        return signedCertificate;
    }

    loadX509CaKey(keySlot);
    if(!_issuerKeyInitialized) return signedCertificate;

    //Must include '\0'
    if((ret = mbedtls_x509_csr_parse(&_csr, data, size)) != 0)
    {
        _errorCode = ret;
        if(ret == MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) GD::uart->sendOutput("Error parsing CSR. No or invalid PEM header or footer. Expected: \"-----BEGIN CERTIFICATE REQUEST-----\" and \"-----END CERTIFICATE REQUEST-----\".");
        else GD::uart->sendOutput("Error parsing CSR.");
        return signedCertificate;
    }

    mbedtls_x509write_crt_set_subject_key(&_crt, &_csr.pk);
    mbedtls_x509write_crt_set_issuer_key(&_crt, &_issuerKey);

    {
        std::array<char, 256> dnBuffer;
        if((ret = mbedtls_x509_dn_gets(dnBuffer.data(), dnBuffer.size(), &_csr.subject)) < 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }

        if((ret = mbedtls_x509write_crt_set_subject_name(&_crt, dnBuffer.data())) != 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }
    }

    { //Issuer name
        std::array <char, 256> dnBuffer;
        if((ret = mbedtls_x509_dn_gets(dnBuffer.data(), dnBuffer.size(), &_issuerX509Cert.subject)) < 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }

        if((ret = mbedtls_x509write_crt_set_issuer_name(&_crt, dnBuffer.data())) != 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }
    }

    mbedtls_x509write_crt_set_md_alg(&_crt, MBEDTLS_MD_SHA256);

    {
        bool valid = false;
        auto randomBytes = Trng::generateRandomBytes(4, valid);
        if(!valid)
        {
            _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
            return std::vector<uint8_t>();
        }
        uint64_t serial = (((int64_t)Time::get()) << 32) | *((uint32_t*)(randomBytes.data()));
        std::array<uint8_t, 8> serialArray;
        I64_TO_U8CARRAY(serialArray, 0, serial);
        if((mbedtls_mpi_read_binary(&_serial, serialArray.data(), serialArray.size())) != 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }
    }

    if((ret = mbedtls_x509write_crt_set_serial(&_crt, &_serial)) != 0)
    {
        _errorCode = ret;
        return signedCertificate;
    }

    {
        auto time = Time::get();
        auto fromEpoch = time - 90000; //Start validity now minus 25 hours
        tm* fromTime = std::localtime(&fromEpoch);
        //1970 is actually wrong!!! But it is implemented here this way.
        std::string fromString = std::to_string(fromTime->tm_year + 1970) + (fromTime->tm_mon + 1 >= 10 ? std::to_string(fromTime->tm_mon + 1) : "0" + std::to_string(fromTime->tm_mon + 1)) + (fromTime->tm_mday >= 10 ? std::to_string(fromTime->tm_mday) : "0" + std::to_string(fromTime->tm_mday)) + (fromTime->tm_hour >= 10 ? std::to_string(fromTime->tm_hour) : "0" + std::to_string(fromTime->tm_hour)) + (fromTime->tm_min >= 10 ? std::to_string(fromTime->tm_min) : "0" + std::to_string(fromTime->tm_min)) + "00";
        auto toEpoch = time + _validity;
        tm* toTime = std::localtime(&toEpoch);
        //1970 is actually wrong!!! But it is implemented here this way.
        std::string toString = std::to_string(toTime->tm_year + 1970) + (toTime->tm_mon + 1 >= 10 ? std::to_string(toTime->tm_mon + 1) : "0" + std::to_string(toTime->tm_mon + 1)) + (toTime->tm_mday >= 10 ? std::to_string(toTime->tm_mday) : "0" + std::to_string(toTime->tm_mday)) + (toTime->tm_hour >= 10 ? std::to_string(toTime->tm_hour) : "0" + std::to_string(toTime->tm_hour)) + (toTime->tm_min >= 10 ? std::to_string(toTime->tm_min) : "0" + std::to_string(toTime->tm_min)) + "00";
        if((ret = mbedtls_x509write_crt_set_validity(&_crt, fromString.c_str(), toString.c_str())) != 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }
    }

    if((ret = mbedtls_x509write_crt_set_basic_constraints(&_crt, 0, 10)) != 0)
    {
        _errorCode = ret;
        return signedCertificate;
    }

    if((ret = mbedtls_x509write_crt_set_subject_key_identifier(&_crt)) != 0)
    {
        _errorCode = ret;
        return signedCertificate;
    }

    if((ret = mbedtls_x509write_crt_set_authority_key_identifier(&_crt)) != 0)
    {
        _errorCode = ret;
        return signedCertificate;
    }

    /*if((ret = mbedtls_x509write_crt_set_key_usage(&_crt, 0xFE)) != 0)
    {
        _errorCode = ret;
        return signedCertificate;
    }*/

    signedCertificate.resize(8192, 0);

    ret = mbedtls_x509write_crt_pem(&_crt, signedCertificate.data(), signedCertificate.size(), Trng::mbedTlsGetRandomNumbers, nullptr);
    if(ret != 0)
    {
        _errorCode = ret;
        return signedCertificate;
    }

    auto pemSize = strlen((const char*)signedCertificate.data()) + 1;
    if(pemSize > signedCertificate.size()) pemSize = signedCertificate.size();
    signedCertificate.resize(pemSize);

    return signedCertificate;
}

void Sign::loadUserCaKeyPair(size_t slot)
{
    size_t keySize = 0;
    size_t certSize = 0;
    int32_t identSize = 0;

    //{{{ Variables to clean up
    std::vector<uint8_t> decryptedData;
    //}}}

    mbedtls_pk_free(&_issuerKey);
    mbedtls_pk_init(&_issuerKey);

    if(slot >= FLASH_USER_CA_SLOT_COUNT || !GD::loggedIn || !GD::encryptionKeySet) goto cleanup;

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        uint32_t address = FLASH_USER_CA_ADDRESS + (slot * FLASH_USER_CA_SLOT_SIZE);
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* data = nullptr;
        size_t dataSize = 0;
        if((metadata >> 24) != 1) goto cleanup;
        dataSize = metadata & 0xFFFF;
        if(dataSize < 2 || dataSize > FLASH_USER_CA_SLOT_SIZE - 4) goto cleanup;
        data = (uint8_t*)(address + 4);

        decryptedData = aes->decrypt(GD::encryptionKey, data, dataSize);
    }

    if(2 > decryptedData.size()) goto cleanup;
    keySize = U8VECTOR_TO_I16(decryptedData, 0);
    if(2 + keySize > decryptedData.size()) goto cleanup;
    //Note that f_rng and p_rng were added by us to support TRNG.
    if(mbedtls_pk_parse_key(&_issuerKey, decryptedData.data() + 2, keySize, nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0) goto cleanup;

    if(2 + keySize + 2 > decryptedData.size()) goto cleanup;
    certSize = U8VECTOR_TO_I16(decryptedData, 2 + keySize);
    if(2 + keySize + 2 + certSize > decryptedData.size()) goto cleanup;
    _issuerSshCert = std::vector<uint8_t>(decryptedData.begin() + 2 + keySize + 2, decryptedData.begin() + 2 + keySize + 2 + certSize);

    if(_issuerSshCert.size() < 4) goto cleanup;

    //{{{ Get ident
        identSize = U8VECTOR_TO_I32(_issuerSshCert, 0);
        _issuerIdent = std::string((char*)_issuerSshCert.data() + 4, identSize);
    //}}}

    if(2 + keySize + 2 + certSize + 4 > decryptedData.size()) goto cleanup;
    _validity = U8VECTOR_TO_I32(decryptedData, 2 + keySize + 2 + certSize);

    _issuerKeyInitialized = true;

cleanup:
    if(!_issuerKeyInitialized)
    {
        mbedtls_pk_free(&_issuerKey);

        std::fill(_issuerSshCert.begin(), _issuerSshCert.end(), 0);
        _issuerSshCert.clear();
        _issuerSshCert.shrink_to_fit();
        std::fill(_issuerIdent.begin(), _issuerIdent.end(), 0);
        _issuerIdent.clear();
        _issuerIdent.shrink_to_fit();
    }

    std::fill(decryptedData.begin(), decryptedData.end(), 0);
}

bool Sign::eraseUserCaKeySlot(size_t slot)
{
    if(slot >= FLASH_USER_CA_SLOT_COUNT || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet) return false;

    return Flash::eraseSlot(slot, FLASH_USER_CA_ADDRESS, FLASH_USER_CA_SLOT_COUNT, FLASH_USER_CA_SLOT_SIZE);
}

bool Sign::writeUserCaKeyPair(size_t slot, std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey, size_t validity)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    size_t decodedCertSize = 0;

    //{{{ Variables to clean up
    //std::vector<uint8_t> privateKey
    //std::vector<uint8_t> publicKey
    std::vector<uint8_t> derKey;
    std::vector<uint8_t> decodedPublicCert;
    std::vector<uint8_t> keyPairBuffer;
    //}}}

    mbedtls_pk_free(&_issuerKey);
    mbedtls_pk_init(&_issuerKey);

    if(privateKey.empty() || privateKey.size() > MAX_PEM_KEY_SIZE || publicKey.empty() || publicKey.size() > MAX_PEM_KEY_SIZE || slot >= FLASH_USER_CA_SLOT_COUNT || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet)
    {
        goto cleanup;
    }

    derKey = parsePrivatePem(privateKey.data(), privateKey.size());
    if(derKey.empty())
    {
        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&_issuerKey, privateKey.data(), privateKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
    }
    else
    {
        //Note that f_rng and p_rng were added by us to support TRNG.
        if(mbedtls_pk_parse_key(&_issuerKey, derKey.data(), derKey.size(), nullptr, 0, Trng::mbedTlsGetRandomNumbers, nullptr) != 0)
        {
            goto cleanup;
        }
    }
    if(mbedtls_pk_get_len(&_issuerKey) > 512)
    {
        goto cleanup;
    }
    mbedtls_pk_free(&_issuerKey);

    {
        if(mbedtls_base64_decode(nullptr, 0, &decodedCertSize, publicKey.data(), publicKey.size() - 1) == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
        {
            goto cleanup;
        }

        decodedPublicCert.resize(decodedCertSize);
        if(mbedtls_base64_decode(decodedPublicCert.data(), decodedPublicCert.size(), &decodedCertSize, publicKey.data(), publicKey.size() - 1) != 0)
        {
            goto cleanup;
        }
        if(decodedPublicCert.empty() || decodedCertSize > 1024)
        {
            goto cleanup;
        }
    }

    keyPairBuffer.reserve(2 + derKey.size() + 2 + decodedCertSize + 4);
    keyPairBuffer.push_back(derKey.size() >> 8);
    keyPairBuffer.push_back(derKey.size() & 0xFF);
    keyPairBuffer.insert(keyPairBuffer.end(), derKey.begin(), derKey.end());
    keyPairBuffer.push_back(decodedCertSize >> 8);
    keyPairBuffer.push_back(decodedCertSize & 0xFF);
    keyPairBuffer.insert(keyPairBuffer.end(), decodedPublicCert.begin(), decodedPublicCert.end());
    I32_TO_U8VECTOR(keyPairBuffer, validity);

    {
        std::unique_ptr<Aes> aes = std::make_unique<Aes>();
        encryptedData = aes->encrypt(GD::encryptionKey, keyPairBuffer.data(), keyPairBuffer.size());
        if(encryptedData.empty())
        {
            goto cleanup;
        }
    }

    if(!Flash::writeSlot(slot, FLASH_USER_CA_ADDRESS, FLASH_USER_CA_SLOT_COUNT, FLASH_USER_CA_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    loadUserCaKeyPair(slot);

    returnValue = _issuerKeyInitialized;

cleanup:
    mbedtls_pk_free(&_issuerKey);
    std::fill(privateKey.begin(), privateKey.end(), 0);
    std::fill(publicKey.begin(), publicKey.end(), 0);
    std::fill(derKey.begin(), derKey.end(), 0);
    std::fill(decodedPublicCert.begin(), decodedPublicCert.end(), 0);
    std::fill(keyPairBuffer.begin(), keyPairBuffer.end(), 0);

    return returnValue;
}

std::vector<uint8_t> Sign::getUserCaPublicKey(size_t keySlot)
{
    std::vector<uint8_t> publicKey;

    if(keySlot >= FLASH_USER_CA_SLOT_COUNT) return publicKey;

    loadUserCaKeyPair(keySlot);
    if(!_issuerKeyInitialized) return publicKey;

    publicKey.resize(8192);
    std::copy(_issuerIdent.begin(), _issuerIdent.end(), publicKey.begin());
    publicKey.at(_issuerIdent.size()) = ' ';

    size_t base64Offset = _issuerIdent.size() + 1;
    size_t base64Size;
    auto ret = mbedtls_base64_encode(publicKey.data() + base64Offset, publicKey.size() - base64Offset, &base64Size, _issuerSshCert.data(), _issuerSshCert.size());
    if(ret != 0 || base64Size + base64Offset > publicKey.size())
    {
        _errorCode = ret;
        return std::vector<uint8_t>();
    }
    publicKey.resize(base64Offset + base64Size);

    return publicKey;
}

std::vector<uint8_t> Sign::signUser(size_t keySlot, const uint8_t* data, size_t size, const std::string& identity, const std::string& principals, uint8_t permissions, const std::string& forceCommand, const std::string& sourceAddresses)
{
    _errorCode = 0;
    std::vector<uint8_t> signedCertificate;
    int32_t ret;

    if(keySlot >= FLASH_USER_CA_SLOT_COUNT || data == nullptr || size == 0 || identity.empty() || principals.empty() || (permissions & 0x1F) == 0) return signedCertificate;
    if(!Trng::isReady())
    {
        _errorCode = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        return signedCertificate;
    }

    loadUserCaKeyPair(keySlot);
    if(!_issuerKeyInitialized) return signedCertificate;

    auto type = mbedtls_pk_get_type(&_issuerKey);
    mbedtls_md_type_t digestType;
    std::string typeString;
    if(type == MBEDTLS_PK_RSA)
    {
        //From OpenSSH source code
        if(_issuerIdent == "ssh-rsa")
        {
            typeString = "ssh-rsa";
            digestType = MBEDTLS_MD_SHA1;
        }
        else if(_issuerIdent == "rsa-sha2-256")
        {
            typeString = "rsa-sha2-256";
            digestType = MBEDTLS_MD_SHA256;
        }
        else if(_issuerIdent == "rsa-sha2-512")
        {
            typeString = "rsa-sha2-512";
            digestType = MBEDTLS_MD_SHA512;
        }
        else
        {
            _errorCode = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            return signedCertificate;
        }

    }
    else if(type == MBEDTLS_PK_ECKEY)
    {
        mbedtls_ecp_group& group = mbedtls_pk_ec(_issuerKey)->grp;
        //See: https://tools.ietf.org/search/rfc4492#page-32 (Equivalent Curves)
        if(group.id == MBEDTLS_ECP_DP_SECP256R1)
        {
            typeString = "ecdsa-sha2-nistp256";
            digestType = MBEDTLS_MD_SHA256;
        }
        else if(group.id == MBEDTLS_ECP_DP_SECP384R1)
        {
            typeString = "ecdsa-sha2-nistp384";
            digestType = MBEDTLS_MD_SHA384;
        }
        else if(group.id == MBEDTLS_ECP_DP_SECP521R1)
        {
            typeString = "ecdsa-sha2-nistp521";
            digestType = MBEDTLS_MD_SHA512;
        }
        else
        {
            _errorCode = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            return signedCertificate; //Unsupported by SSH
        }
    }
    else return std::vector<uint8_t>();

    signedCertificate.reserve(8192);

    //Ident of public user cert, nonce and public certificate
    std::string signedIdent;
    {
        size_t bufferSize;
        ret = mbedtls_base64_decode(nullptr, 0, &bufferSize, data, size);
        if(ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> decodedPublicCert;
        decodedPublicCert.resize(bufferSize);
        ret = mbedtls_base64_decode(decodedPublicCert.data(), decodedPublicCert.size(), &bufferSize, data, size);
        if(ret != 0)
        {
            _errorCode = ret;
            return signedCertificate;
        }
        if(decodedPublicCert.size() < 4) return std::vector<uint8_t>();

        int32_t identSize = U8VECTOR_TO_I32(decodedPublicCert, 0);
        std::string ident((char*)decodedPublicCert.data() + 4, identSize);
        if(ident == "ssh-rsa") signedIdent = "ssh-rsa-cert-v01@openssh.com";
        else if(ident == "rsa-sha2-256") signedIdent = "rsa-sha2-256-cert-v01@openssh.com";
        else if(ident == "rsa-sha2-512") signedIdent = "rsa-sha2-512-cert-v01@openssh.com";
        else if(ident == "ecdsa-sha2-nistp256") signedIdent = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
        else if(ident == "ecdsa-sha2-nistp384") signedIdent = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
        else if(ident == "ecdsa-sha2-nistp521") signedIdent = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
        else if(ident == "ssh-ed25519") signedIdent = "ssh-ed25519-cert-v01@openssh.com";
        else return std::vector<uint8_t>();

        I32_TO_U8VECTOR(signedCertificate, signedIdent.size());
        signedCertificate.insert(signedCertificate.end(), signedIdent.begin(), signedIdent.end());

        //Nonce
        I32_TO_U8VECTOR(signedCertificate, 0x20);
        {
            bool valid = false;
            auto randomNonceBytes = Trng::generateRandomBytes(32, valid);
            if(!valid)
            {
                _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
                return std::vector<uint8_t>();
            }
            signedCertificate.insert(signedCertificate.end(), randomNonceBytes.begin(), randomNonceBytes.begin() + 32);
        }

        //Ident already is inserted before nonce, so ignore it here
        signedCertificate.insert(signedCertificate.end(), decodedPublicCert.begin() + 4 + identSize, decodedPublicCert.end());
    }

    //Insert 64 bit serial
    {
        bool valid = false;
        auto randomBytes = Trng::generateRandomBytes(4, valid);
        if(!valid)
        {
            _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
            return std::vector<uint8_t>();
        }
        uint64_t serial = (((int64_t)Time::get()) << 32) | *((uint32_t*)(randomBytes.data()));
        I64_TO_U8VECTOR(signedCertificate, serial);
    }

    //Insert type
    I32_TO_U8VECTOR(signedCertificate, 1); //1 = SSH_CERT_TYPE_USER, 2 = SSH_CERT_TYPE_HOST

    //Insert identity
    {
        I32_TO_U8VECTOR(signedCertificate, identity.size());
        signedCertificate.insert(signedCertificate.end(), identity.begin(), identity.end());
    }

    //Insert principals
    {
        size_t startPos = signedCertificate.size();
        I32_TO_U8VECTOR(signedCertificate, 0);

        std::string principal;
        int32_t startIndex = 0;
        auto endIndex = principals.find(',', startIndex);
        bool exitLoop = false;
        while(!exitLoop)
        {
            if(endIndex == std::string::npos)
            {
                principal = principals.substr(startIndex);
                exitLoop = true;
            }
            else
            {
                principal = principals.substr(startIndex, endIndex - startIndex);
                startIndex = endIndex + 1;
                endIndex = principals.find(',', startIndex);
            }

            I32_TO_U8VECTOR(signedCertificate, principal.size());
            signedCertificate.insert(signedCertificate.end(), principal.begin(), principal.end());
        }

        I32_TO_U8CARRAY(signedCertificate, startPos, (signedCertificate.size() - startPos - 4));
    }

    //Insert valid from
    I64_TO_U8VECTOR(signedCertificate, (uint64_t)(Time::get() - 3600));

    //Insert valid to
    I64_TO_U8VECTOR(signedCertificate, (uint64_t)(Time::get() + _validity));

    //Insert options
    {
        size_t optionsStartPos = signedCertificate.size();
        I32_TO_U8VECTOR(signedCertificate, 0); //Options size
        if(!forceCommand.empty())
        {
            std::string label = "force-command";
            I32_TO_U8VECTOR(signedCertificate, label.size());
            signedCertificate.insert(signedCertificate.end(), label.begin(), label.end());
            I32_TO_U8VECTOR(signedCertificate, forceCommand.size() + 4);
            I32_TO_U8VECTOR(signedCertificate, forceCommand.size());
            signedCertificate.insert(signedCertificate.end(), forceCommand.begin(), forceCommand.end());
        }
        if(!sourceAddresses.empty())
        {
            std::string label = "source-address";
            I32_TO_U8VECTOR(signedCertificate, label.size());
            signedCertificate.insert(signedCertificate.end(), label.begin(), label.end());
            size_t startPos = signedCertificate.size();
            I32_TO_U8VECTOR(signedCertificate, 0);

            std::string sourceAddress;
            int32_t startIndex = 0;
            auto endIndex = sourceAddresses.find(',', startIndex);
            bool exitLoop = false;
            while(!exitLoop)
            {
                if(endIndex == std::string::npos)
                {
                    sourceAddress = sourceAddresses.substr(startIndex);
                    exitLoop = true;
                }
                else
                {
                    sourceAddress = sourceAddresses.substr(startIndex, endIndex - startIndex);
                    startIndex = endIndex + 1;
                    endIndex = sourceAddresses.find(',', startIndex);
                }

                I32_TO_U8VECTOR(signedCertificate, sourceAddress.size());
                signedCertificate.insert(signedCertificate.end(), sourceAddress.begin(), sourceAddress.end());
            }

            I32_TO_U8CARRAY(signedCertificate, startPos, (signedCertificate.size() - startPos - 4));
        }
        I32_TO_U8CARRAY(signedCertificate, optionsStartPos, (signedCertificate.size() - optionsStartPos - 4));
    }

    //Insert permissions
    {
        std::vector<uint8_t> permissionsVector;
        permissionsVector.reserve(130); //Maximum permission size
        for(int32_t i = 0; i < 5; i++)
        {
            if(!(permissions & (1 << i))) continue;
            std::string permission;
            switch(i)
            {
            case 0:
                permission = "permit-X11-forwarding";
                break;
            case 1:
                permission = "permit-agent-forwarding";
                break;
            case 2:
                permission = "permit-port-forwarding";
                break;
            case 3:
                permission = "permit-pty";
                break;
            case 4:
                permission = "permit-user-rc";
                break;
            }
            I32_TO_U8VECTOR(permissionsVector, permission.size());
            permissionsVector.insert(permissionsVector.end(), permission.begin(), permission.end());
            I32_TO_U8VECTOR(permissionsVector, 0);
        }
        I32_TO_U8VECTOR(signedCertificate, permissionsVector.size());
        signedCertificate.insert(signedCertificate.end(), permissionsVector.begin(), permissionsVector.end());
    }

    //Insert NULL
    I32_TO_U8VECTOR(signedCertificate, 0);

    //Insert public CA certificate
    {
        I32_TO_U8VECTOR(signedCertificate, _issuerSshCert.size());
        signedCertificate.insert(signedCertificate.end(), _issuerSshCert.begin(), _issuerSshCert.end());
    }

    std::vector<uint8_t> digest;
    //Calculate digest
    {
        auto mdInfo = mbedtls_md_info_from_type(digestType);
        if(!mdInfo) return std::vector<uint8_t>();
        size_t digestSize = mbedtls_md_get_size(mdInfo);
        digest.resize(digestSize);
        if(digestType == MBEDTLS_MD_SHA1) ret = mbedtls_sha1_ret(signedCertificate.data(), signedCertificate.size(), digest.data());
        else if(digestType == MBEDTLS_MD_SHA256) ret = mbedtls_sha256_ret(signedCertificate.data(), signedCertificate.size(), digest.data(), 0);
        else if(digestType == MBEDTLS_MD_SHA384) ret = mbedtls_sha512_ret(signedCertificate.data(), signedCertificate.size(), digest.data(), 1);
        else if(digestType == MBEDTLS_MD_SHA512) ret = mbedtls_sha512_ret(signedCertificate.data(), signedCertificate.size(), digest.data(), 0);

        if(ret != 0)
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }
    }

    std::array<uint8_t, MBEDTLS_MPI_MAX_SIZE> signature;
    size_t signatureSize = 0;
    //Sign digest
    {
        ret = mbedtls_pk_sign(&_issuerKey, digestType, digest.data(), digest.size(), signature.data(), &signatureSize, Trng::mbedTlsGetRandomNumbers, nullptr);
        if(ret != 0)
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }
    }

    //Insert signature
    {
        if(type == MBEDTLS_PK_ECKEY)
        {
            //Get r and s for ECDSA
            auto rs = ecdsaSignatureToSshFormat(signature.data(), signatureSize);
            I32_TO_U8VECTOR(signedCertificate, 4 + typeString.size() + 4 + rs.size());
            I32_TO_U8VECTOR(signedCertificate, typeString.size());
            signedCertificate.insert(signedCertificate.end(), typeString.begin(), typeString.end());
            I32_TO_U8VECTOR(signedCertificate, rs.size());
            signedCertificate.insert(signedCertificate.end(), rs.begin(), rs.end());
        }
        else
        {
            //RSA signature can be written as it is
            I32_TO_U8VECTOR(signedCertificate, 4 + typeString.size() + 4 + signatureSize);
            I32_TO_U8VECTOR(signedCertificate, typeString.size());
            signedCertificate.insert(signedCertificate.end(), typeString.begin(), typeString.end());
            I32_TO_U8VECTOR(signedCertificate, signatureSize);
            signedCertificate.insert(signedCertificate.end(), signature.begin(), signature.begin() + signatureSize);
        }
    }

    //Calculate and return Base64
    {
        std::vector<uint8_t> base64Buffer;
        base64Buffer.resize(8192);

        size_t base64Offset = signedIdent.size() + 1;
        std::copy(signedIdent.begin(), signedIdent.end(), base64Buffer.begin());
        base64Buffer.at(signedIdent.size()) = (uint8_t)' ';

        size_t base64Size;
        ret = mbedtls_base64_encode(base64Buffer.data() + base64Offset, base64Buffer.size() - base64Offset, &base64Size, signedCertificate.data(), signedCertificate.size());
        if(ret != 0 || base64Size + base64Offset > base64Buffer.size())
        {
            _errorCode = ret;
            return std::vector<uint8_t>();
        }
        base64Buffer.resize(base64Offset + base64Size);

        return base64Buffer;
    }
}

std::vector<uint8_t> Sign::ecdsaSignatureToSshFormat(const uint8_t* signature, size_t signatureSize)
{
    //Based on mbedtls_ecdsa_read_signature_restartable()

    int ret;
    unsigned char* p = (unsigned char*)signature;
    const unsigned char* end = signature + signatureSize;
    size_t len;
    size_t rlen;
    size_t slen;
    size_t mpiPos;
    mbedtls_mpi r;
    mbedtls_mpi s;
    std::vector<uint8_t> result;

    if(signature == nullptr || signatureSize == 0) return std::vector<uint8_t>();

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( p + len != end )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &r ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &s ) ) != 0 )
    {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }


    rlen = r.n * sizeof(mbedtls_mpi_uint); //sizeof(mbedtls_mpi_uint) is equivalent to ciL
    slen = s.n * sizeof(mbedtls_mpi_uint); //sizeof(mbedtls_mpi_uint) is equivalent to ciL
    result.reserve(4 + rlen + 4 + slen);

    {
        std::vector<uint8_t> mpiBuffer;
        mpiBuffer.resize(rlen, 0);
        ret = mbedtls_mpi_write_binary(&r, mpiBuffer.data(), rlen);
        if(ret != 0) goto cleanup;

        mpiPos = 0;
        for(auto b : mpiBuffer)
        {
            //Remove leading zeros except if first bit of next byte is 1 => removing the leading zero byte would make the number negative
            if(b != 0 || mpiPos + 1 >= mpiBuffer.size() || (mpiBuffer[mpiPos + 1] & 0x80)) break;
            mpiPos++;
        }

        if(mpiPos == mpiBuffer.size()) goto cleanup;
        I32_TO_U8VECTOR(result, mpiBuffer.size() - mpiPos);
        result.insert(result.end(), mpiBuffer.begin() + mpiPos, mpiBuffer.end());
    }

    {
        std::vector<uint8_t> mpiBuffer;
        mpiBuffer.resize(slen, 0);
        ret = mbedtls_mpi_write_binary(&s, mpiBuffer.data(), slen);
        if(ret != 0)
        {
            result.clear();
            goto cleanup;
        }

        mpiPos = 0;
        for(auto b : mpiBuffer)
        {
            //Remove leading zeros except if first bit of next byte is 1 => removing the leading zero byte would make the number negative
            if(b != 0 || mpiPos + 1 >= mpiBuffer.size() || (mpiBuffer[mpiPos + 1] & 0x80)) break;
            mpiPos++;
        }

        if(mpiPos == mpiBuffer.size())
        {
            result.clear();
            goto cleanup;
        }
        I32_TO_U8VECTOR(result, mpiBuffer.size() - mpiPos);
        result.insert(result.end(), mpiBuffer.begin() + mpiPos, mpiBuffer.end());
    }
cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if(ret != 0) _errorCode = ret;

    return result;
}

}

