/* Copyright 2013-2019 Homegear GmbH */

#ifndef AES_HPP_
#define AES_HPP_

#include "Mellon.hpp"
#include "Flash.hpp"
#include "Trng.hpp"

#include <vector>

namespace Mellon
{

class Aes
{
public:
    Aes();
    Aes(size_t slot);
    ~Aes();

    int32_t getErrorCode() { return _errorCode; }

    bool writeKey(uint8_t* key, size_t size);
    bool eraseKey();

    /**
     * Encrypts data using 256 bit AES-GCM.
     *
     * @param data The data to encrypt.
     * @param size The actual size of the data (not the buffer size).
     */
    std::vector<uint8_t> encrypt(const uint8_t* data, size_t size);

    std::vector<uint8_t> decrypt(const uint8_t* data, size_t size);

    std::vector<uint8_t> encrypt(const std::array<uint8_t, 32>& key, const uint8_t* data, size_t size);

    std::vector<uint8_t> decrypt(const std::array<uint8_t, 32>& key, const uint8_t* data, size_t size);
private:
    static const size_t _ivSize = 16;
    static const size_t _blockSize = 16;
    static const size_t _keySize = 32;
    static const size_t _lengthSize = 2;
    static const size_t _maxAesBufferSize = 16384 + 16; //= A maximum of 16398 bytes of data + 2 length bytes

    int32_t _errorCode = 0;
    int32_t _slot = -1;
    std::array<uint8_t, 32> _key{0};

    void reset();
    bool loadKey();
};

} /* namespace Mellon */

#endif /* AES_HPP_ */
