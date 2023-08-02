/* Copyright 2013-2019 Homegear GmbH */

#include "Aes.hpp"

namespace Mellon
{

Aes::Aes()
{
    _slot = -1;

    reset();
}

Aes::Aes(size_t slot)
{
    _slot = slot;

    reset();
}

Aes::~Aes()
{
    std::fill(_key.begin(), _key.end(), 0);

    SysCtlPeripheralDisable(SYSCTL_PERIPH_CCM0);
    SysCtlPeripheralReset(SYSCTL_PERIPH_CCM0);
}

void Aes::reset()
{
    //
    // Disable clock to CCM0 and reset the module from  system control and then
    // enable the clock.
    //
    SysCtlPeripheralDisable(SYSCTL_PERIPH_CCM0);
    SysCtlPeripheralReset(SYSCTL_PERIPH_CCM0);
    SysCtlPeripheralEnable(SYSCTL_PERIPH_CCM0);

    //
    // Wait for the peripheral to be ready.
    //
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_CCM0));

    //
    // Reset AES Module.
    //
    AESReset(AES_BASE);
}

bool Aes::eraseKey()
{
    if(_slot >= FLASH_AES_KEY_SLOT_COUNT || _slot < 0 || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet) return false;

    return Flash::eraseSlot(_slot, FLASH_AES_KEY_ADDRESS, FLASH_AES_KEY_SLOT_COUNT, AES_KEY_SLOT_SIZE);
}

bool Aes::writeKey(uint8_t* key, size_t size)
{
    bool returnValue = false;
    std::vector<uint8_t> encryptedData;

    if(key == nullptr || size != 32 || _slot >= FLASH_AES_KEY_SLOT_COUNT || _slot < 0 || !GD::loggedIn || !GD::adminMode || !GD::encryptionKeySet)
    {
        goto cleanup;
    }

    encryptedData = encrypt(GD::encryptionKey, key, size);
    if(encryptedData.empty())
    {
        goto cleanup;
    }

    if(!Flash::writeSlot(_slot, FLASH_AES_KEY_ADDRESS, FLASH_AES_KEY_SLOT_COUNT, AES_KEY_SLOT_SIZE, encryptedData.data(), encryptedData.size()))
    {
        goto cleanup;
    }

    returnValue = true;

cleanup:
    std::fill(key, key + size, 0);
    reset();
    return returnValue;
}

bool Aes::loadKey()
{
    bool returnValue = false;

    //{{{ Variables to clean up
    std::vector<uint8_t> decryptedData;
    //}}}

    if(_slot >= FLASH_AES_KEY_SLOT_COUNT || _slot < 0 || !GD::loggedIn || !GD::encryptionKeySet)
    {
        goto cleanup;
    }

    {
        uint32_t address = FLASH_AES_KEY_ADDRESS + (_slot * AES_KEY_SLOT_SIZE);
        uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
        uint8_t* data = nullptr;
        size_t dataSize = 0;
        if((metadata >> 24) != 1) goto cleanup;
        dataSize = metadata & 0xFFFF;
        if(dataSize == 0 || dataSize > AES_KEY_SLOT_SIZE - 4) goto cleanup;
        data = (uint8_t*)(address + 4);

        decryptedData = decrypt(GD::encryptionKey, data, dataSize);

        if(decryptedData.size() != 32) goto cleanup;

        std::copy(decryptedData.begin(), decryptedData.end(), _key.begin());
    }

    returnValue = true;

cleanup:
    std::fill(decryptedData.begin(), decryptedData.end(), 0);
    reset();
    return returnValue;
}

std::vector<uint8_t> Aes::encrypt(const uint8_t* data, size_t size)
{
    if(!loadKey()) return std::vector<uint8_t>();

    return encrypt(_key, data, size);
}

std::vector<uint8_t> Aes::encrypt(const std::array<uint8_t, 32>& key, const uint8_t* data, size_t size)
{
    if(data == nullptr || size == 0) return std::vector<uint8_t>();
    if(!Trng::isReady())
    {
        _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
        return std::vector<uint8_t>();
    }

    size_t blockSize = ((((size + _lengthSize) - 1) / _blockSize) + 1) * _blockSize;
    if(blockSize > _maxAesBufferSize) return std::vector<uint8_t>();

    AESConfigSet(AES_BASE, (AES_CFG_KEY_SIZE_256BIT | AES_CFG_DIR_ENCRYPT | AES_CFG_MODE_GCM_HY0CALC));

    bool valid = false;
    auto& randomBytes = Trng::generateRandomBytes(_ivSize, valid);
    if(!valid)
    {
        _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
        return std::vector<uint8_t>();
    }
    std::array<uint8_t, _ivSize> iv;
    std::copy(randomBytes.begin(), randomBytes.begin() + _ivSize, iv.begin());
    AESIVSet(AES_BASE, (uint32_t*)iv.data());

    AESKey1Set(AES_BASE, (uint32_t*)key.data(), AES_CFG_KEY_SIZE_256BIT);

    std::vector<uint8_t> output;
    output.resize(blockSize + _ivSize);

    std::copy(iv.begin(), iv.end(), output.begin());

    std::vector<uint8_t> input;
    input.reserve(blockSize);
    input.push_back((uint8_t)((size >> 8) & 0xFF));
    input.push_back((uint8_t)(size & 0xFF));
    input.insert(input.end(), data, data + size);
    if(input.size() < blockSize)
    {
        bool valid = false;
        auto& randomBytes = Trng::generateRandomBytes(blockSize - input.size(), valid);
        if(!valid)
        {
            std::fill(input.begin(), input.end(), 0);
            _errorCode = MELLON_ERR_ENTROPY_SOURCE_FAILED;
            return std::vector<uint8_t>();
        }
        input.insert(input.end(), randomBytes.begin(), randomBytes.begin() + (blockSize - input.size()));
    }

    if(!AESDataProcess(AES_BASE, (uint32_t*)input.data(), (uint32_t*)(output.data() + _ivSize), blockSize)) output.clear();

    std::fill(input.begin(), input.end(), 0);

    return output;
}

std::vector<uint8_t> Aes::decrypt(const uint8_t* data, size_t size)
{
    if(!loadKey()) return std::vector<uint8_t>();

    return decrypt(_key, data, size);
}

std::vector<uint8_t> Aes::decrypt(const std::array<uint8_t, 32>& key, const uint8_t* data, size_t size)
{
    if(data == nullptr || size > _maxAesBufferSize + _ivSize || size < _ivSize + _blockSize || (size % 16) != 0) return std::vector<uint8_t>();

    AESConfigSet(AES_BASE, (AES_CFG_KEY_SIZE_256BIT | AES_CFG_DIR_DECRYPT | AES_CFG_MODE_GCM_HY0CALC));

    AESIVSet(AES_BASE, (uint32_t*)data);

    AESKey1Set(AES_BASE, (uint32_t*)key.data(), AES_CFG_KEY_SIZE_256BIT);

    std::vector<uint8_t> outputBuffer;
    outputBuffer.resize(size - _ivSize);

    if(!AESDataProcess(AES_BASE, (uint32_t*)(data + _ivSize), (uint32_t*)outputBuffer.data(), size - _ivSize)) return std::vector<uint8_t>();

    size_t dataSize = (((size_t)outputBuffer[0]) << 8) | outputBuffer[1];
    if(dataSize + 2 > outputBuffer.size()) return std::vector<uint8_t>();
    std::vector<uint8_t> output(outputBuffer.begin() + 2, outputBuffer.begin() + 2 + dataSize);

    return output;
}

} /* namespace Mellon */
