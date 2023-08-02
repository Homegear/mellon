/* Copyright 2013-2019 Homegear GmbH */

#ifndef TRNG_HPP_
#define TRNG_HPP_

#include "Mellon.hpp"

#include <array>

#define MELLON_ERR_ENTROPY_SOURCE_FAILED                 -0x003C

namespace Mellon
{

struct TrngProbabilities
{
    uint8_t lastBits = 0;
    uint32_t probability1 = 0x40000000ul;
    uint32_t probability0To0 = 0x20000000ul;
    uint32_t probability0To1 = 0x20000000ul;
    uint32_t probability1To0 = 0x20000000ul;
    uint32_t probability1To1 = 0x20000000ul;
};

struct TrngData
{
    uint32_t mean = (2000ul << 20);
    uint32_t median = (2000ul << 20);
    int16_t offset = 0;
    uint16_t omitCounter = 0;
    uint32_t cycleCounter = 0;
    uint32_t cycleCounter2 = 0;
    uint8_t bytesAvailable = 0;
    uint8_t bufferBytePos = 0;
    uint8_t bufferBitPos = 0;
    uint8_t bufferByte = 0;
    std::array<uint8_t, 256> buffer;
};


class Trng
{
public:
    ~Trng() = default;
    static void init();
    static bool isReady();
    static std::array<uint8_t, 256>& generateRandomBytes(uint8_t count, bool& valid);
    static uint32_t getMean() { return _trngData->mean; }
    static uint32_t getMedian() { return _trngData->median; }
    static uint32_t getMedianOffset() { return _trngData->offset; }
    static uint32_t getCycleCounter() { return _trngData->cycleCounter; }
    static TrngProbabilities& getProbabilities() { return *_probabilities; }
    static bool randomDelay(size_t min, size_t max);
    static int32_t mbedTlsGetRandomNumbers(void* data, uint8_t* output, size_t len);
private:
    //{{{ TRNG generation
        static std::unique_ptr<TrngData> _trngData;
    //}}}

    //{{{ Autocorrelation
        static std::unique_ptr<TrngProbabilities> _probabilities;
    //}}}

    static uint8_t _bufferReadPos;
    //Even though maximum count is 255 maximum buffer size needs to be 256 as we need a multiple of 32 for hashing.
    static std::unique_ptr<std::array<uint8_t, 256>> _trngOutputBuffer;

    Trng() = delete;

    static void interruptHandler();
};

} /* namespace Mellon */

#endif /* TRNG_HPP_ */
