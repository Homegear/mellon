/* Copyright 2013-2019 Homegear GmbH */

#include <Trng.hpp>

#include <cmath>
#include "mbedtls/sha256.h"

namespace Mellon
{

std::unique_ptr<TrngData> Trng::_trngData;
std::unique_ptr<TrngProbabilities> Trng::_probabilities;
uint8_t Trng::_bufferReadPos;
std::unique_ptr<std::array<uint8_t, 256>> Trng::_trngOutputBuffer;

void Trng::interruptHandler()
{
    // Get the interrupt status from the ADC
    auto getIntStatus = ADCIntStatus(ADC0_BASE, 3, true);

    // If the interrupt status for Sequencer 3 is set, clear the status and read the data
    if(getIntStatus == 0x8)
    {
        // Clear the ADC interrupt flag.
        ADCIntClear(ADC0_BASE, 3);

        // Read ADC Value.
        uint32_t randomNumber;
        ADCSequenceDataGet(ADC0_BASE, 3, &randomNumber);

        _trngData->omitCounter++;
        if((_trngData->omitCounter & 0x1F) != 0) return;

        if(!(_trngData->cycleCounter & 0xFFC00000ul))
        {
            _trngData->cycleCounter++;
            if(!(_trngData->cycleCounter & 0xFFF80000ul))
            {
                _trngData->median += randomNumber > (_trngData->median >> 20) ? 10000 : -10000;
            }
            else if(!(_trngData->cycleCounter & 0xFFF00000ul))
            {
                _trngData->median += randomNumber > (_trngData->median >> 20) ? 1000 : -1000;
            }
            else if(!(_trngData->cycleCounter & 0xFFE00000ul))
            {
                _trngData->median += randomNumber > (_trngData->median >> 20) ? 100 : -100;
            }
        }
        else
        {
            if(!(_trngData->cycleCounter2 & 0xFFF00000)) _trngData->cycleCounter2++;
            else
            {
                if(_probabilities->probability1 > 1073849198) _trngData->offset += 1;  //> 0.50005
                else if(_probabilities->probability1 < 1073634450) _trngData->offset -= 1;  //< 0.49995
                if(_trngData->offset > 1000) _trngData->offset = 1000;
                else if(_trngData->offset < -1000) _trngData->offset = -1000;
                _trngData->cycleCounter2 = 0;
            }
        }

        //{{{ Mean
            _trngData->mean = (_trngData->mean - (_trngData->mean >> 20)) + randomNumber;
        //}}}

        //{{{ Median
            _trngData->median += randomNumber > (_trngData->median >> 20) ? 10 : -10;
        //}}}

        //{{{ Autocorrelation
            _probabilities->lastBits = (_probabilities->lastBits << 1);
        //}}}

        if(randomNumber > (_trngData->median >> 20) + _trngData->offset)
        {
            _trngData->bufferByte |= 1 << _trngData->bufferBitPos;

            //{{{ Autocorrelation
                _probabilities->lastBits |= 1;
            //}}}

            //{{{ Probability for 1
                _probabilities->probability1 = (_probabilities->probability1 - (_probabilities->probability1 >> 20)) + 2048;
            //}}}
        }
        else
        {
            //{{{ Probability for 1
                _probabilities->probability1 = _probabilities->probability1 - (_probabilities->probability1 >> 20);
            //}}}
        }

        //{{{ Autocorrelation
            if(_probabilities->lastBits & 1) //Current bit is 1
            {
                _probabilities->probability1To0 = (_probabilities->probability1To0 - (_probabilities->probability1To0 >> 20));
                _probabilities->probability0To0 = (_probabilities->probability0To0 - (_probabilities->probability0To0 >> 20));
                if(_probabilities->lastBits & 2) //Last bit is 1 => 1 to 1
                {
                    _probabilities->probability1To1 = (_probabilities->probability1To1 - (_probabilities->probability1To1 >> 20)) + 2048;
                    _probabilities->probability0To1 = (_probabilities->probability0To1 - (_probabilities->probability0To1 >> 20));
                }
                else //Last bit is 0 => 0 to 1
                {
                    _probabilities->probability0To1 = (_probabilities->probability0To1 - (_probabilities->probability0To1 >> 20)) + 2048;
                    _probabilities->probability1To1 = (_probabilities->probability1To1 - (_probabilities->probability1To1 >> 20));
                }
            }
            else //Current bit is 0
            {
                _probabilities->probability1To1 = (_probabilities->probability1To1 - (_probabilities->probability1To1 >> 20));
                _probabilities->probability0To1 = (_probabilities->probability0To1 - (_probabilities->probability0To1 >> 20));
                if(_probabilities->lastBits & 2) //Last bit is 1 => 1 to 0
                {
                    _probabilities->probability1To0 = (_probabilities->probability1To0 - (_probabilities->probability1To0 >> 20)) + 2048;
                    _probabilities->probability0To0 = (_probabilities->probability0To0 - (_probabilities->probability0To0 >> 20));
                }
                else //Last bit is 0 => 0 to 0
                {
                    _probabilities->probability0To0 = (_probabilities->probability0To0 - (_probabilities->probability0To0 >> 20)) + 2048;
                    _probabilities->probability1To0 = (_probabilities->probability1To0 - (_probabilities->probability1To0 >> 20));
                }
            }
        //}}}

        _trngData->bufferBitPos++;
        if(_trngData->bufferBitPos >= 8)
        {
            _trngData->buffer[_trngData->bufferBytePos] = _trngData->bufferByte;
            _trngData->bufferBytePos++;
            _trngData->bufferByte = 0;
            _trngData->bufferBitPos = 0;
            if(_trngData->bytesAvailable < 255) _trngData->bytesAvailable++;
        }
    }
}

void Trng::init()
{
    _trngData = std::make_unique<TrngData>();
    _trngOutputBuffer = std::make_unique<std::array<uint8_t, 256>>();
    _probabilities = std::make_unique<TrngProbabilities>();
    _bufferReadPos = 0;

    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOE);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOE));
    GPIOPinTypeADC(GPIO_PORTE_BASE, GPIO_PIN_3);

    // Enable the clock to ADC-0 and wait for it to be ready
    SysCtlPeripheralEnable(SYSCTL_PERIPH_ADC0);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_ADC0));

    ADCClockConfigSet(ADC0_BASE, ADC_CLOCK_SRC_PLL | ADC_CLOCK_RATE_EIGHTH, 30);

    ADCReferenceSet(ADC0_BASE, ADC_REF_INT);

    // Configure Sequencer 3 to sample a single analog channel
    // Sequencer 3 is the only one with one sample
    ADCSequenceStepConfigure(ADC0_BASE, 3, 0, ADC_CTL_CH0 | ADC_CTL_IE | ADC_CTL_SHOLD_4 | ADC_CTL_END);

    // Enable sample sequence 3 with a timer signal trigger. Sequencer 2 will do a single sample when the timer generates a trigger on timeout.
    ADCSequenceConfigure(ADC0_BASE, 3, ADC_TRIGGER_ALWAYS, 0);

    // Sample sequence 3 is now configured. It must be enabled.
    ADCSequenceEnable(ADC0_BASE, 3);

    // Clear the interrupt status flag before enabling. This is done to make sure the interrupt flag is cleared before we sample.
    ADCIntClear(ADC0_BASE, 3);
    ADCIntEnable(ADC0_BASE, 3);

    // Register interrupt handler (also enables interrupt)
    ADCIntRegister(ADC0_BASE, 3, &Trng::interruptHandler);
}

bool Trng::isReady()
{
    //Uncomment for debugging - makes Trng ready immediately
    /*#warning Comment the following line
    return true;*/

    if(_trngData->cycleCounter < 0x80000 || //< 524288 cycles
       _trngData->median < _trngData->mean ||
       _trngData->median - _trngData->mean > 1048576000ul || //> 1000
       _trngData->median < 1048576000ul || _trngData->median > 3670016000ul || //< 1000 || > 3200
       _probabilities->probability1 < 1052770304ul || _probabilities->probability1 > 1094713344ul ||     //Between 0,49 [(0,49 * 2048) << 20] and 0,51
       _probabilities->probability0To0 < 515899392ul || _probabilities->probability0To0 > 557842432ul || //Between 0,24 and 0,26
       _probabilities->probability0To1 < 515899392ul || _probabilities->probability0To1 > 557842432ul || //Between 0,24 and 0,26
       _probabilities->probability1To0 < 515899392ul || _probabilities->probability1To0 > 557842432ul || //Between 0,24 and 0,26
       _probabilities->probability1To1 < 515899392ul || _probabilities->probability1To1 > 557842432ul    //Between 0,24 and 0,26
       )
    {
        return false;
    }
    return true;
}

std::array<uint8_t, 256>& Trng::generateRandomBytes(uint8_t count, bool& valid)
{
    valid = false;
    if(!isReady()) return *_trngOutputBuffer;

    int16_t alignedCount = count; //Maximum aligned Count is 256
    if((alignedCount & 0x1F) != 0) alignedCount = alignedCount + (32 - (alignedCount & 0x1F));

    std::array<uint8_t, 32> trngHashBuffer;

    for(int i = 0; i < alignedCount; i += 32)
    {
        for(int j = 0; j < 32; j++)
        {
            while(_trngData->bytesAvailable == 0)
            {
                //Interrupt hangs if we don't wait here
                SysCtlDelay(Mellon::GD::clockFrequency / (100 * 4)); //10 ms
            }
            trngHashBuffer[j] = _trngData->buffer[_bufferReadPos++];

            //For debugging: Directly write data to output buffer
            //#warning Hash result
            //(*_trngOutputBuffer)[i + j] = _trngData->buffer[_bufferReadPos++];

            _trngData->bytesAvailable--;
        }

        if(mbedtls_sha256_ret(trngHashBuffer.data(), trngHashBuffer.size(), _trngOutputBuffer->data() + i, 0) != 0)
        {
            return *_trngOutputBuffer;
        }
    }

    valid = true;
    return *_trngOutputBuffer;
}

bool Trng::randomDelay(size_t min, size_t max)
{
    if(max == 0 || min >= max) return false;
    if(!isReady()) return false;
    bool valid = false;
    auto randomBytes = Trng::generateRandomBytes(4, valid);
    if(!valid) return false;
    uint32_t randomInteger = *((uint32_t*)randomBytes.data());
    double waitFor = (((double)randomInteger) / ((double)UINT_MAX / (double)(max - min))) + (double)min;
    SysCtlDelay(std::lround(((double)Mellon::GD::clockFrequency) / (4.0 / waitFor))); //min - max s
    return true;
}

int Trng::mbedTlsGetRandomNumbers(void* data, uint8_t* output, size_t len)
{
    if(len > 65535) return MELLON_ERR_ENTROPY_SOURCE_FAILED;

    size_t remainingBytes = len;
    size_t pos = 0;
    uint8_t count = 0;
    bool valid = false;
    while(remainingBytes > 0)
    {
        valid = false;
        if(remainingBytes > 255) count = 255;
        else count = remainingBytes;

        auto& randomBytes = Trng::generateRandomBytes(count, valid);
        if(!valid) return MELLON_ERR_ENTROPY_SOURCE_FAILED;
        for(int i = 0; i < count; i++)
        {
            output[pos] = randomBytes[i];
            pos++;
        }
        remainingBytes -= count;
    }

    return 0;
}

} /* namespace Mellon */
