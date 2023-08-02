/* Copyright 2013-2019 Homegear GmbH */

#include "Mellon.hpp"
#include "Uart.hpp"

namespace Mellon
{

uint32_t GD::clockFrequency = (uint32_t)-1;
Gpio GD::ledGreen(SYSCTL_PERIPH_GPIOK, GPIO_PORTK_BASE, GpioDirection::out, 4);
Gpio GD::ledOrange(SYSCTL_PERIPH_GPIOK, GPIO_PORTK_BASE, GpioDirection::out, 5);
//{{{ Launchpad:
/*Gpio GD::ledGreen(SYSCTL_PERIPH_GPION, GPIO_PORTN_BASE, GpioDirection::out, 1);
Gpio GD::ledOrange(SYSCTL_PERIPH_GPION, GPIO_PORTN_BASE, GpioDirection::out, 0);*/
//}}}
Gpio GD::rts(SYSCTL_PERIPH_GPIOH, GPIO_PORTH_BASE, GpioDirection::out, 0);
Gpio GD::cts(SYSCTL_PERIPH_GPIOH, GPIO_PORTH_BASE, GpioDirection::in, 1);
Gpio GD::chargePumpShdn(SYSCTL_PERIPH_GPIOF, GPIO_PORTF_BASE, GpioDirection::out, 4);
Gpio GD::unplugged(SYSCTL_PERIPH_GPIOM, GPIO_PORTM_BASE, GpioDirection::in, 6);
Gpio GD::vbusSensePlus(SYSCTL_PERIPH_GPIOC, GPIO_PORTC_BASE, GpioDirection::in, 6); //Unused, configure as input without pull-up or pull-down

bool GD::loggedIn = false;
bool GD::adminMode = false;
std::array<uint8_t, 32> GD::unlockKey{0};
bool GD::encryptionKeySet = false;
std::array<uint8_t, 32> GD::encryptionKey{0};
uint32_t GD::dhParamsGenerationTime = 0;
mbedtls_dhm_context GD::dhParams{};
std::unique_ptr<Uart> GD::uart;

void GD::init()
{
    mbedtls_dhm_init(&Mellon::GD::dhParams); //Without this, cleanup() in main.cpp crashes Mellon when calling mbedtls_dhm_free() and dhParams.len is not null
}

void GD::safeAppendZero(std::vector<uint8_t>& vector)
{
    std::vector<uint8_t> tempVector;
    tempVector.reserve(vector.size() + 1);
    tempVector.insert(tempVector.end(), vector.begin(), vector.end());
    tempVector.push_back(0);
    vector.swap(tempVector);
    std::fill(tempVector.begin(), tempVector.end(), 0);
}

void GD::safeShrinkToFit(std::vector<uint8_t>& vector)
{
    std::vector<uint8_t> tempVector;
    tempVector.reserve(vector.size());
    tempVector.insert(tempVector.end(), vector.begin(), vector.end());
    vector.swap(tempVector);
    std::fill(tempVector.begin(), tempVector.end(), 0);
}

}
