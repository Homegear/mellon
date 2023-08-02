/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_GPIO_H
#define MELLON_GPIO_H

#include "CommonTypes.hpp"

#include <msp.h>
#include "driverlib/driverlib.h"

namespace Mellon
{

typedef uint8_t GpioPinIndex;
typedef uint8_t GpioPinValue;
typedef uint32_t GpioPinConfig;

enum class GpioDirection : uint8_t
{
    in = 0,
    out = 1
};

class Gpio
{
private:
    Register _peripheral = (uint32_t)-1;
    Register _port = (uint32_t)-1;
    GpioDirection _direction = GpioDirection::out;
    GpioPinValue _pinValue = (uint8_t)-1;
public:
    Gpio() = default;

    Gpio(Register peripheral, Register port, GpioDirection direction, GpioPinIndex pin);

    Register getPeripheral() { return _peripheral; }
    Register getPort() { return _port; }
    GpioDirection getDirection() { return _direction; }
    void setDirection(GpioDirection gpioDirection);
    GpioPinValue getPinValue() { return _pinValue; }
    void setHigh();
    void setLow();
    void toggleState();
    bool getState();
};

}

#endif
