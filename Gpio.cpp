/* Copyright 2013-2019 Homegear GmbH */

#include <Gpio.hpp>

#include "driverlib/inc/hw_gpio.h"

namespace Mellon
{

Gpio::Gpio(Register peripheral, Register port, GpioDirection direction, GpioPinIndex pin)
{
    _peripheral = peripheral;
    _port = port;
    _direction = direction;
    _pinValue = 1 << pin;

    SysCtlPeripheralEnable(peripheral);
    setDirection(_direction);
}

void Gpio::setDirection(GpioDirection gpioDirection)
{
    _direction = gpioDirection;
    if((bool)gpioDirection) GPIOPinTypeGPIOOutput(_port, HWREG(_port + GPIO_O_PC) | _pinValue);
    else GPIOPinTypeGPIOInput(_port, HWREG(_port + GPIO_O_PC) | _pinValue);
}

void Gpio::setHigh()
{
    GPIOPinWrite(_port, _pinValue, _pinValue);
}

void Gpio::setLow()
{
    GPIOPinWrite(_port, _pinValue, 0);
}

void Gpio::toggleState()
{
    if(GPIOPinRead(_port, _pinValue) == _pinValue) GPIOPinWrite(_port, _pinValue, 0);
    else GPIOPinWrite(_port, _pinValue, _pinValue);
}

bool Gpio::getState()
{
    return GPIOPinRead(_port, _pinValue) == _pinValue;
}

}
