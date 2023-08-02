/* Copyright 2013-2019 Homegear GmbH */

#include <Uart.hpp>

namespace Mellon
{

Uart::Uart(const UartSettings& settings)
{
    _settings = settings;
    _rxBuffer.reserve(_uartBufferSize);

    //Enable UART peripherals
    SysCtlPeripheralEnable(_settings.uartPeripheral);
    SysCtlPeripheralEnable(_settings.portPeripheral);
    while(!SysCtlPeripheralReady(_settings.uartPeripheral));
    while(!SysCtlPeripheralReady(_settings.portPeripheral));

    //Set pins as UART pins
    GPIOPinConfigure(_settings.rxPinConfig);
    GPIOPinConfigure(_settings.txPinConfig);
    GPIOPinTypeUART(_settings.portBase, (1 << _settings.rxPin) | (1 << _settings.txPin));

    UARTConfigSetExpClk(_settings.uartBase, Mellon::GD::clockFrequency, _settings.baudRate, _settings.flags);

    //Enable interrupts
    Callback<void(void)>::storedMethod = std::bind(&Uart::interruptHandler, this);
    UARTIntRegister(_settings.uartBase, static_cast<interruptType>(Callback<void(void)>::callback));
    IntEnable(_settings.uartInterrupt);
    UARTIntEnable(_settings.uartBase, UART_INT_RX | UART_INT_RT);
}

Uart::~Uart()
{
}

void Uart::interruptHandler()
{
    //Get interrupt status
    uint32_t status = UARTIntStatus(_settings.uartBase, true);
    int32_t result = 0;

    //Clear interrupt
    UARTIntClear(_settings.uartBase, status);

    while(UARTCharsAvail(_settings.uartBase))
    {
        result = UARTCharGetNonBlocking(_settings.uartBase);
        if(result == -1) break; //Shouldn't happen
        uint8_t data = (uint8_t)result;
        if(data >= 0xF2)
        {
            if(_status == UartStatus::unset || (UartStatus)data == UartStatus::nack) _status = (UartStatus)data;
            continue;
        }
        if(_finished || (_rxBuffer.empty() && data != _uartStart))
        {
            UARTCharPutNonBlocking(_settings.uartBase, (uint8_t)UartStatus::nack);
            while(UARTCharsAvail(_settings.uartBase))
            {
                UARTCharGetNonBlocking(_settings.uartBase);
            }
            continue;
        }
        if(data == _uartStart) //Start byte => reset
        {
            _escape = false;
            _rxBuffer.clear();
        }
        else if(_escape)
        {
            data |= 0x80;
            _escape = false;
        }
        else if(data == _uartEscape)
        {
            _escape = true;
            continue;
        }
        if(_rxBuffer.size() + 1 > _rxBuffer.capacity() && _rxBuffer.size() > 3)
        {
            size_t requiredSize = ((((size_t)_rxBuffer.at(1)) << 8) | _rxBuffer.at(2)) + 3;
            if(requiredSize > _uartBufferSize)
            {
                _rxBuffer.clear();
                _rxBuffer.shrink_to_fit();
                _rxBuffer.reserve(_uartBufferSize);
                UARTCharPutNonBlocking(_settings.uartBase, (uint8_t)UartStatus::tooMuchData);
                continue;
            }
            _rxBuffer.reserve(requiredSize);
        }
        _rxBuffer.push_back(data);
        if(_rxBuffer.size() > 3 && _rxBuffer.size() == ((((size_t)_rxBuffer.at(1)) << 8) | _rxBuffer.at(2)) + 3)
        {
            _finished = true;
        }
    }
}

void Uart::flushRx()
{
    std::fill(_rxBuffer.begin(), _rxBuffer.end(), 0);
    _rxBuffer.clear();
    if(_rxBuffer.capacity() > _uartBufferSize)
    {
        _rxBuffer.shrink_to_fit();
        _rxBuffer.reserve(_uartBufferSize);
    }
    _finished = false;
    _escape = false;
}

void Uart::rawSendBlocking(uint8_t data)
{
    UARTCharPut(_settings.uartBase, data);
}

void Uart::rawSendNonBlocking(uint8_t data)
{
    while(!UARTCharPutNonBlocking(_settings.uartBase, data));
}

void Uart::sendBlocking(uint8_t data)
{
    if(data >= 0xF0)
    {
        rawSendBlocking(_uartEscape);
        rawSendBlocking(data & 0x7F);
    }
    else rawSendBlocking(data);
}

void Uart::sendNonBlocking(uint8_t data)
{
    if(data >= 0xF0)
    {
        rawSendNonBlocking(_uartEscape);
        rawSendNonBlocking(data & 0x7F);
    }
    else rawSendNonBlocking(data);
}

void Uart::send(const std::vector<uint8_t>& data)
{
    send(data.data(), data.size());
}

void Uart::send(const uint8_t* data, size_t size)
{
    if(size == 0) return;
    _status = UartStatus::unset;
    for(int i = 0; i < 10; i++)
    {
        if(_status == UartStatus::nack)
        {
            SysCtlDelay(GD::clockFrequency / (80 * 4)); //12.5 ms
            _status = UartStatus::unset;
        }

        rawSendNonBlocking(_uartStart);
        sendNonBlocking(size >> 8);
        sendNonBlocking(size & 0xFF);

        for(size_t j = 0; j < size - 1; j++)
        {
            sendNonBlocking(data[j]);
        }

        sendBlocking(data[size - 1]);

        for(int j = 0; j < 1000; j++)
        {
            if(_status != UartStatus::unset) break;
            SysCtlDelay(GD::clockFrequency / (1000 * 4)); //1 ms
        }

        if(_status == UartStatus::ack) break;
    }
}

void Uart::sendOutput(const std::string& message)
{
    std::vector<uint8_t> data;
    data.reserve(1 + message.size());
    data.push_back(0xE0);
    data.insert(data.end(), message.begin(), message.end());
    send(data.data(), data.size());
}

void Uart::sendStatus(UartStatus status)
{
    rawSendBlocking((uint8_t)status);
}

}
