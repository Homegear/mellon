/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_UART_H
#define MELLON_UART_H

#include "Mellon.hpp"

#include <cstdint>
#include <array>
#include <vector>
#include <string>

namespace Mellon
{

enum class UartStatus : uint8_t
{
    unset =            0x00,
    ack =              0xF2,
    unknownCommand =   0xF3,
    wrongPayloadSize = 0xF4,
    unknownError =     0xF5,
    tryAgainLater =    0xF6,
    heapOverflow =     0xF7,
    tooMuchData =      0xF8,
    resetNeeded =      0xF9,
    unauthorized =     0xFA,
    locked =           0xFB,
    invalidTime =      0xFC,
    reserved5 =        0xFD,
    reserved6 =        0xFE,
    nack =             0xFF
};

struct UartSettings
{
    Register uartPeripheral = (uint32_t)-1; //E. g. SYSCTL_PERIPH_UART7
    Register portPeripheral = (uint32_t)-1; //E. g. SYSCTL_PERIPH_GPIOC
    Register uartBase = (uint32_t)-1; //E. g. UART7_BASE
    Register portBase = (uint32_t)-1; //E. g. GPIO_PORTC_BASE
    GpioPinIndex rxPin = (uint8_t)-1; //E. g. 4
    GpioPinIndex txPin = (uint8_t)-1; //E. g. 5
    GpioPinConfig rxPinConfig = (uint32_t)-1; //E. g. GPIO_PC4_U7RX
    GpioPinConfig txPinConfig = (uint32_t)-1; //E. g. GPIO_PC5_U7TX
    Interrupt uartInterrupt = (uint32_t)-1; //E. g. INT_UART7
    uint32_t baudRate = 115200;
    uint32_t flags = UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE;
};

class Uart
{
public:
    Uart(const UartSettings& settings);
    ~Uart();

    bool finished() { return _finished; }
    std::vector<uint8_t> rxBuffer() { return _rxBuffer; }

    void flushRx();
    void send(const std::vector<uint8_t>& data);
    void send(const uint8_t* data, size_t size);
    void sendOutput(const std::string& message);
    void sendStatus(UartStatus status);
private:
    static const size_t _uartBufferSize = 8220;
    static const uint8_t _uartStart = 0xF0;
    static const uint8_t _uartEscape = 0xF1;

    UartSettings _settings;
    std::vector<uint8_t> _rxBuffer;
    bool _finished = false;
    bool _escape = false;
    bool _sending = false;
    UartStatus _status = UartStatus::unset;

    void interruptHandler();

    inline void rawSendBlocking(uint8_t byte);
    inline void rawSendNonBlocking(uint8_t byte);
    inline void sendBlocking(uint8_t byte);
    inline void sendNonBlocking(uint8_t byte);
};

}

#endif
