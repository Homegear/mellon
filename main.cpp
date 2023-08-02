/* Copyright 2013-2019 Homegear GmbH */

#include "Mellon.hpp"
#include "Uart.hpp"
#include "CommandHandler.hpp"
#include "Trng.hpp"
#include "Time.hpp"
#include "Hibernation.hpp"
#include "Flash.hpp"

#include <string>

uint32_t _lastCleanup = 0;

void watchdogHandler()
{
    WatchdogIntClear(WATCHDOG0_BASE);
}

inline void lock()
{
    // See chapter 7.5.2 and 7.2.3.12
    uint32_t bootConfig = HWREG(FLASH_BOOTCFG);
    if(bootConfig & 3)
    {
        HWREG(FLASH_FMA) = 0x75100000;
        HWREG(FLASH_FMD) = 0x7FFFFFFC;
        HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;
        while(HWREG(FLASH_FMC) & FLASH_FMC_COMT); //Wait for completion
        for(int32_t i = 0; i < 100; i++) //Blink both LEDs for 10 seconds
        {
            Mellon::GD::ledOrange.setHigh();
            Mellon::GD::ledGreen.setHigh();
            SysCtlDelay(Mellon::GD::clockFrequency / (20 * 4)); //50ms
            Mellon::GD::ledOrange.setLow();
            Mellon::GD::ledGreen.setLow();
            SysCtlDelay(Mellon::GD::clockFrequency / (20 * 4)); //50ms
        }

        while(true);
    }
    else
    {
        Mellon::GD::ledGreen.setHigh();
        SysCtlDelay(Mellon::GD::clockFrequency / (1 * 4)); //1s
        Mellon::GD::ledGreen.setLow();
    }
}

inline void disableJtag()
{
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOC);
    GPIOC->LOCK = GPIO_LOCK_KEY;
    GPIOC->CR = 0x01;
    GPIOC->AFSEL &= 0xfe;
    GPIOC->LOCK = GPIO_LOCK_KEY;
    GPIOC->CR = 0x02;
    GPIOC->AFSEL &= 0xfd;
    GPIOC->LOCK = GPIO_LOCK_KEY;
    GPIOC->CR = 0x04;
    GPIOC->AFSEL &= 0xfb;
    GPIOC->LOCK = GPIO_LOCK_KEY;
    GPIOC->CR = 0x08;
    GPIOC->AFSEL &= 0xf7;
    GPIOC->LOCK = GPIO_LOCK_KEY;
    GPIOC->CR = 0x00;
    GPIOC->LOCK = 0;
    GPIOPinTypeGPIOInput(GPIO_PORTC_BASE, (GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3));
}

inline void initClock()
{
    //
    // Set the clocking to run directly from the crystal at 120MHz.
    //
    Mellon::GD::clockFrequency = SysCtlClockFreqSet((SYSCTL_XTAL_16MHZ | SYSCTL_OSC_MAIN | SYSCTL_USE_PLL | SYSCTL_CFG_VCO_480), 120000000);
    //Settings for launchpad:
    //Mellon::GD::clockFrequency = SysCtlClockFreqSet((SYSCTL_XTAL_25MHZ | SYSCTL_OSC_MAIN | SYSCTL_USE_PLL | SYSCTL_CFG_VCO_480), 120000000);

    //
    // Enable processor interrupts.
    //
    IntMasterEnable();
}

inline void initWatchdog()
{
    SysCtlPeripheralEnable(SYSCTL_PERIPH_WDOG0);
    WatchdogIntRegister(WATCHDOG0_BASE, watchdogHandler);
    WatchdogReloadSet(WATCHDOG0_BASE, Mellon::GD::clockFrequency * 5);
    WatchdogResetEnable(WATCHDOG0_BASE);
    WatchdogEnable(WATCHDOG0_BASE);

    SysCtlResetBehaviorSet(SYSCTL_ONRST_WDOG0_POR | SYSCTL_ONRST_WDOG1_POR | SYSCTL_ONRST_BOR_POR | SYSCTL_ONRST_EXT_POR);
}

inline void initGpios()
{
    Mellon::GD::rts.setHigh();
    Mellon::GD::chargePumpShdn.setLow();
}

inline void initUart()
{
    Mellon::UartSettings uartSettings;
    uartSettings.uartPeripheral = SYSCTL_PERIPH_UART0;
    uartSettings.portPeripheral = SYSCTL_PERIPH_GPIOA;
    uartSettings.uartBase = UART0_BASE;
    uartSettings.portBase = GPIO_PORTA_BASE;
    uartSettings.rxPin = 0;
    uartSettings.txPin = 1;
    uartSettings.rxPinConfig = GPIO_PA0_U0RX;
    uartSettings.txPinConfig = GPIO_PA1_U0TX;
    uartSettings.uartInterrupt = INT_UART0;
    uartSettings.baudRate = 1000000;
    uartSettings.flags = UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE;

    //Settings for launchpad:
    /*uartSettings.uartPeripheral = SYSCTL_PERIPHGD::uart7;
    uartSettings.portPeripheral = SYSCTL_PERIPH_GPIOC;
    uartSettings.uartBase = UART7_BASE;
    uartSettings.portBase = GPIO_PORTC_BASE;
    uartSettings.rxPin = 4;
    uartSettings.txPin = 5;
    uartSettings.rxPinConfig = GPIO_PC4_U7RX;
    uartSettings.txPinConfig = GPIO_PC5_U7TX;
    uartSettings.uartInterrupt = INTGD::uart7;
    uartSettings.baudRate = 115200;
    uartSettings.flags = UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE;*/

    Mellon::GD::uart = std::make_unique<Mellon::Uart>(uartSettings);
}

void cleanup()
{
    if(Mellon::Time::get() - _lastCleanup > 60)
    {
        _lastCleanup = Mellon::Time::get();
        if(Mellon::GD::dhParams.len > 0 && Mellon::Time::get() - Mellon::GD::dhParamsGenerationTime > 1800)
        {
            mbedtls_dhm_free(&Mellon::GD::dhParams);
            Mellon::GD::dhParamsGenerationTime = 0;
        }
    }
}

int main(void)
{
    //{{{ Basic init
        //Comment for debugging
        //#warning Uncomment safety function calls
        disableJtag();
        initClock();
        //Comment for debugging
        //#warning Uncomment safety function calls
        lock();
        //Comment for debugging
        //#warning Uncomment this
        initWatchdog();
        Mellon::GD::init();
        initGpios();
    //}}}

    //{{{ Module init
        Mellon::GD::ledOrange.setHigh();
        if(!Mellon::Flash::init()) while(true);
        Mellon::Hibernation::init();
        Mellon::Time::init();
        Mellon::Trng::init();
        initUart();

        Mellon::CommandHandler commandHandler;

        SysCtlDelay(Mellon::GD::clockFrequency / (1 * 4)); //1 s

        Mellon::GD::ledOrange.setLow();
    //}}}

    { // Show hibernation status with LED
        uint32_t data = Mellon::Hibernation::getData(8);
        Mellon::Hibernation::setData(8, data | 2);
        for(size_t i = 0; i < 5; i++) //Blink green LED 5 times
        {
            Mellon::GD::ledGreen.setHigh();
            if(data & 3) Mellon::GD::ledOrange.setHigh(); //Blink orange LED, too when hibernation sequence did not complete.
            SysCtlDelay(Mellon::GD::clockFrequency / (4 * 4)); //250ms
            Mellon::GD::ledGreen.setLow();
            if(data & 3) Mellon::GD::ledOrange.setLow();
            SysCtlDelay(Mellon::GD::clockFrequency / (4 * 4)); //250ms
        }
    }

    //{{{ Debug settings
    /*#warning Comment this
    {
        Mellon::GD::loggedIn = true;
        Mellon::GD::adminMode = true;
        Mellon::GD::encryptionKeySet = true;
        auto key = std::array<uint8_t, 32>{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        std::copy(key.begin(), key.end(), Mellon::GD::encryptionKey.begin());
        key.at(1) = 0x11;
        std::copy(key.begin(), key.end(), Mellon::GD::unlockKey.begin());
    }*/
    //}}}

    while(true)
    {
        cleanup();

        if(Mellon::GD::uart->finished())
        {
            std::vector<uint8_t> packet = Mellon::GD::uart->rxBuffer(); //Copy rx buffer
            Mellon::GD::safeShrinkToFit(packet);
            Mellon::GD::uart->flushRx(); //Now we can receive new data
            Mellon::GD::ledGreen.setHigh();
            if(packet.size() > 3)
            {
                commandHandler.handleCommand((Mellon::Commands)packet.at(3), packet);
                std::fill(packet.begin(), packet.end(), 0);
            }
            Mellon::GD::ledGreen.setLow();
        }
        else
        {
            if(!Mellon::Trng::isReady())
            {
                Mellon::GD::ledOrange.setHigh();
                SysCtlDelay(Mellon::GD::clockFrequency / (10 * 4)); //100 ms
                Mellon::GD::ledOrange.setLow();
                if(Mellon::GD::uart->finished()) continue;
                SysCtlDelay(Mellon::GD::clockFrequency / (10 * 4)); //100 ms
                Mellon::GD::ledOrange.setHigh();
                SysCtlDelay(Mellon::GD::clockFrequency / (10 * 4)); //100 ms
                Mellon::GD::ledOrange.setLow();
                if(Mellon::GD::uart->finished()) continue;
                SysCtlDelay(Mellon::GD::clockFrequency / (10 * 4)); //100 ms
                Mellon::GD::ledOrange.setHigh();
                SysCtlDelay(Mellon::GD::clockFrequency / (10 * 4)); //100 ms
                Mellon::GD::ledOrange.setLow();
                if(Mellon::GD::uart->finished()) continue;
                SysCtlDelay(Mellon::GD::clockFrequency / (2 * 4)); //500 ms
            }
        }
    }
}
