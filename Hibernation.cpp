/* Copyright 2013-2019 Homegear GmbH */

#include "Hibernation.hpp"
#include "User.hpp"

#include "driverlib/inc/hw_hibernate.h"

namespace Mellon
{

void Hibernation::interruptHandler()
{
    if(ComparatorIntStatus(COMP_BASE, 0, true))
    {
        setData(4, HibernateRTCGet());
        setData(8, 0xAAAAAAA1);

        ComparatorIntClear(COMP_BASE, 0);
        User::logout();

        setData(8, 0xAAAAAAA0);

        HibernateRequest();
    }
}

void Hibernation::init()
{
    SysCtlPeripheralEnable(SYSCTL_PERIPH_HIBERNATE);

    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOC);
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOD);

    GPIOPinTypeComparator(GPIO_PORTC_BASE, GPIO_PIN_7);
    GPIOPinConfigure(GPIO_PD0_C0O);
    GPIOPinTypeComparatorOutput(GPIO_PORTD_BASE, GPIO_PIN_0);

    SysCtlPeripheralEnable(SYSCTL_PERIPH_COMP0);
    while(!(SysCtlPeripheralReady(SYSCTL_PERIPH_COMP0)));

    ComparatorConfigure(COMP_BASE, 0, (COMP_INT_FALL | COMP_ASRCP_REF));
    ComparatorRefSet(COMP_BASE, COMP_REF_1_65V);
    ComparatorIntEnable(COMP_BASE, 0);
    ComparatorIntRegister(COMP_BASE, 0, &Hibernation::interruptHandler);

    HibernateLowBatSet(HIBERNATE_LOW_BAT_DETECT | HIBERNATE_LOW_BAT_2_5V);
}

uint32_t Hibernation::getLastHibernation(uint8_t& state)
{
    state = getData(8) & 0xF;
    return getData(4);
}

uint32_t Hibernation::getData(size_t offset)
{
    if(offset % 4 != 0 || offset > 12) return 0;
    return HWREG(HIB_DATA + offset);
}

void Hibernation::setData(size_t offset, uint32_t data)
{
    if(offset % 4 != 0 || offset > 12) return;
    HWREG(HIB_DATA + offset) = data;
    while(!(HWREG(HIB_CTL) & HIB_CTL_WRC)); //Wait for write completion
}

bool Hibernation::getBatteryLow()
{
    HibernateBatCheckStart();
    while(HibernateBatCheckDone());
    auto status = HibernateIntStatus(true);
    HibernateIntClear(status);
    return (status & HIBERNATE_INT_LOW_BAT) == HIBERNATE_INT_LOW_BAT;
}

} /* namespace Mellon */
