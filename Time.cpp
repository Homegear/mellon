/* Copyright 2013-2019 Homegear GmbH */

#include "Time.hpp"
#include "Flash.hpp"
#include "User.hpp"

namespace Mellon
{

void Time::init()
{
    SysCtlPeripheralEnable(SYSCTL_PERIPH_HIBERNATE);
    if(!HibernateIsActive())
    {
        HibernateEnableExpClk(32768); //The argument is not used by the function.
        HibernateClockConfig(HIBERNATE_OSC_LOWDRIVE);
        HibernateRTCEnable();
        HibernateCounterMode(HIBERNATE_COUNTER_RTC);
    }

    //#warning Remove comment
    if(HibernateRTCGet() <= 1000000000ul) Flash::eraseAll();
}

uint32_t Time::get()
{
    return HibernateRTCGet();
}

bool Time::set(uint32_t time)
{
    if(HibernateRTCGet() > 1000000000ul)
    {
        // Time already is set. Only allow correction of a time drift.
        // Every 23 hours a correction of 1 minute is allowed.

        if(!GD::loggedIn) return false;

        uint32_t currentTime = HibernateRTCGet();
        uint32_t lastSet = 0;
        HibernateDataGet(&lastSet, 1);
        if(currentTime - lastSet >= 82800)
        {
            if(time >= currentTime)
            {
                if(time - currentTime > 60) time = currentTime + 60;
            }
            else
            {
                if(currentTime - time > 60) time = currentTime - 60;
            }
            HibernateRTCSet(time);
            lastSet = time;
            HibernateDataSet(&lastSet, 1);
            return true;
        }
        else return false;
    }
    else
    {
        uint32_t timeBefore = HibernateRTCGet();

        User::logout();
        if(!Flash::eraseAll())
        {
            return false;
        }

        time += (HibernateRTCGet() - timeBefore);
        HibernateRTCSet(time);
        HibernateDataSet(&time, 1);
        return true;
    }
}

void Time::reset()
{
    HibernateRTCSet(0);
}

bool Time::isValid()
{
    return HibernateRTCGet() > 1000000000ul;
}

} /* namespace Mellon */
