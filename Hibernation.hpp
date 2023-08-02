/* Copyright 2013-2019 Homegear GmbH */

#ifndef HIBERNATION_HPP_
#define HIBERNATION_HPP_

#include "Mellon.hpp"

namespace Mellon
{

class Hibernation
{
public:
    ~Hibernation() = default;

    static void init();
    static bool getBatteryLow();
    static void setData(size_t offset, uint32_t data);
    static uint32_t getData(size_t offset);
    static uint32_t getLastHibernation(uint8_t& state);
private:
    Hibernation() = delete;

    static void interruptHandler();
};

} /* namespace Mellon */

#endif
