/* Copyright 2013-2019 Homegear GmbH */

#ifndef TIME_HPP_
#define TIME_HPP_

#include "Mellon.hpp"

namespace Mellon
{

class Time
{
public:
    ~Time() = default;

    static void init();
    static uint32_t get();
    static bool set(uint32_t timestamp);
    static void reset();
    static bool isValid();
private:
    Time() = delete;
};

} /* namespace Mellon */

#endif /* TIME_HPP_ */
