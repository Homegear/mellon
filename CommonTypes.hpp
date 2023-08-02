/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_COMMON_TYPES_H
#define MELLON_COMMON_TYPES_H

#include <cstdint>
#include <functional>

typedef uint32_t Register;
typedef uint32_t Interrupt;

template <typename T> struct Callback;

template <typename ReturnType, typename... Parameters> struct Callback<ReturnType(Parameters...)>
{
   template <typename... Arguments> static ReturnType callback(Arguments... arguments)
   {
      storedMethod(arguments...);
   }
   static std::function<ReturnType(Parameters...)> storedMethod;
};

template <typename ReturnType, typename... Parameters> std::function<ReturnType(Parameters...)> Callback<ReturnType(Parameters...)>::storedMethod;

typedef void (*interruptType)(void);

#endif
