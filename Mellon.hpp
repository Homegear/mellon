/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_DEFINES_H
#define MELLON_DEFINES_H

#include "Gpio.hpp"

#include <cstdint>
#include <array>
#include <vector>
#include <memory>

#include "mbedtls/dhm.h"

#define MELLON_VERSION 0x0105

#define DHPARAMS_MAX_SIZE 512

namespace Mellon
{

class Uart;

#define I64_TO_U8VECTOR(v, n) {v.push_back((uint8_t)(((n) >> 56) & 0xFF));v.push_back((uint8_t)(((n) >> 48) & 0xFF));v.push_back((uint8_t)(((n) >> 40) & 0xFF));v.push_back((uint8_t)(((n) >> 32) & 0xFF));v.push_back((uint8_t)(((n) >> 24) & 0xFF));v.push_back((uint8_t)(((n) >> 16) & 0xFF));v.push_back((uint8_t)(((n) >> 8) & 0xFF));v.push_back((uint8_t)((n) & 0xFF));}
#define I32_TO_U8VECTOR(v, n) {v.push_back((uint8_t)(((n) >> 24) & 0xFF));v.push_back((uint8_t)(((n) >> 16) & 0xFF));v.push_back((uint8_t)(((n) >> 8) & 0xFF));v.push_back((uint8_t)((n) & 0xFF));}
#define I16_TO_U8VECTOR(v, n) {v.push_back((uint8_t)(((n) >> 8) & 0xFF));v.push_back((uint8_t)((n) & 0xFF));}
#define U8VECTOR_TO_I64(v, pos) (pos + 8 > v.size() ? 0 : (((uint64_t)v[pos]) << 56) | (((uint64_t)v[pos + 1]) << 48) | (((uint64_t)v[pos + 2]) << 40) | (((uint64_t)v[pos + 3]) << 32) | (((uint64_t)v[pos + 4]) << 24) | (((uint64_t)v[pos + 5]) << 16) | (((uint64_t)v[pos + 6]) << 8) | ((uint64_t)v[pos + 7]))
#define U8VECTOR_TO_I32(v, pos) (pos + 4 > v.size() ? 0 : (((uint32_t)v[pos]) << 24) | (((uint32_t)v[pos + 1]) << 16) | (((uint32_t)v[pos + 2]) << 8) | ((uint32_t)v[pos + 3]))
#define U8VECTOR_TO_I16(v, pos) (pos + 2 > v.size() ? 0 : (((uint16_t)v[pos]) << 8) | ((uint16_t)v[pos + 1]))
#define I64_TO_U8CARRAY(a, pos, n) {a[pos] = (uint8_t)(((n) >> 56) & 0xFF);a[pos + 1] = (uint8_t)(((n) >> 48) & 0xFF);a[pos + 2] = (uint8_t)(((n) >> 40) & 0xFF);a[pos + 3] = (uint8_t)(((n) >> 32) & 0xFF);a[pos + 4] = (uint8_t)(((n) >> 24) & 0xFF);a[pos + 5] = (uint8_t)(((n) >> 16) & 0xFF);a[pos + 6] = (uint8_t)(((n) >> 8) & 0xFF);a[pos + 7] = (uint8_t)((n) & 0xFF);}
#define I32_TO_U8CARRAY(a, pos, n) {a[pos] = (uint8_t)(((n) >> 24) & 0xFF);a[pos + 1] = (uint8_t)(((n) >> 16) & 0xFF);a[pos + 2] = (uint8_t)(((n) >> 8) & 0xFF);a[pos + 3] = (uint8_t)((n) & 0xFF);}
#define I16_TO_U8CARRAY(a, pos, n) {a[pos] = (uint8_t)(((n) >> 8) & 0xFF);a[pos + 1] = (uint8_t)((n) & 0xFF);}
#define U8CARRAY_TO_I32(a, size, pos) (pos + 4 > size ? 0 : (((uint32_t)a[pos]) << 24) | (((uint32_t)a[pos + 1]) << 16) | (((uint32_t)a[pos + 2]) << 8) | ((uint32_t)a[pos + 3]))
#define U8CARRAY_TO_I16(a, size, pos) (pos + 2 > size ? 0 : (((uint16_t)a[pos]) << 8) | ((uint16_t)a[pos + 1]))

class GD
{
public:
    static uint32_t clockFrequency;
    static Gpio ledGreen;
    static Gpio ledOrange;
    static Gpio rts;
    static Gpio cts;
    static Gpio chargePumpShdn;
    static Gpio unplugged;
    static Gpio vbusSensePlus;

    static bool loggedIn;
    static bool adminMode;
    /**
     * - On user stick: Key to encrypt the encryption key
     * - On server stick:  Key to encrypt the private certificate to decrypt encryption key
     */
    static std::array<uint8_t, 32> unlockKey;

    static bool encryptionKeySet;

    /**
     * Server stick only: The AES key to encrypt all stored data except the private certificate to decrypt this key.
     */
    static std::array<uint8_t, 32> encryptionKey;

    static uint32_t dhParamsGenerationTime;
    static mbedtls_dhm_context dhParams;
    static std::unique_ptr<Uart> uart;

    static void init();
    static void safeAppendZero(std::vector<uint8_t>& vector);
    static void safeShrinkToFit(std::vector<uint8_t>& vector);
private:
    GD() = default;
};

}

#endif
