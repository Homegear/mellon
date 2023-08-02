/* Copyright 2013-2019 Homegear GmbH */

#ifndef FLASH_HPP_
#define FLASH_HPP_

#include "Mellon.hpp"
#include "FlashAddressMapping.hpp"

#include "driverlib/inc/hw_flash.h"

namespace Mellon
{

class Flash
{
public:
    ~Flash() = default;

    static bool init();
    static bool eraseAll();
    static void massErase();
    static bool eraseSector(uint32_t address);
    static bool eraseSlot(size_t slot, uint32_t areaAddress, uint32_t slotCount, uint32_t slotSize);
    static bool writeSlot(size_t slot, uint32_t areaAddress, uint32_t slotCount, uint32_t slotSize, uint8_t* data, size_t dataSize);
private:
    Flash() = delete;
};

} /* namespace Mellon */

#endif /* FLASH_HPP_ */
