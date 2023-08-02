/* Copyright 2013-2019 Homegear GmbH */

#include <Flash.hpp>

namespace Mellon
{

bool Flash::init()
{
    if(FLASH_SECTOR_SIZE != SysCtlFlashSectorSizeGet()) return false;
    return true;
}

bool Flash::eraseAll()
{
    bool success = true;
    for(int32_t address = FLASH_DATA_START_ADDRESS; address < 0x100000; address += FLASH_SECTOR_SIZE)
    {
        Mellon::GD::ledGreen.toggleState();
        if(!eraseSector(address)) success = false;
    }
    Mellon::GD::ledGreen.setLow();
    return success;
}

void Flash::massErase()
{
    FLASH_CTRL->FMC = FLASH_FMC_WRKEY | FLASH_FMC_MERASE;
    while(FLASH_CTRL->FMC & FLASH_FMC_MERASE);
}

bool Flash::eraseSector(uint32_t address)
{
    if(address % FLASH_SECTOR_SIZE != 0) return false;
    return FlashErase(address) == 0;
}

bool Flash::eraseSlot(size_t slot, uint32_t areaAddress, uint32_t slotCount, uint32_t slotSize)
{
    if(slot >= slotCount) return false;

    uint32_t slotAddress = areaAddress + (slot * slotSize);

    //{{{ Load sector into memory
    uint32_t sectorAddress = slotAddress - (slotAddress % FLASH_SECTOR_SIZE);
    auto sectorData = std::make_unique<std::array<uint8_t, FLASH_SECTOR_SIZE>>();
    std::copy((uint8_t*)sectorAddress, (uint8_t*)sectorAddress + FLASH_SECTOR_SIZE, sectorData->begin());
    //}}}

    if(!eraseSector(sectorAddress)) return false;

    uint32_t slotOffset = slotAddress - sectorAddress;
    std::fill(sectorData->begin() + slotOffset, sectorData->begin() + slotOffset + slotSize, 0);

    return FlashProgram((uint32_t*)sectorData->data(), sectorAddress, sectorData->size()) == 0;
}

bool Flash::writeSlot(size_t slot, uint32_t areaAddress, uint32_t slotCount, uint32_t slotSize, uint8_t* data, size_t dataSize)
{
    if(dataSize == 0 || data == nullptr || dataSize > slotSize - 4 || slot >= slotCount) return false;

    uint32_t slotAddress = areaAddress + (slot * slotSize);

    //{{{ Load sector into memory
    uint32_t sectorAddress = slotAddress - (slotAddress % FLASH_SECTOR_SIZE);
    auto sectorData = std::make_unique<std::array<uint8_t, FLASH_SECTOR_SIZE>>();
    std::copy((uint8_t*)sectorAddress, (uint8_t*)sectorAddress + FLASH_SECTOR_SIZE, sectorData->begin());
    //}}}

    if(!eraseSector(sectorAddress)) return false;

    //{{{ Overwrite old slot data
    uint32_t slotOffset = slotAddress - sectorAddress;
    std::fill(sectorData->begin() + slotOffset, sectorData->begin() + slotOffset + slotSize, 0);
    //}}}

    uint32_t metadata = (((uint32_t)1) << 24) | (dataSize & 0xFFFF);
    I32_TO_U8CARRAY((*sectorData), slotOffset, metadata);
    std::copy(data, data + dataSize, sectorData->begin() + slotOffset + 4);

    return FlashProgram((uint32_t*)sectorData->data(), sectorAddress, sectorData->size()) == 0;
}

} /* namespace Mellon */
