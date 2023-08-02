/* Copyright 2013-2019 Homegear GmbH */

#include "CommandHandler.hpp"
#include "Uart.hpp"
#include "Trng.hpp"
#include "Aes.hpp"
#include "Hibernation.hpp"
#include "Time.hpp"
#include "Sign.hpp"
#include "User.hpp"

namespace Mellon
{

CommandHandler::CommandHandler()
{
}

//{{{
void CommandHandler::getFirmwareVersion()
{
    uint16_t data = (MELLON_VERSION >> 8) | ((MELLON_VERSION & 0xFF) << 8);
    GD::uart->send((uint8_t*)&data, 2);
}

void CommandHandler::getSerialNumber()
{
    std::array<uint8_t, 16> serialNumber;
    I32_TO_U8CARRAY(serialNumber, 0, SYSCTL->UNIQUEID0);
    I32_TO_U8CARRAY(serialNumber, 4, SYSCTL->UNIQUEID1);
    I32_TO_U8CARRAY(serialNumber, 8, SYSCTL->UNIQUEID2);
    I32_TO_U8CARRAY(serialNumber, 12, SYSCTL->UNIQUEID3);
    GD::uart->send((uint8_t*)serialNumber.data(), serialNumber.size());
}

void CommandHandler::setName(const std::string& name)
{
    if(Flash::writeSlot(0, FLASH_NAME_ADDRESS, 1, FLASH_NAME_SIZE, (uint8_t*)name.data(), name.size())) GD::uart->sendStatus(UartStatus::ack);
    else GD::uart->sendStatus(UartStatus::unknownError);
}

void CommandHandler::getName()
{
    std::string name;

    uint32_t address = FLASH_NAME_ADDRESS;
    uint32_t metadata = U8CARRAY_TO_I32(((uint8_t*)address), 4, 0);
    uint8_t* data = nullptr;
    size_t dataSize = 0;
    if((metadata >> 24) == 1)
    {
        dataSize = metadata & 0xFFFF;
        if(dataSize > 0 && dataSize <= FLASH_NAME_SIZE - 4)
        {
            data = (uint8_t*)(address + 4);
            name = std::string((char*)data, dataSize);
        }
    }

    if(name.empty()) name = "<unset>";

    GD::uart->send((uint8_t*)name.data(), name.size());
}
//}}}

void CommandHandler::handleCommand(Commands command, std::vector<uint8_t>& packet)
{
    if(packet.size() < 4)
    {
        GD::uart->sendStatus(UartStatus::wrongPayloadSize);
        return; //4 is the size of the header, so smaller packets are not possible
    }

    if(command != Commands::setTime && command != Commands::getName && command != Commands::getSerialNumber && !Time::isValid())
    {
        GD::uart->sendStatus(UartStatus::invalidTime);
        return;
    }

    //{{{ General (0x00 - 0x1F)
    /*
     * Command 0x01 - Get firmware version
     */
    if(command == Commands::getFirmwareVersion)
    {
        getFirmwareVersion();
    }

    /*
     * Command 0x02 - Get serial number
     */
    else if(command == Commands::getSerialNumber)
    {
        getSerialNumber();
    }

    /*
     * Command 0x03 - Set name
     */
    else if(command == Commands::setName)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1) //Header + at least one name byte
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::string name((char*)packet.data() + 4, packet.size() - 4);
        setName(name);
    }

    /*
     * Command 0x04 - Get name
     */
    else if(command == Commands::getName)
    {
        getName();
    }

    /*
     * Command 0x05 - Set time
     */
    else if(command == Commands::setTime)
    {
        if(packet.size() != 4 + 4)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        int32_t time = (((int32_t)packet.at(4)) << 24) | (((int32_t)packet.at(5)) << 16) | (((int32_t)packet.at(6)) << 8) | packet.at(7);
        if(Time::set(time)) GD::uart->sendStatus(UartStatus::ack);
        else if(!GD::loggedIn && Time::get() > 1000000000ul) GD::uart->sendStatus(UartStatus::unauthorized);
        else GD::uart->sendStatus(UartStatus::tryAgainLater);
    }

    /*
     * Command 0x06 - Get time
     */
    else if(command == Commands::getTime)
    {
        uint32_t time = Time::get();
        std::array<uint8_t, 4> data{ (uint8_t)((time >> 24) & 0xFF), (uint8_t)((time >> 16) & 0xFF), (uint8_t)((time >> 8) & 0xFF), (uint8_t)(time & 0xFF) };
        GD::uart->send(data.data(), data.size());
    }

    /*
     * Command 0x07 - Get battery low
     */
    else if(command == Commands::getBatteryLow)
    {
        std::array<uint8_t, 1> data{ (uint8_t)Hibernation::getBatteryLow() };
        GD::uart->send(data.data(), data.size());
    }

    /*
     * Command 0x08 - Login
     */
    else if(command == Commands::login)
    {
        if(packet.size() < 4 + 10) //10 (minimum passphrase length) + header
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::string passphrase((char*)packet.data() + 4, packet.size() - 4);

        auto passphraseId = User::login(passphrase);
        if(passphraseId >= 0)
        {
            std::array<uint8_t, 1> data{ (uint8_t)passphraseId };
            if(GD::adminMode) data.at(0) |= 0x80;
            GD::uart->send(data.data(), data.size());
        }
        else if(!Trng::isReady()) GD::uart->sendStatus(UartStatus::tryAgainLater);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }

    /*
     * Command 0x09 - Logout
     */
    else if(command == Commands::logout)
    {
        if(User::logout()) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }

    /*
     * Command 0x0A - Reset
     */
    else if(command == Commands::reset)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        User::logout();
        if(Flash::eraseAll())
        {
            Time::reset();
            GD::uart->sendStatus(UartStatus::ack);
            SysCtlReset();
        }
        else GD::uart->sendStatus(UartStatus::unknownError);
    }

    /*
     * Command 0x0B - Get last shutdown
     */
    else if(command == Commands::getLastShutdown)
    {
        uint8_t state = false;
        uint32_t time = Hibernation::getLastHibernation(state);
        std::array<uint8_t, 5> data{ (uint8_t)((time >> 24) & 0xFF), (uint8_t)((time >> 16) & 0xFF), (uint8_t)((time >> 8) & 0xFF), (uint8_t)(time & 0xFF), state };
        GD::uart->send(data.data(), data.size());
    }
    //}}}

    /*
     * Command 0x0C - Is ready
     */
    else if(command == Commands::isReady)
    {
        std::array<uint8_t, 1> data{ (uint8_t)Trng::isReady() };
        GD::uart->send(data.data(), data.size());
    }
    //}}}

    /*
     * Command 0x0D - Is logged in
     */
    else if(command == Commands::isLoggedIn)
    {
        uint8_t statusByte = 0;
        statusByte = (uint8_t)GD::loggedIn;
        statusByte |= ((uint8_t)GD::adminMode) << 1;

        std::array<uint8_t, 1> data{ statusByte };
        GD::uart->send(data.data(), data.size());
    }

    /*
     * Command 0x0E - Get reset cause
     */
    else if(command == Commands::getResetCause)
    {
        uint32_t resetCause1 = SysCtlResetCauseGet();
        uint32_t resetCause2 = HibernateIntStatus(false); //Must also be evaluated as described in section 4.2.7
        std::array<uint8_t, 8> data{ (uint8_t)((resetCause1 >> 24) & 0xFF), (uint8_t)((resetCause1 >> 16) & 0xFF), (uint8_t)((resetCause1 >> 8) & 0xFF), (uint8_t)(resetCause1 & 0xFF), (uint8_t)((resetCause2 >> 24) & 0xFF), (uint8_t)((resetCause2 >> 16) & 0xFF), (uint8_t)((resetCause2 >> 8) & 0xFF), (uint8_t)(resetCause2 & 0xFF) };
        GD::uart->send(data.data(), data.size());
    }

    /*
     * Command 0x0F - Clear reset cause
     */
    else if(command == Commands::clearResetCause)
    {
        SysCtlResetCauseClear(SYSCTL_CAUSE_HSRVREQ | SYSCTL_CAUSE_HIB | SYSCTL_CAUSE_WDOG1 | SYSCTL_CAUSE_SW | SYSCTL_CAUSE_WDOG0 | SYSCTL_CAUSE_BOR | SYSCTL_CAUSE_POR | SYSCTL_CAUSE_EXT);
        HibernateIntClear(HIBERNATE_INT_PIN_WAKE | HIBERNATE_INT_LOW_BAT | HIBERNATE_INT_VDDFAIL | HIBERNATE_INT_RESET_WAKE | HIBERNATE_INT_GPIO_WAKE | HIBERNATE_INT_RTC_MATCH_0 | HIBERNATE_INT_WR_COMPLETE);
        GD::uart->sendStatus(UartStatus::ack);
    }
    //}}}

    //{{{ Data encryption key commands (0x20 - 0x2F)
    /*
     * Command 0x20 - Write AES unlock encryption key
     */
    else if(command == Commands::writeAesUnlockEncryptionKey)
    {
        if(packet.size() < 4 + 10 + 32) //Header + 10 (minimum passphrese length) + 32 (key length)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::string passphrase((char*)packet.data() + 4 + 32, packet.size() - 4 - 32);

        if(User::writeAesUnlockEncryptionKey(packet.data() + 4, 32, passphrase)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x21 - Add unlock passphrase
     */
    else if(command == Commands::addUnlockPassphrase)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1 + 10 + 1 + 10) //Header + passphrase size + 10 (minimum passphrase size) + passphrase size + 10 (minimum passphrase size)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        bool admin = (bool)packet.at(4);
        size_t firstPassphraseSize = packet.at(5);
        size_t secondPassphraseSize = packet.size() - 6 - firstPassphraseSize;
        std::string oldPassphrase((char*)packet.data() + 6, firstPassphraseSize);
        std::string newPassphrase((char*)packet.data() + 6 + firstPassphraseSize, secondPassphraseSize);

        auto passphraseId = User::addPassphrase(oldPassphrase, newPassphrase, admin);
        if(passphraseId >= 0)
        {
            std::array<uint8_t, 1> data{ (uint8_t)passphraseId };
            if(admin) data.at(0) |= 0x80;
            GD::uart->send(data.data(), data.size());
        }
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x22 - Remove unlock passphrase
     */
    else if(command == Commands::removeUnlockPassphrase)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 10) //Header + 10 (minimum passphrase size)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::string passphrase((char*)packet.data() + 4, packet.size() - 4);

        if(User::removePassphrase(passphrase)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    //}}}

    //{{{ User only Mellon commands (0x30 - 0x3F)
    /*
     * Command 0x30 - Write server AES encryption key
     */
    else if(command == Commands::writeServerAesEncryptionKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() != 4 + 32)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        if(User::writeServerAesEncryptionKey(packet.data() + 4, packet.size() - 4)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x31 - Write unlock public key
     */
    else if(command == Commands::writeUnlockPublicKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1) //At least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        if(packet.back() != 0) GD::safeAppendZero(packet);

        if(User::writeUnlockPublicKey(packet.data() + 4, packet.size() - 4)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x32 - Get unlock response
     */
    else if(command == Commands::getUnlockResponse)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1) //At least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        auto data = User::getUnlockResponse(packet.data() + 4, packet.size() - 4);
        if(!data.empty()) GD::uart->send(data.data(), data.size());
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    //}}}

    //{{{ Server only Mellon commands (0x40 - 0x4F)
    /*
     * Command 0x40 - Write Diffie-Hellman parameters
     */
    else if(command == Commands::writeDhParameters)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1) //At least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        if(packet.back() != 0) GD::safeAppendZero(packet);

        if(User::writeDhParameters(packet.data() + 4, packet.size() - 4)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x41 - Write unlock private key
     */
    else if(command == Commands::writeUnlockPrivateKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1) //At least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        if(packet.back() != 0) GD::safeAppendZero(packet);

        if(User::writeUnlockPrivateKey(packet.data() + 4, packet.size() - 4)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x42 - Get unlock parameters
     */
    else if(command == Commands::getUnlockParameters)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        auto result = User::getUnlockParameters();
        if(!result.empty()) GD::uart->send(result.data(), result.size());
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x43 - Unlock
     */
    else if(command == Commands::unlock)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(packet.size() < 4 + 1) //At least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        if(User::unlock(packet.data() + 4, packet.size() - 4)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    //}}}

    //{{{ CA (0x50 - 0x7F)
    //    - 0x50 - 0x5F General commands
    //    - 0x60 - 0x6F Sign commands

    /*
     * Command 0x50 - Write SSH host CA key pair
     */
    else if(command == Commands::writeSshHostCaKeyPair)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1 + 2 + 1 + 2 + 1 + 4) //Header + slot + private key size + at least 1 byte of private key + public key size + at least 1 byte of public key + 4 byte validity
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        //{{{ Read slot
            size_t pos = 4;
            if(pos + 1 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t slot = packet.at(pos);
            pos++;
        //}}}

        //{{{ Read private key
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t privateKeySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + privateKeySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::vector<uint8_t> privateKey;
            privateKey.reserve(packet.at(pos + privateKeySize - 1) == 0 ? privateKeySize : privateKeySize + 1);
            privateKey.insert(privateKey.end(), packet.begin() + pos, packet.begin() + pos + privateKeySize);
            if(privateKey.back() != 0)  GD::safeAppendZero(privateKey);
            pos += privateKeySize;
        //}}}

        //{{{ Read public key
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t publicKeySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + publicKeySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::vector<uint8_t> publicKey;
            publicKey.reserve(packet.at(pos + publicKeySize - 1) == 0 ? publicKeySize : publicKeySize + 1);
            publicKey.insert(publicKey.end(), packet.begin() + pos, packet.begin() + pos + publicKeySize);
            if(publicKey.back() != 0)  GD::safeAppendZero(publicKey);
            pos += publicKeySize;
        //}}}

        //{{{ Read validity
            if(pos + 4 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t validity = U8VECTOR_TO_I32(packet, pos);
        //}}}

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        if(sign->writeSshHostCaKeyPair(slot, privateKey, publicKey, validity)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x51 - Erase SSH host CA key pair
     */
    else if(command == Commands::eraseSshHostCaKeyPair)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        if(sign->eraseSshHostCaKeySlot(packet.at(4))) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x52 - Write X.509 CA key
     */
    else if(command == Commands::writeX509CaKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1 + 2 + 1 + 2 + 1 + 4) //Header + slot + private key size + at least 1 byte of private key + public key size + at least 1 byte of public key + 4 byte validity
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        //{{{ Read slot
            size_t pos = 4;
            if(pos + 1 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t slot = packet.at(pos);
            pos++;
        //}}}

        //{{{ Read private key
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t privateKeySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + privateKeySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::vector<uint8_t> privateKey;
            privateKey.reserve(packet.at(pos + privateKeySize - 1) == 0 ? privateKeySize : privateKeySize + 1);
            privateKey.insert(privateKey.end(), packet.begin() + pos, packet.begin() + pos + privateKeySize);
            if(privateKey.back() != 0) GD::safeAppendZero(privateKey);
            pos += privateKeySize;
        //}}}

        //{{{ Read public key
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t publicKeySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + publicKeySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::vector<uint8_t> publicKey;
            publicKey.reserve(packet.at(pos + publicKeySize - 1) == 0 ? publicKeySize : publicKeySize + 1);
            publicKey.insert(publicKey.end(), packet.begin() + pos, packet.begin() + pos + publicKeySize);
            if(publicKey.back() != 0) GD::safeAppendZero(publicKey);
            pos += publicKeySize;
        //}}}

        //{{{ Read validity
            if(pos + 4 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t validity = U8VECTOR_TO_I32(packet, pos);
        //}}}

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        if(sign->writeX509CaKey(slot, privateKey, publicKey, validity)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x53 - Erase X.509 CA key
     */
    else if(command == Commands::eraseX509CaKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        if(sign->eraseX509CaKeySlot(packet.at(4))) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x54 - Write user CA key pair
     */
    else if(command == Commands::writeUserCaKeyPair)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1 + 2 + 1 + 2 + 1 + 4) //Header + slot + private key size + at least 1 byte of private key + public key size + at least 1 byte of public key + 4 byte validity
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        //{{{ Read slot
            size_t pos = 4;
            if(pos + 1 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t slot = packet.at(pos);
            pos++;
        //}}}

        //{{{ Read private key
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t privateKeySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + privateKeySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::vector<uint8_t> privateKey;
            privateKey.reserve(packet.at(pos + privateKeySize - 1) == 0 ? privateKeySize : privateKeySize + 1);
            privateKey.insert(privateKey.end(), packet.begin() + pos, packet.begin() + pos + privateKeySize);
            if(privateKey.back() != 0) GD::safeAppendZero(privateKey);
            pos += privateKeySize;
        //}}}

        //{{{ Read public key
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t publicKeySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + publicKeySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::vector<uint8_t> publicKey;
            publicKey.reserve(packet.at(pos + publicKeySize - 1) == 0 ? publicKeySize : publicKeySize + 1);
            publicKey.insert(publicKey.end(), packet.begin() + pos, packet.begin() + pos + publicKeySize);
            if(publicKey.back() != 0) GD::safeAppendZero(publicKey);
            pos += publicKeySize;
        //}}}

        //{{{ Read validity
            if(pos + 4 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t validity = U8VECTOR_TO_I32(packet, pos);
        //}}}

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        if(sign->writeUserCaKeyPair(slot, privateKey, publicKey, validity)) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x55 - Erase user CA key pair
     */
    else if(command == Commands::eraseUserCaKeyPair)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        if(sign->eraseUserCaKeySlot(packet.at(4))) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x56 - Get SSH Host CA public key
     */
    else if(command == Commands::getSshHostCaPublicKey)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        auto publicKey = sign->getSshHostCaPublicKey(packet.at(4));
        if(publicKey.empty()) GD::uart->sendStatus(UartStatus::unknownError);
        else GD::uart->send(publicKey);
    }
    /*
     * Command 0x57 - Get X.509 Host CA public key
     */
    else if(command == Commands::getX509CaPublicKey)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        auto publicKey = sign->getX509CaPublicKey(packet.at(4));
        if(publicKey.empty()) GD::uart->sendStatus(UartStatus::unknownError);
        else GD::uart->send(publicKey);
    }
    /*
     * Command 0x58 - Get User CA public key
     */
    else if(command == Commands::getUserCaPublicKey)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        auto publicKey = sign->getUserCaPublicKey(packet.at(4));
        if(publicKey.empty()) GD::uart->sendStatus(UartStatus::unknownError);
        else GD::uart->send(publicKey);
    }
    /*
     * Command 0x60 - Sign SSH host certificate
     */
    else if(command == Commands::signSshHostCert)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        //Header + slot + key size + at least 1 byte of key + identity size + at least 1 byte of identity + principals size + at least 1 byte of principals
        if(packet.size() < 4 + 1 + 2 + 1 + 2 + 1 + 2 + 1)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        //{{{ Read slot
            size_t pos = 4;
            if(pos + 1 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t slot = packet.at(pos);
            pos++;
        //}}}

        //{{{ Read public certificate
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t dataSize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + dataSize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t* data = packet.data() + pos;
            pos += dataSize;
        //}}}

        //{{{ Read public identity
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t identitySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + identitySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::string identity((char*)packet.data() + pos, identitySize);
            pos += identitySize;
        //}}}

        //{{{ Read principals
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t principalsSize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + principalsSize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::string principals((char*)packet.data() + pos, principalsSize);
        //}}}

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        auto signedCertificate = sign->signSshHost(slot, data, dataSize, identity, principals);
        if(signedCertificate.empty())
        {
            int errorCode = sign->getErrorCode();
            if(errorCode == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED) GD::uart->sendStatus(UartStatus::tryAgainLater);
            else if(errorCode == MBEDTLS_ERR_MPI_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_ASN1_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_MD_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_PEM_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_PK_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_X509_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_ECP_ALLOC_FAILED) GD::uart->sendStatus(UartStatus::heapOverflow);
            else GD::uart->sendStatus(UartStatus::unknownError);
        }
        else GD::uart->send(signedCertificate);
    }
    /*
     * Command 0x61 - Sign X.509 CSR
     */
    else if(command == Commands::signX509Csr)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 1 + 2 + 1) //Header + slot + CSR size + at least 1 byte of CSR
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        uint8_t slot = packet.at(4);

        if(4 + 1 + 2 > packet.size())
        {
            GD::uart->sendStatus(UartStatus::unknownError);
            return;
        }
        size_t csrSize = U8VECTOR_TO_I16(packet, 4 + 1);
        if(4 + 1 + 2 + csrSize > packet.size())
        {
            GD::uart->sendStatus(UartStatus::unknownError);
            return;
        }
        if(packet.back() != 0)
        {
            GD::safeAppendZero(packet); //Make sure data ends with '\0'
            csrSize++;
        }
        uint8_t* csr = packet.data() + 4 + 1 + 2;

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        auto signedCertificate = sign->signX509Csr(slot, csr, csrSize);
        if(signedCertificate.empty())
        {
            int errorCode = sign->getErrorCode();
            if(errorCode == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED) GD::uart->sendStatus(UartStatus::tryAgainLater);
            else if(errorCode == MBEDTLS_ERR_MPI_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_ASN1_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_MD_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_PEM_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_PK_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_X509_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_ECP_ALLOC_FAILED) GD::uart->sendStatus(UartStatus::heapOverflow);
            else GD::uart->sendStatus(UartStatus::unknownError);
        }
        else GD::uart->send(signedCertificate);
    }
    /*
     * Command 0x62 - Sign user certificate
     */
    else if(command == Commands::signUserCert)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        //Header + slot + key size + at least 1 byte of key + identity size + at least 1 byte of identity + principals size + at least 1 byte of principals + 1 byte permissions + 2 bytes force command size + 2 bytes source address size
        if(packet.size() < 4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 1 + 2 + 2)
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        //{{{ Read slot
            size_t pos = 4;
            if(pos + 1 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t slot = packet.at(pos);
            pos++;
        //}}}

        //{{{ Read public certificate
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t dataSize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + dataSize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t* data = packet.data() + pos;
            pos += dataSize;
        //}}}

        //{{{ Read public identity
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t identitySize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + identitySize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::string identity((char*)packet.data() + pos, identitySize);
            pos += identitySize;
        //}}}

        //{{{ Read principals
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t principalsSize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + principalsSize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::string principals((char*)packet.data() + pos, principalsSize);
            pos += principalsSize;
        //}}}

        //{{{ Read permissions
            if(pos + 1 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            uint8_t permissions = packet.at(pos);
            pos++;
        //}}}

        //{{{ Read force command
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t forceCommandSize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + forceCommandSize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::string forceCommand((char*)packet.data() + pos, forceCommandSize);
            pos += forceCommandSize;
        //}}}

        //{{{ Read source address
            if(pos + 2 > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            size_t sourceAddressSize = U8VECTOR_TO_I16(packet, pos);
            pos += 2;

            if(pos + sourceAddressSize > packet.size())
            {
                GD::uart->sendStatus(UartStatus::wrongPayloadSize);
                return;
            }
            std::string sourceAddress((char*)packet.data() + pos, sourceAddressSize);
            pos += sourceAddressSize;
        //}}}

        std::unique_ptr<Sign> sign = std::make_unique<Sign>();
        auto signedCertificate = sign->signUser(slot, data, dataSize, identity, principals, permissions, forceCommand, sourceAddress);
        if(signedCertificate.empty())
        {
            int errorCode = sign->getErrorCode();
            if(errorCode == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED) GD::uart->sendStatus(UartStatus::tryAgainLater);
            else if(errorCode == MBEDTLS_ERR_MPI_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_ASN1_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_MD_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_PEM_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_PK_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_X509_ALLOC_FAILED ||
                    errorCode == MBEDTLS_ERR_ECP_ALLOC_FAILED) GD::uart->sendStatus(UartStatus::heapOverflow);
            else GD::uart->sendStatus(UartStatus::unknownError);
        }
        else GD::uart->send(signedCertificate);
    }

    //{{{ AES (0x80 - 0xAF)
    //    - 0x80 - 0x8F General commands
    //    - 0x90 - 0x9F Encryption commands
    //    - 0xA0 - 0xAF Decryption commands

    /*
     * Command 0x80 - Write AES key
     *
     * @param slot The 2 byte slot index
     * @param key The key to write to the slot
     */
    else if(command == Commands::writeAesKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() != 4 + 2 + 32) //Header + slot + key
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        std::unique_ptr<Aes> aes = std::make_unique<Aes>(U8VECTOR_TO_I16(packet, 4));
        auto result = aes->writeKey(packet.data() + 6, packet.size() - 6);
        if(result) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x81 - Erase AES key
     *
     * @param slot The 2 byte slot index to erase
     */
    else if(command == Commands::eraseAesKey)
    {
        if(!GD::loggedIn || !GD::adminMode)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() != 4 + 2) //Header + slot
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        std::unique_ptr<Aes> aes = std::make_unique<Aes>(U8VECTOR_TO_I16(packet, 4));
        if(aes->eraseKey()) GD::uart->sendStatus(UartStatus::ack);
        else GD::uart->sendStatus(UartStatus::unknownError);
    }
    /*
     * Command 0x90 - AES encrypt
     *
     * @param slot The 2 byte slot index
     * @param data The data to encrypt
     */
    else if(command == Commands::aesEncrypt)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 2 + 1) //Header + slot + at least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::unique_ptr<Aes> aes = std::make_unique<Aes>(U8VECTOR_TO_I16(packet, 4));
        auto encryptedData = aes->encrypt(packet.data() + 6, packet.size() - 6);
        if(encryptedData.empty())
        {
            int errorCode = aes->getErrorCode();
            if(errorCode == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED) GD::uart->sendStatus(UartStatus::tryAgainLater);
            else GD::uart->sendStatus(UartStatus::unknownError);
        }
        else GD::uart->send(encryptedData);
    }
    /*
     * Command 0xA0 - AES decrypt
     *
     * @param slot The 2 byte slot index
     * @param data The data to decrypt
     */
    else if(command == Commands::aesDecrypt)
    {
        if(!GD::loggedIn)
        {
            GD::uart->sendStatus(UartStatus::unauthorized);
            return;
        }

        if(!GD::encryptionKeySet)
        {
            GD::uart->sendStatus(UartStatus::locked);
            return;
        }

        if(packet.size() < 4 + 2 + 1) //Header + slot + at least 1 byte of payload
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }

        std::unique_ptr<Aes> aes = std::make_unique<Aes>(U8VECTOR_TO_I16(packet, 4));
        auto decryptedData = aes->decrypt(packet.data() + 6, packet.size() - 6);
        if(decryptedData.empty())
        {
            int errorCode = aes->getErrorCode();
            if(errorCode == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED) GD::uart->sendStatus(UartStatus::tryAgainLater);
            else GD::uart->sendStatus(UartStatus::unknownError);
        }
        else GD::uart->send(decryptedData);
    }
    //}}}

    //{{{ TRNG (0xC0 - 0xCF)
    /*
     * Command 0xC0 - Generate random numbers.
     *
     * @param count uint8_t Number of random bytes to generate.
     */
    else if(command == Commands::generateRandomBytes)
    {
        if(packet.size() != 4 + 1) //Header + count
        {
            GD::uart->sendStatus(UartStatus::wrongPayloadSize);
            return;
        }
        const uint8_t count = packet.at(4);
        bool valid = false;
        auto& randomBytes = Trng::generateRandomBytes(count, valid);
        if(valid) GD::uart->send(randomBytes.data(), count);
        else GD::uart->sendStatus(UartStatus::tryAgainLater);
    }

    /*
     * Command 0xC1 - Get information about the TRNG.
     */
    else if(command == Commands::getRandomInfo)
    {
        uint32_t cycleCounter = Trng::getCycleCounter();
        uint32_t mean = Trng::getMean();
        int16_t medianOffset = Trng::getMedianOffset();
        uint32_t median = Trng::getMedian();
        auto& probabilities = Trng::getProbabilities();
        uint8_t data[34] = {
            (uint8_t)((cycleCounter >> 24) & 0xFF),
            (uint8_t)((cycleCounter >> 16) & 0xFF),
            (uint8_t)((cycleCounter >> 8) & 0xFF),
            (uint8_t)(cycleCounter & 0xFF),
            (uint8_t)((mean >> 24) & 0xFF),
            (uint8_t)((mean >> 16) & 0xFF),
            (uint8_t)((mean >> 8) & 0xFF),
            (uint8_t)(mean & 0xFF),
            (uint8_t)((median >> 24) & 0xFF),
            (uint8_t)((median >> 16) & 0xFF),
            (uint8_t)((median >> 8) & 0xFF),
            (uint8_t)(median & 0xFF),
            (uint8_t)((medianOffset >> 8) & 0xFF),
            (uint8_t)(medianOffset & 0xFF),
            (uint8_t)((probabilities.probability1 >> 24) & 0xFF),
            (uint8_t)((probabilities.probability1 >> 16) & 0xFF),
            (uint8_t)((probabilities.probability1 >> 8) & 0xFF),
            (uint8_t)(probabilities.probability1 & 0xFF),
            (uint8_t)((probabilities.probability0To0 >> 24) & 0xFF),
            (uint8_t)((probabilities.probability0To0 >> 16) & 0xFF),
            (uint8_t)((probabilities.probability0To0 >> 8) & 0xFF),
            (uint8_t)(probabilities.probability0To0 & 0xFF),
            (uint8_t)((probabilities.probability0To1 >> 24) & 0xFF),
            (uint8_t)((probabilities.probability0To1 >> 16) & 0xFF),
            (uint8_t)((probabilities.probability0To1 >> 8) & 0xFF),
            (uint8_t)(probabilities.probability0To1 & 0xFF),
            (uint8_t)((probabilities.probability1To0 >> 24) & 0xFF),
            (uint8_t)((probabilities.probability1To0 >> 16) & 0xFF),
            (uint8_t)((probabilities.probability1To0 >> 8) & 0xFF),
            (uint8_t)(probabilities.probability1To0 & 0xFF),
            (uint8_t)((probabilities.probability1To1 >> 24) & 0xFF),
            (uint8_t)((probabilities.probability1To1 >> 16) & 0xFF),
            (uint8_t)((probabilities.probability1To1 >> 8) & 0xFF),
            (uint8_t)(probabilities.probability1To1 & 0xFF)
        };

        GD::uart->send(data, 34);
    }
    //}}}

    else
    {
        GD::uart->sendStatus(UartStatus::unknownCommand);
    }
}

}
