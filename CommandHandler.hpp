/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_COMMANDHANDLER_H
#define MELLON_COMMANDHANDLER_H

#include "Mellon.hpp"

namespace Mellon
{

enum class Commands : uint8_t
{
    getFirmwareVersion =            0x01,
    getSerialNumber =               0x02,
    setName =                       0x03,
    getName =                       0x04,
    setTime =                       0x05,
    getTime =                       0x06,
    getBatteryLow =                 0x07,
    login =                         0x08,
    logout =                        0x09,
    reset =                         0x0A,
    getLastShutdown =               0x0B,
    isReady =                       0x0C,
    isLoggedIn =                    0x0D,
    getResetCause =                 0x0E,
    clearResetCause =               0x0F,

    writeAesUnlockEncryptionKey =   0x20,
    addUnlockPassphrase =           0x21,
    removeUnlockPassphrase =        0x22,

    writeServerAesEncryptionKey =   0x30,
    writeUnlockPublicKey =          0x31,
    getUnlockResponse =             0x32,

    writeDhParameters =             0x40,
    writeUnlockPrivateKey =         0x41,
    getUnlockParameters =           0x42,
    unlock =                        0x43,

    writeSshHostCaKeyPair =         0x50,
    eraseSshHostCaKeyPair =         0x51,
    writeX509CaKey =                0x52,
    eraseX509CaKey =                0x53,
    writeUserCaKeyPair =            0x54,
    eraseUserCaKeyPair =            0x55,

    getSshHostCaPublicKey =         0x56,
    getX509CaPublicKey =            0x57,
    getUserCaPublicKey =            0x58,

    signSshHostCert =               0x60,
    signX509Csr =                   0x61,
    signUserCert =                  0x62,

    writeAesKey =                   0x80,
    eraseAesKey =                   0x81,
    aesEncrypt =                    0x90,
    aesDecrypt =                    0xA0,

    generateRandomBytes =           0xC0,
    getRandomInfo =                 0xC1,

    output =                        0xE0
};

class CommandHandler
{
public:
    CommandHandler();
    ~CommandHandler();

    void handleCommand(Commands command, std::vector<uint8_t>& packet);
private:
    void getFirmwareVersion();
    void getSerialNumber();
    void setName(const std::string& name);
    void getName();
};

}

#endif
