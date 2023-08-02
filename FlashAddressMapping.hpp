/* Copyright 2013-2019 Homegear GmbH */

#ifndef MELLON_FLASH_ADDRESS_MAPPING_H
#define MELLON_FLASH_ADDRESS_MAPPING_H

//Note:
//If only one or both of the first two words of the last line of a sector in a bank are programmed, an Erase of entire Sector, Mass Erase of device, or toggle mass erase does not erase the flash back to all 1's.
//=> As all our data is AES-encrypted, we only need to make sure, that our data is 16-byte-aligned.

#define FLASH_SECTOR_SIZE                               0x4000
#define FLASH_DATA_START_ADDRESS                        0x60000

//{{{ Sign.cpp
#define MAX_PEM_KEY_SIZE                                0x2000

#define FLASH_USER_CA_ADDRESS                           FLASH_DATA_START_ADDRESS
#define FLASH_USER_CA_SLOT_SIZE                         0x1000
#define FLASH_USER_CA_SLOT_COUNT                        0x20

#define FLASH_X509_HOST_CA_ADDRESS                      FLASH_USER_CA_ADDRESS + (FLASH_USER_CA_SLOT_SIZE * FLASH_USER_CA_SLOT_COUNT)
#define FLASH_X509_HOST_CA_SLOT_SIZE                    0x2000
#define FLASH_X509_HOST_CA_SLOT_COUNT                   0x20

#define FLASH_SSH_HOST_CA_ADDRESS                       FLASH_X509_HOST_CA_ADDRESS + (FLASH_X509_HOST_CA_SLOT_SIZE * FLASH_X509_HOST_CA_SLOT_COUNT)
#define FLASH_SSH_HOST_CA_SLOT_SIZE                     0x1000
#define FLASH_SSH_HOST_CA_SLOT_COUNT                    0x20
//}}}

//{{{ AES.cpp
#define AES_KEY_SLOT_SIZE                               0x50

#define FLASH_AES_KEY_ADDRESS                           FLASH_SSH_HOST_CA_ADDRESS + (FLASH_SSH_HOST_CA_SLOT_SIZE * FLASH_SSH_HOST_CA_SLOT_COUNT)
#define FLASH_AES_KEY_SLOT_COUNT                        0x400
//}}}

//{{{ User.cpp
//{ User Mellon
#define FLASH_SERVER_ENCRYPTION_KEY_ADDRESS             FLASH_AES_KEY_ADDRESS + (AES_KEY_SLOT_SIZE * FLASH_AES_KEY_SLOT_COUNT)
#define FLASH_SERVER_ENCRYPTION_KEY_SLOT_SIZE           0x80
#define FLASH_SERVER_ENCRYPTION_KEY_SLOT_COUNT          0x01
//}

//{ Server Mellon
#define FLASH_DH_PARAMS_ADDRESS                         FLASH_SERVER_ENCRYPTION_KEY_ADDRESS + (FLASH_SERVER_ENCRYPTION_KEY_SLOT_SIZE * FLASH_SERVER_ENCRYPTION_KEY_SLOT_COUNT)
#define FLASH_DH_PARAMS_SLOT_SIZE                       0x800
#define FLASH_DH_PARAMS_SLOT_COUNT                      0x01

#define FLASH_UNLOCK_PRIVATE_KEY_ADDRESS                FLASH_DH_PARAMS_ADDRESS + (FLASH_DH_PARAMS_SLOT_SIZE * FLASH_DH_PARAMS_SLOT_COUNT)
#define FLASH_UNLOCK_PRIVATE_KEY_SLOT_SIZE              0x1000
#define FLASH_UNLOCK_PRIVATE_KEY_SLOT_COUNT             0x01
//}

//{ User Mellon
#define FLASH_UNLOCK_PUBLIC_KEY_ADDRESS                 FLASH_UNLOCK_PRIVATE_KEY_ADDRESS + (FLASH_UNLOCK_PRIVATE_KEY_SLOT_SIZE * FLASH_UNLOCK_PRIVATE_KEY_SLOT_COUNT)
#define FLASH_UNLOCK_PUBLIC_KEY_SLOT_SIZE               0x800
#define FLASH_UNLOCK_PUBLIC_KEY_SLOT_COUNT              0x01

//{ User and server Mellon
#define FLASH_UNLOCK_USER_PASSPHRASES_ADDRESS           FLASH_UNLOCK_PUBLIC_KEY_ADDRESS + (FLASH_UNLOCK_PUBLIC_KEY_SLOT_SIZE * FLASH_UNLOCK_PUBLIC_KEY_SLOT_COUNT)
#define FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE         0x80
#define FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT        0x0A
//}
//}}}

#define FLASH_NAME_ADDRESS                              FLASH_UNLOCK_USER_PASSPHRASES_ADDRESS + (FLASH_UNLOCK_USER_PASSPHRASES_SLOT_SIZE * FLASH_UNLOCK_USER_PASSPHRASES_SLOT_COUNT)
#define FLASH_NAME_SIZE                                 0x100

#define USED_FLASH_SIZE                                 FLASH_NAME_ADDRESS + FLASH_NAME_SIZE

#if USED_FLASH_SIZE >= 0x100000
#error Out of flash memory
#endif

#endif
