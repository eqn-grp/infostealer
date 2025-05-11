#pragma once
#include "main.h"

HMODULE mozglue_addr, nss3_addr;

typedef enum {
    siBuffer = 0,
    siClearDataBuffer,
    siCipherDataBuffer,
    siDERCertBuffer,
    siEncodedCertBuffer,
    siDERNameBuffer,
    siEncodedNameBuffer,
    siAsciiNameString,
    siAsciiString,
    siDEROID
} SECItemType;
 
struct SECItemStr {
    SECItemType type;
    unsigned char *data;
    unsigned int len;
};

typedef enum {
	SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
} SECStatus;

typedef struct SECItemStr SECItem;

typedef SECStatus (*NSSInit)(char *);
typedef SECStatus (*SECItem_FreeItem)(SECItem* item, BOOL freeItem);
typedef void *(*PK11GetInternalKeySlot)();
typedef SECStatus (*PK11SDRDecrypt)(SECItem *, SECItem *, void *);
typedef SECItem* (*NSSBase64DecodeBuffer)(void *ptr, SECItem *, char *, unsigned int);
typedef SECStatus (*PK11Authenticate)(void *, int, void *);
typedef SECStatus (*PK11CheckUserPassword)(void *, char *);
typedef SECStatus (*NSSShutdown)();
typedef void (*PK11FreeSlot)(void *);

NSSInit NSS_Init;
PK11GetInternalKeySlot PK11_GetInternalKeySlot;
PK11SDRDecrypt PK11SDR_Decrypt;
NSSBase64DecodeBuffer NSSBase64_DecodeBuffer;
PK11Authenticate PK11_Authenticate;
PK11CheckUserPassword PK11_CheckUserPassword;
NSSShutdown NSS_Shutdown;
PK11FreeSlot PK11_FreeSlot;
SECItem_FreeItem mySECItem_FreeItem;