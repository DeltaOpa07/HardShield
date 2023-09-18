#pragma once
#include <windows.h>
#include <tchar.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#include <cstdio>
#include <cstdlib>
#define DEBUG(fmt, ...) (_tprintf(TEXT(fmt), __VA_ARGS__))
#else 
#define DEBUG(...) (0)
#endif 

#define RSABITS (2048)

#define MAGICSIZE ((8) * sizeof(TCHAR))

#define HSENCTYPE (4)

#define HSAESKEYLEN (16)

// the encrypted mark
#define HSMAGIC TEXT("HardShld")
// used by HSCrypto, this buffersize is for input and output
#define HSIOBUFSIZE 0x100000
// suffix of encrypted files
#define HSUFFIX TEXT(".HARDSD")
// suffix of temp encrypted files
#define HSUFFIXTEMP TEXT(".HARDSDT")



#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif

// structure needs to use when use AES
#pragma pack(1)
typedef struct _AESOBJ
{
	PUCHAR pbIV;
	ULONG  cbIV;
	PUCHAR pbKeyObject;
	ULONG  cbKeyObject;
	BCRYPT_ALG_HANDLE hCryptProvider;
	BCRYPT_KEY_HANDLE hKeyHdl;
} AESOBJ, * PAESOBJ;
#pragma pack()

#pragma pack(1)
typedef struct _CRYPTO
{
	BCRYPT_ALG_HANDLE hProv;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pbInBuffer;
	PBYTE pbOutBuffer;
	AESOBJ stAesObj;
} CRYPTO, *PCRYPTO;
#pragma pack()


extern LPCTSTR pcszFileExts[];