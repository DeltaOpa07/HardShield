#pragma once
#include <windows.h>
#include <tchar.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define RSABITS (2048)

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif

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


extern LPCTSTR pcszFileExts[];