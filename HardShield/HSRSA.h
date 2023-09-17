#pragma once
#include "HSCommon.h"

// RSA2048
BCRYPT_ALG_HANDLE InitRSA();

BOOLEAN 
ExportToFile(BCRYPT_KEY_HANDLE hKeyHdl, 
	LPCWSTR pKeyType, 
	LPCTSTR pFileName,
	BOOLEAN fCryptKey = FALSE); // If it needs the encryption keys


BOOLEAN 
Encrypt(BCRYPT_KEY_HANDLE hKeyHdl, 
	PUCHAR pbPlain, 
	ULONG cbPlain, 
	PUCHAR pbCipher, 
	ULONG cbCipher, 
	PULONG pcbResult);

BOOLEAN
Decrypt(BCRYPT_KEY_HANDLE hKeyHdl, PUCHAR pbCipher, ULONG cbCipher, PUCHAR pbPlain, ULONG cbPlain, PULONG pcbResult);

BOOLEAN 
ExportToMem(BCRYPT_KEY_HANDLE hKeyHdl, 
	LPCWSTR pKeyType, 
	PBYTE pbBlob, 
	ULONG cbBlob, 
	PULONG pKeyLen);

BOOLEAN 
ExportToFile(BCRYPT_KEY_HANDLE hKeyHdl, 
	LPCWSTR pKeyType, 
	LPCTSTR pFileName, 
	BOOLEAN fCryptKey);

BCRYPT_KEY_HANDLE 
ImportKeyFromFile(BCRYPT_ALG_HANDLE hCryptProvider,
	LPCWSTR pKeyType, 
	LPCTSTR pFileName);

BCRYPT_KEY_HANDLE 
ImportKeyFromMem(BCRYPT_ALG_HANDLE hCryptProvider, 
	LPCTSTR pKeyType, 
	PUCHAR pbBlob, 
	ULONG cbBlob);

BCRYPT_KEY_HANDLE GenKey(BCRYPT_ALG_HANDLE hCryptProvider);
