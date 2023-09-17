#include <windows.h>
#include <tchar.h>
#include <cstdio>
#include <cstdlib>
#include "HSRSA.h"

VOID PrintHex(PBYTE pHexBuf, DWORD dwSizeBuf)
{
	for (int i = 0; i < dwSizeBuf; ++i)
	{
		printf("%02X", pHexBuf[i]);
		if (!((i + 1) % 32))
		{
			putchar('\n');
		}
	}
}

BOOLEAN GenPairKeysToFile(BCRYPT_ALG_HANDLE hCryptProvider)
{
	BCRYPT_KEY_HANDLE hKeyHdl = INVALID_HANDLE_VALUE;
	BOOLEAN fOk = FALSE;

	if (INVALID_HANDLE_VALUE == hCryptProvider)
	{
		return(FALSE);
	}
	do
	{
		// Gen pub-pri keys
		hKeyHdl = GenKey(hCryptProvider);
		if (INVALID_HANDLE_VALUE == hKeyHdl)
		{
			break;
		}

		// export pub key to local file 
		fOk = ExportToFile(hKeyHdl, BCRYPT_RSAPUBLIC_BLOB, TEXT("HardShield.public"));
		if (!fOk)
		{
			break;
		}
		// export pri key to local file
		fOk = ExportToFile(hKeyHdl, BCRYPT_RSAPRIVATE_BLOB, TEXT("HardShield.private"));
		if (!fOk)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);
	
	return(fOk);
}

int main()
{
	UCHAR ucTestAry[] = "Hello world";
	UCHAR ucCipher[4096] = { 0 };
	UCHAR ucPlain[4096] = { 0 };
	ULONG cbCipher = 0;
	ULONG cbPlain = 0;

	BCRYPT_ALG_HANDLE g_hCryptProvider = INVALID_HANDLE_VALUE;
	BCRYPT_KEY_HANDLE g_hKeyHdl = INVALID_HANDLE_VALUE;
	
	g_hCryptProvider = InitRSA();

	//g_hKeyHdl = ImportKeyFromFile(g_hCryptProvider, BCRYPT_RSAPRIVATE_BLOB, TEXT("HardShield.private"));
	//printf("Origin: \r\n%s\r\n\r\n", ucTestAry);
	//Encrypt(g_hKeyHdl, ucTestAry, 11, ucCipher, sizeof(ucCipher), &cbCipher);
	//printf("key: \r\n");
	//PrintHex(ucCipher, cbCipher);
	//printf("\r\ndec: \r\n");
	//
	//Decrypt(g_hKeyHdl, ucCipher, sizeof(ucCipher), ucPlain, sizeof(ucPlain), &cbPlain);
	//printf("%s\r\n", ucPlain);
	

	system("pause");

	return(0);
}