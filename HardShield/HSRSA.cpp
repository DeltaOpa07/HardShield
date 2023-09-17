#include "HSRSA.h"


BCRYPT_ALG_HANDLE InitRSA()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BOOLEAN fOk = FALSE;
	BCRYPT_ALG_HANDLE hCryptProvider = INVALID_HANDLE_VALUE;

	do
	{
		status = BCryptOpenAlgorithmProvider(&hCryptProvider,
			BCRYPT_RSA_ALGORITHM,
			NULL,
			0);
		if (STATUS_SUCCESS != status)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);
	
	if (!fOk)
	{
		hCryptProvider = INVALID_HANDLE_VALUE;
	}

	return(hCryptProvider);
}


BCRYPT_KEY_HANDLE GenKey(BCRYPT_ALG_HANDLE hCryptProvider)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_KEY_HANDLE hCryptKey = INVALID_HANDLE_VALUE;
	BOOLEAN fOk = FALSE;

	if (INVALID_HANDLE_VALUE == hCryptProvider)
	{
		return(FALSE);
	}
	do
	{
		status = BCryptGenerateKeyPair(hCryptProvider, &hCryptKey, RSABITS, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		status = BCryptFinalizeKeyPair(hCryptKey, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);

	if (!fOk)
	{
		hCryptKey = INVALID_HANDLE_VALUE;
	}

	return(hCryptKey);
}

BCRYPT_KEY_HANDLE ImportKeyFromMem(BCRYPT_ALG_HANDLE hCryptProvider, LPCTSTR pKeyType, PUCHAR pbBlob, ULONG cbBlob)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_KEY_HANDLE hCryptKey = INVALID_HANDLE_VALUE;
	BOOLEAN fOk = FALSE;

	do
	{
		status = BCryptImportKeyPair(hCryptProvider, NULL, pKeyType, &hCryptKey, pbBlob, cbBlob, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		hCryptKey = INVALID_HANDLE_VALUE;
	} while (FALSE);

	return(hCryptKey);
}

BCRYPT_KEY_HANDLE ImportKeyFromFile(BCRYPT_ALG_HANDLE hCryptProvider, LPCWSTR pKeyType, LPCTSTR pFileName)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BYTE bBlob[4096] = { 0 };
	ULONG cbBlob = 0;
	ULONG cbFile = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_KEY_HANDLE hKeyHdl = INVALID_HANDLE_VALUE;
	BOOLEAN fOk = FALSE;

	do
	{
		hFile = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			break;
		}
		cbFile = GetFileSize(hFile, NULL);
		if (sizeof(bBlob) < cbFile)
		{
			break;
		}
		fOk = ReadFile(hFile, bBlob, sizeof(bBlob), &cbBlob, NULL);
		if (!fOk)
		{
			break;
		}
		status = BCryptImportKeyPair(hCryptProvider, NULL, pKeyType, &hKeyHdl, bBlob, cbBlob, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
	} while (FALSE);

	if (INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return(hKeyHdl);
}

BOOLEAN ExportToMem(BCRYPT_KEY_HANDLE hKeyHdl, LPCWSTR pKeyType, PBYTE pbBlob, ULONG cbBlob, PULONG pKeyLen)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData = 0;
	BOOLEAN fOk = FALSE;

	do
	{
		// Get the length that key needs
		status = BCryptExportKey(hKeyHdl, NULL, pKeyType, NULL, 0, &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		if (pKeyLen)
		{
			*pKeyLen = cbData;
		}
		if (cbBlob < cbData)
		{
			break;
		}
		status = BCryptExportKey(hKeyHdl, NULL, pKeyType, pbBlob, cbBlob, &cbBlob, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);

	return(fOk);
}

BOOLEAN 
Encrypt(BCRYPT_KEY_HANDLE hKeyHdl, 
	PUCHAR pbPlain, 
	ULONG cbPlain, 
	PUCHAR pbCipher, 
	ULONG cbCipher, 
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbBlock = RSABITS / 8;			// 256
	ULONG cbMaxEncBlk = cbBlock - 11;
	ULONG cbMaxDecBlk = cbBlock;
	// the max size after encryption
	ULONG cbMaxCipher = (INT)(((cbPlain + cbMaxEncBlk - 1) / cbMaxEncBlk) * cbBlock);
	ULONG cbData = 0;
	ULONG cbResult = 0;

	if (INVALID_HANDLE_VALUE == hKeyHdl)
	{
		return(FALSE);
	}
	if (!pbCipher && !cbCipher)
	{
		if (pcbResult)
		{
			*pcbResult = cbMaxCipher;
		}
		return(FALSE);
	}
	cbResult = 0;

	for (ULONG i = 0, s = 0; i < cbPlain; i += s)
	{
		s = cbPlain - i;
		if (s > cbMaxEncBlk)
		{
			s = cbMaxEncBlk;
		}
		status = BCryptEncrypt(hKeyHdl, pbPlain + i, s, NULL, NULL, 0, pbCipher + cbResult, cbBlock, &cbData, BCRYPT_PAD_PKCS1);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		cbResult += cbData;
	}

	if (pcbResult)
	{
		*pcbResult = cbResult;
	}

	return(FALSE);
}

BOOLEAN
Decrypt(BCRYPT_KEY_HANDLE hKeyHdl, 
	PUCHAR pbCipher, 
	ULONG cbCipher, 
	PUCHAR pbPlain, 
	ULONG cbPlain, 
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbBlock = RSABITS / 8;
	ULONG cbMaxEncBlk = cbBlock - 11;
	ULONG cbMaxDecBlk = cbBlock;
	ULONG cbMaxPlain = cbCipher / cbBlock * cbMaxEncBlk;
	ULONG cbData = 0;
	ULONG cbResult = 0;
	BOOLEAN fOk = FALSE;

	if (INVALID_HANDLE_VALUE == hKeyHdl)
	{
		return(FALSE);
	}
	for (ULONG i = 0; i < cbCipher; i += cbBlock)
	{
		status = BCryptDecrypt(hKeyHdl, pbCipher + i, cbBlock, NULL, NULL, 0, pbPlain + cbResult, cbBlock, &cbData, BCRYPT_PAD_PKCS1);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		cbResult += cbData;
	}
	if (pcbResult)
	{
		*pcbResult = cbResult;
	}

	return(TRUE);
}

BOOLEAN ExportToFile(BCRYPT_KEY_HANDLE hKeyHdl, LPCWSTR pKeyType, LPCTSTR pFileName, BOOLEAN fCryptKey)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UCHAR bBlob[4096] = { 0 };
	ULONG cbBlob = 0;
	UCHAR bBlock[256] = { 0 };
	ULONG cbData = 0;
	BOOLEAN bResult = FALSE;

	do
	{
		bResult = ExportToMem(hKeyHdl, pKeyType, bBlob, sizeof(bBlob), &cbBlob);
		if (!bResult)
		{
			break;
		}
		hFile = CreateFile(pFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			bResult = FALSE;
			break;
		}
		if (fCryptKey)
		{
			for (ULONG i = 0, cbSize = 0, cbBlock = 0; i < cbBlob; i += cbSize)
			{
				cbSize = cbBlob - i;
				if (cbSize > 256 - 11)
				{
					cbSize = 256 - 11;
				}
				bResult = Encrypt(hKeyHdl, bBlob + i, cbSize, bBlock, sizeof(bBlock), &cbBlock);
				if (!bResult)
				{
					break;
				}
				bResult = WriteFile(hFile, bBlock, cbBlock, &cbData, NULL);
				if (!bResult || cbData != cbBlock)
				{
					break;
				}
			}
		}
		else
		{
			bResult = WriteFile(hFile, bBlob, sizeof(bBlob), &cbData, NULL);
			if (!bResult)
			{
				bResult = FALSE;
			}
		}
	} while (FALSE);

	if (INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return(bResult);
}