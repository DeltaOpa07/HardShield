#include "HSAES.h"

VOID AES::InitAESObj(PAESOBJ pAesObj)
{
	if (!pAesObj)
	{
		return;
	}
	pAesObj->cbIV = pAesObj->cbKeyObject = 0;
	pAesObj->pbIV = pAesObj->pbKeyObject = NULL;
	pAesObj->hCryptProvider = pAesObj->hKeyHdl = INVALID_HANDLE_VALUE;

	return;
}

VOID AES::DestroyAESObj(PAESOBJ pAesObj)
{
	if (!pAesObj)
	{
		return;
	}
	pAesObj->cbIV = pAesObj->cbKeyObject = 0;

	if (pAesObj->pbKeyObject)
	{
		HeapFree(GetProcessHeap(), 0, pAesObj->pbKeyObject);
		pAesObj->pbKeyObject = NULL;
	}
	if (pAesObj->pbIV)
	{
		HeapFree(GetProcessHeap(), 0, pAesObj->pbIV);
		pAesObj->pbIV = NULL;
	}
	if (pAesObj->hCryptProvider)
	{
		BCryptCloseAlgorithmProvider(pAesObj->hCryptProvider, 0);
		pAesObj->hCryptProvider = INVALID_HANDLE_VALUE;
	}
	if (INVALID_HANDLE_VALUE != pAesObj->hKeyHdl)
	{
		BCryptDestroyKey(pAesObj->hKeyHdl);
		pAesObj->hKeyHdl = INVALID_HANDLE_VALUE;
	}
}

BOOLEAN AES::HSInitAES(PAESOBJ pAesObj)
{
	NTSTATUS status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE hCryptProvider = INVALID_HANDLE_VALUE;

	PUCHAR pbIV = NULL;
	ULONG cbIV = 0;
	PUCHAR pbKeyObject = NULL;
	ULONG cbKeyObject = 0;

	ULONG cbBlock = 0;
	ULONG cbData = 0;

	BOOLEAN fOk = FALSE;

	do
	{
		if (!pAesObj)
		{
			break;
		}
		AES::InitAESObj(pAesObj);

		status = BCryptOpenAlgorithmProvider(&hCryptProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		status = BCryptGetProperty(hCryptProvider, BCRYPT_BLOCK_LENGTH, (PUCHAR)&cbBlock, sizeof(cbBlock), &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		cbIV = cbBlock;
		pbIV = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIV);
		status = BCryptGetProperty(hCryptProvider, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(cbKeyObject), &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		pbKeyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbKeyObject);
		if (!pbKeyObject)
		{
			break;
		}
		pAesObj->cbIV = cbIV;
		pAesObj->pbIV = pbIV;
		pAesObj->cbKeyObject = cbKeyObject;
		pAesObj->pbKeyObject = pbKeyObject;
		pAesObj->hCryptProvider = hCryptProvider;
		
		fOk = TRUE;
	} while (FALSE);

	if (!fOk)
	{
		if (pbKeyObject)
		{
			HeapFree(GetProcessHeap(), 0, pbKeyObject);
			pbKeyObject = NULL;
		}
		if (pbIV)
		{
			HeapFree(GetProcessHeap(), 0, pbIV);
			pbIV = NULL;
		}
		if (hCryptProvider)
		{
			BCryptCloseAlgorithmProvider(hCryptProvider, 0);
			hCryptProvider = INVALID_HANDLE_VALUE;
		}
	}

	return(fOk);
}

BOOLEAN AES::GenKey(PAESOBJ pAesObj, PUCHAR pbKey, ULONG cbKey)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_KEY_HANDLE hKeyHdl = INVALID_HANDLE_VALUE;
	ULONG cbKeyObject = 0;

	status = BCryptGenerateSymmetricKey(pAesObj->hCryptProvider,
		&pAesObj->hKeyHdl, 
		pAesObj->pbKeyObject, 
		pAesObj->cbKeyObject, 
		pbKey, 
		cbKey, 
		0);
	if (!NT_SUCCESS(status))
	{
		return(FALSE);
	}
	
	return(TRUE);
}

BOOLEAN AES::Encrypt(PAESOBJ pAesInfo, PUCHAR pbPlain, ULONG cbPlain, PUCHAR pbCipher, ULONG cbCipher, PULONG pcbResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData = 0;
	BOOLEAN fOk = FALSE;

	if (!pAesInfo || !pbPlain || !cbPlain || !pbCipher || !cbCipher || !pcbResult)
	{
		return(FALSE);
	}
	do
	{
		status = BCryptEncrypt(pAesInfo->hKeyHdl, 
			pbPlain,
			cbPlain, 
			NULL, 
			pAesInfo->pbIV, 
			pAesInfo->cbIV, 
			NULL, 
			0, 
			&cbData, 
			0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		if (pcbResult)
		{
			*pcbResult = cbData;
		}
		status = BCryptEncrypt(pAesInfo->hKeyHdl, 
			pbPlain, 
			cbPlain,
			NULL, 
			pAesInfo->pbIV, 
			pAesInfo->cbIV, 
			pbCipher, 
			cbData, &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		
		fOk = TRUE;
	} while (FALSE);
	

	return(fOk);
}

BOOLEAN AES::Decrypt(PAESOBJ pAesObj, 
	PUCHAR pbCipher, 
	ULONG cbCipher, 
	PUCHAR pbPlain, 
	ULONG cbPlain, 
	PULONG pcbResult)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG cbData = 0;
	BOOLEAN fOk = FALSE;

	if (!pAesObj || !pbPlain || !cbPlain || !pbCipher || !cbCipher || !pcbResult)
	{
		return(FALSE);
	}
	do
	{
		status = BCryptDecrypt(pAesObj->hKeyHdl, pbCipher, cbCipher, NULL, pAesObj->pbIV, pAesObj->cbIV, NULL, 0, &cbData, 0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		if (pcbResult)
		{
			*pcbResult = cbData;
		}
		// after the decrypt, the plain text size is smaller than the cipher text
		// bcz AES128 is block cipher algorithm, each block is 16 bytes and it's align
		if (cbPlain < cbData)
		{
			break;
		}
		status = BCryptDecrypt(pAesObj->hKeyHdl, 
			pbCipher, 
			cbCipher, 
			NULL, 
			pAesObj->pbIV, 
			pAesObj->cbIV, 
			pbPlain, 
			cbData, 
			&cbData, 
			0);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		fOk = TRUE;
	} while (FALSE);

	return(fOk);
}