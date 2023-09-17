#include "HSAES.h"

VOID InitAESObj(PAESOBJ pAesObj)
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

VOID DestroyAESObj(PAESOBJ pAesObj)
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
	}
}

BOOLEAN HSInitAES(PAESOBJ pAesObj)
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
		InitAESObj(pAesObj);

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
