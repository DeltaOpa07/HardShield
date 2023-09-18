#pragma once
#include "HSCommon.h"

namespace AES
{
	// CBC AES128
	VOID InitAESObj(PAESOBJ pAesObj);

	BOOLEAN HSInitAES(PAESOBJ pAesObj);

	BOOLEAN Encrypt(PAESOBJ pAesInfo,
		PUCHAR pbPlain,
		ULONG cbPlain,
		PUCHAR pbCipher,
		ULONG cbCipher,
		PULONG pcbResult);

	BOOLEAN Decrypt(PAESOBJ pAesObj,
		PUCHAR pbCipher,
		ULONG cbCipher,
		PUCHAR pbPlain,
		ULONG cbPlain,
		PULONG pcbResult);

	BOOLEAN GenKey(PAESOBJ pAesObj,
		PUCHAR pbKey,
		ULONG cbKey);
	VOID DestroyAESObj(PAESOBJ pAesObj);
};


