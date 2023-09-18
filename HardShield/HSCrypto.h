#pragma once
#include "HSCommon.h"
#include "HSAES.h"
#include "HSRSA.h"

namespace Crypto
{
	BOOLEAN InitCrypto(PCRYPTO pCryptoObj, ULONG ucInitBufSize = HSIOBUFSIZE);

	VOID DestroyCrypto(PCRYPTO pCryptoObj);

	BOOLEAN GenKey(PCRYPTO pCryptoObj);

	BOOLEAN ImportPrivateKey(PCRYPTO pCryptObj, LPCTSTR pPrivateBlobFile);

	BOOLEAN ImportPrivateKey(PCRYPTO pCryptObj, PUCHAR pbPrivateBlob, ULONG cbPrivateBlob);

	BOOLEAN ImportPublicKey(PCRYPTO pCryptObj, LPCTSTR pPublicBlobFile);

	BOOLEAN ImportPublicKey(PCRYPTO pCryptObj, PUCHAR pbPublicBlob, ULONG cbPublicBlob);

	BOOLEAN Encrypt(PCRYPTO pCryptObj, LPCTSTR pFileName);

	BOOLEAN GenRandom(PUCHAR pbBuffer, ULONG cbBuffer);
};
