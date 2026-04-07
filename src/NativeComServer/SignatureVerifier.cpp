#include "pch.h"
#include "SignatureVerifier.h"

HRESULT SignatureVerifier::Verify(
    const BYTE* pbData, DWORD cbData,
    PBYTE pbKey, DWORD cbKey,
    PBYTE pbSignature, DWORD cbSignature)
{
    // Import the public key into NCrypt
    wil::unique_ncrypt_prov hProvider;
    wil::unique_ncrypt_key hKey;

    RETURN_IF_FAILED(NCryptOpenStorageProvider(&hProvider, nullptr, 0));
    RETURN_IF_FAILED(NCryptImportKey(
        hProvider.get(), NULL, BCRYPT_PUBLIC_KEY_BLOB,
        nullptr, &hKey, pbKey, cbKey, 0));

    // Hash the data with SHA-256
    DWORD objLenSize = 0, bytesRead = 0;
    RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
        BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PBYTE>(&objLenSize), sizeof(objLenSize), &bytesRead, 0));

    auto hashObj = std::make_unique<BYTE[]>(objLenSize);
    wil::unique_bcrypt_hash hHash;
    RETURN_IF_NTSTATUS_FAILED(BCryptCreateHash(
        BCRYPT_SHA256_ALG_HANDLE, wil::out_param(hHash),
        hashObj.get(), objLenSize, nullptr, 0, 0));
    RETURN_IF_NTSTATUS_FAILED(BCryptHashData(
        hHash.get(), const_cast<PUCHAR>(pbData), cbData, 0));

    DWORD hashLen = 0;
    RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
        BCRYPT_SHA256_ALG_HANDLE, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PBYTE>(&hashLen), sizeof(hashLen), &bytesRead, 0));

    auto hash = std::make_unique<BYTE[]>(hashLen);
    RETURN_IF_NTSTATUS_FAILED(BCryptFinishHash(hHash.get(), hash.get(), hashLen, 0));

    // Determine padding (RSA vs EC)
    PVOID paddingInfo = nullptr;
    DWORD dwFlags = 0;
    BCRYPT_PKCS1_PADDING_INFO pkcs1 = {};

    if (cbKey >= sizeof(BCRYPT_KEY_BLOB))
    {
        auto* pKeyBlob = reinterpret_cast<BCRYPT_KEY_BLOB*>(pbKey);
        if (pKeyBlob->Magic == BCRYPT_RSAPUBLIC_MAGIC)
        {
            pkcs1.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            paddingInfo = &pkcs1;
            dwFlags = BCRYPT_PAD_PKCS1;
        }
    }

    RETURN_IF_WIN32_ERROR(NCryptVerifySignature(
        hKey.get(), paddingInfo,
        hash.get(), hashLen,
        pbSignature, cbSignature,
        dwFlags));

    return S_OK;
}
