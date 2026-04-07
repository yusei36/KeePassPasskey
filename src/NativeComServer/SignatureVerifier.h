#pragma once
#include "pch.h"

/// Verifies that a request buffer was signed by the Windows platform using
/// the operation signing public key obtained at registration time.
class SignatureVerifier
{
public:
    /// Verify SHA-256 signature over dataBuffer using the stored public key.
    /// Public key is a BCRYPT_KEY_BLOB (as returned by WebAuthNPluginGetOperationSigningPublicKey).
    static HRESULT Verify(
        _In_reads_bytes_(cbData)        const BYTE* pbData,
        _In_                            DWORD       cbData,
        _In_reads_bytes_(cbKey)         PBYTE       pbKey,
        _In_                            DWORD       cbKey,
        _In_reads_bytes_(cbSignature)   PBYTE       pbSignature,
        _In_                            DWORD       cbSignature);
};
