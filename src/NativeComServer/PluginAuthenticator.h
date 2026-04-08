#pragma once
#include "pch.h"
#include <pluginauthenticator.h>
#include <wrl/implements.h>

using namespace Microsoft::WRL;

class PluginAuthenticator :
    public RuntimeClass<RuntimeClassFlags<ClassicCom>, IPluginAuthenticator>
{
public:
    PluginAuthenticator();
    ~PluginAuthenticator() = default;

    // IPluginAuthenticator — real interface from pluginauthenticator.h
    HRESULT STDMETHODCALLTYPE MakeCredential(
        __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pRequest,
        __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE pResponse) noexcept override;

    HRESULT STDMETHODCALLTYPE GetAssertion(
        __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pRequest,
        __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE pResponse) noexcept override;

    HRESULT STDMETHODCALLTYPE CancelOperation(
        __RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST pCancelRequest) noexcept override;

    HRESULT STDMETHODCALLTYPE GetLockStatus(
        __RPC__out PLUGIN_LOCK_STATUS* pLockStatus) noexcept override;

private:
    volatile bool m_cancelled = false;
};

class PluginAuthenticatorFactory :
    public RuntimeClass<RuntimeClassFlags<ClassicCom>, IClassFactory>
{
public:
    STDMETHODIMP CreateInstance(IUnknown* pOuter, REFIID riid, void** ppv) noexcept override;
    STDMETHODIMP LockServer(BOOL fLock) noexcept override;
};
