namespace KeePassPasskeyProvider.Interop;

internal static class HResults
{
    public const int S_OK                                  = 0;
    public const int E_INVALIDARG                          = unchecked((int)0x80070057);
    public const int E_FAIL                                = unchecked((int)0x80004005);
    public const int E_NOINTERFACE                         = unchecked((int)0x80004002);
    public const int CLASS_E_NOAGGREGATION                 = unchecked((int)0x80040110);
    public const int NTE_BAD_SIGNATURE                     = unchecked((int)0x80090006);
    public const int NTE_NOT_FOUND                         = unchecked((int)0x80090011);
    public const int NTE_USER_CANCELLED                    = unchecked((int)0x80090036);
    public const int HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS   = unchecked((int)0x800700B7);
}
