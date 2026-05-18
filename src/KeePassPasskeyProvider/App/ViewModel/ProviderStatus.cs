// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.App.ViewModel;

public enum ProviderStatus
{
    NotRegistered,
    AutoregisterFailed,
    WaitingToBeEnabled,
    KeePassNotConnected,
    NoDatabase,
    VersionMismatch,
    Ready,
}
