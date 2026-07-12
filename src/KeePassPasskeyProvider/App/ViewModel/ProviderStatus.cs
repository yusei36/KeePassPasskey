// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.App.ViewModel;

// VersionMismatch = compatible protocol but different product versions (still fully working,
// shown as a caution), unlike the blocking IncompatibleVersion.
public enum ProviderStatus
{
    NotRegistered,
    AutoregisterFailed,
    WaitingToBeEnabled,
    KeePassNotConnected,
    NoDatabase,
    IncompatibleVersion,
    VersionMismatch,
    Ready,
}

// State of the "KeePass plugin" pill; version states follow the same distinction as ProviderStatus.
public enum PluginPillState
{
    NotConnected,
    Running,
    NoDatabase,
    VersionMismatch,
    IncompatibleVersion,
}
