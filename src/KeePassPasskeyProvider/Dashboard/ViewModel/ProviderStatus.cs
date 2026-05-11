// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Kögel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Dashboard.ViewModel;

public enum ProviderStatus
{
    NotRegistered,
    AutoregisterFailed,
    WaitingToBeEnabled,
    PluginNotRunning,
    NoDatabase,
    VersionMismatch,
    Ready,
}
