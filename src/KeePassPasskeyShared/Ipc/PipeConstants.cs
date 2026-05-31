// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;

namespace KeePassPasskeyShared.Ipc
{
    public static class PipeConstants
    {
#if DEBUG
        public const string PipeName = "keepass-passkey-provider-dev";
#else
        public const string PipeName = "keepass-passkey-provider";
#endif

        public static readonly string Version =
            Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion ?? "unknown";
    }
}
