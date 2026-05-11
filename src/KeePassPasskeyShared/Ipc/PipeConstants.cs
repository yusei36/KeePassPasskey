// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Kögel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;

namespace KeePassPasskeyShared.Ipc
{
    public static class PipeConstants
    {
        public const string PipeName = "keepass-passkey-provider";

        public static readonly string Version =
            Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion ?? "unknown";
    }
}
