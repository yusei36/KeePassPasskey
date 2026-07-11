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

        /// <summary>
        /// <see cref="Version"/> with the SemVer build metadata (the "gitsha" the SDK appends)
        /// removed, used for the pipe compatibility handshake. This makes two builds of the same version
        /// from different commits e.g. a Store build vs a GitHub build compatible. The pre-release tag
        /// (e.g. "-dev") is kept, so Debug and Release stay incompatible.
        /// </summary>
        public static readonly string CompatibilityVersion = StripBuildMetadata(Version);

        /// <summary>Removes SemVer build metadata (everything from the first '+') from a version string.</summary>
        public static string StripBuildMetadata(string version)
        {
            if (string.IsNullOrEmpty(version)) return version;
            var plus = version.IndexOf('+');
            return plus >= 0 ? version.Substring(0, plus) : version;
        }
    }
}
