// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;

namespace KeePassPasskey.Passkey
{
    /// <summary>
    /// Pure matching of a KeePass entry's URL against a WebAuthn RP id, used to find existing
    /// entries a new passkey could be saved onto. No KeePass dependency, so it is unit-testable.
    /// </summary>
    internal static class RpIdMatcher
    {
        /// <summary>
        /// Returns true when the host of <paramref name="url"/> equals <paramref name="rpId"/> or is
        /// a subdomain of it (e.g. url host "www.github.com" matches rpId "github.com"). The match is
        /// case-insensitive. The leading-dot subdomain rule keeps lookalikes such as "mygithub.com"
        /// or "github.com.evil.com" from matching "github.com".
        /// </summary>
        internal static bool UrlHostMatchesRpId(string url, string rpId)
        {
            if (string.IsNullOrEmpty(rpId)) return false;

            var host = TryGetHost(url);
            if (string.IsNullOrEmpty(host)) return false;

            return string.Equals(host, rpId, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + rpId, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts the host from a URL, accepting values with or without a scheme (a bare
        /// "github.com/login" is treated as "https://github.com/login"). Port, path and query are
        /// discarded. Returns null when no host can be determined.
        /// </summary>
        internal static string TryGetHost(string url)
        {
            if (string.IsNullOrEmpty(url)) return null;

            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
                return uri.Host;
            if (Uri.TryCreate("https://" + url, UriKind.Absolute, out uri) && !string.IsNullOrEmpty(uri.Host))
                return uri.Host;
            return null;
        }
    }
}
