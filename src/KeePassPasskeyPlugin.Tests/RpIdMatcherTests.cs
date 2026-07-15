// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskey.Passkey;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class RpIdMatcherTests
{
	// --- Exact host matches -------------------------------------------------------------

	[Theory]
	[InlineData("https://github.com", "github.com")]
	[InlineData("https://github.com/login?next=/x", "github.com")] // path + query stripped
	[InlineData("https://github.com:8443", "github.com")]           // port stripped
	[InlineData("github.com", "github.com")]                        // no scheme
	[InlineData("github.com/login", "github.com")]                  // no scheme, with path
	[InlineData("HTTPS://GitHub.com", "github.com")]                // case-insensitive
	[InlineData("https://github.com", "GITHUB.COM")]                // case-insensitive rpId
	public void UrlHostMatchesRpId_ExactHost_Matches(string url, string rpId)
	{
		Assert.True(RpIdMatcher.UrlHostMatchesRpId(url, rpId));
	}

	// --- Subdomain matches --------------------------------------------------------------

	[Theory]
	[InlineData("https://www.github.com/login", "github.com")]
	[InlineData("https://login.eu.github.com", "github.com")]
	[InlineData("www.github.com", "github.com")] // no scheme
	public void UrlHostMatchesRpId_Subdomain_Matches(string url, string rpId)
	{
		Assert.True(RpIdMatcher.UrlHostMatchesRpId(url, rpId));
	}

	// --- Non-matches (including lookalike / spoof attempts) -----------------------------

	[Theory]
	[InlineData("https://mygithub.com", "github.com")]        // suffix but not at a label boundary
	[InlineData("https://github.com.evil.com", "github.com")] // rpId is a middle label, not the host suffix
	[InlineData("https://gitlab.com", "github.com")]          // unrelated
	[InlineData("https://example.com", "login.example.com")]  // parent host does not match subdomain rpId (one-way)
	public void UrlHostMatchesRpId_Lookalikes_DoNotMatch(string url, string rpId)
	{
		Assert.False(RpIdMatcher.UrlHostMatchesRpId(url, rpId));
	}

	// --- Empty / null inputs ------------------------------------------------------------

	[Theory]
	[InlineData(null, "github.com")]
	[InlineData("", "github.com")]
	[InlineData("   ", "github.com")]            // whitespace has no host
	[InlineData("not a url", "github.com")]      // spaces -> no valid host
	[InlineData("https://github.com", null)]
	[InlineData("https://github.com", "")]
	public void UrlHostMatchesRpId_EmptyOrInvalidInputs_DoNotMatch(string? url, string? rpId)
	{
		Assert.False(RpIdMatcher.UrlHostMatchesRpId(url!, rpId!));
	}

	// --- TryGetHost -------------------------------------------------------------------

	[Theory]
	[InlineData("https://www.github.com/login?x=1", "www.github.com")]
	[InlineData("http://example.com:8080/path", "example.com")]
	[InlineData("github.com", "github.com")]        // scheme prepended
	[InlineData("github.com/login", "github.com")]  // scheme prepended, path stripped
	public void TryGetHost_ReturnsHost(string url, string expected)
	{
		Assert.Equal(expected, RpIdMatcher.TryGetHost(url));
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	public void TryGetHost_NoHost_ReturnsNull(string? url)
	{
		Assert.Null(RpIdMatcher.TryGetHost(url!));
	}
}
