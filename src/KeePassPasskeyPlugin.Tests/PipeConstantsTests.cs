// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using KeePassPasskeyShared.Ipc;
using Xunit;

namespace KeePassPasskeyPlugin.Tests
{
    public class PipeConstantsTests
    {
        [Theory]
        [InlineData("1.3.0+697b6b6df23fb7e1a0398261e350b5bed3020346", "1.3.0")]
        [InlineData("1.3.0-dev+7d169e9b1d06d1147f26636d3d561fda74cd663b", "1.3.0-dev")] // pre-release tag kept
        [InlineData("1.3.0", "1.3.0")]                                                  // no metadata
        [InlineData("1.3.0-dev", "1.3.0-dev")]
        [InlineData("", "")]
        public void StripBuildMetadata_RemovesCommitHashButKeepsVersionAndPreRelease(string input, string expected)
        {
            Assert.Equal(expected, PipeConstants.StripBuildMetadata(input));
        }

        [Fact]
        public void StripBuildMetadata_Null_ReturnsNull()
        {
            Assert.Null(PipeConstants.StripBuildMetadata(null));
        }

        [Theory]
        [InlineData("1.3.0", "1.2.3", 1)]
        [InlineData("1.2.3", "1.3.0", -1)]
        [InlineData("1.3.0", "1.3.0", 0)]
        [InlineData("1.4.0-dev+abc123", "1.3.0+def456", 1)]          // different numeric parts: 1.4.0 > 1.3.0 regardless of the -dev tag or +commit metadata
        [InlineData("1.4.0-dev", "1.3.0-dev", 1)]                    // two Debug builds (same -dev pipe): numeric still wins
        [InlineData("1.4.0-dev", "1.4.0", -1)]                       // -dev never meets a release across the pipe; documents that -dev sorts older
        [InlineData("1.4.0-rc1", "1.4.0", -1)]                       // pre-release is older than the final
        [InlineData("1.4.0", "1.4.0-rc1", 1)]                        // final is newer than the pre-release
        [InlineData("1.4.0-rc1", "1.4.0-rc1", 0)]                    // same pre-release
        [InlineData("1.4.0-rc1", "1.4.0-rc2", -1)]                   // ordinal within same numeric
        [InlineData("1.3.0-dev+abc123", "1.3.0-dev+def456", 0)]      // build metadata ignored
        [InlineData("unknown", "1.3.0", 0)]                          // unparseable -> 0
        [InlineData("", "1.3.0", 0)]
        public void CompareProductVersions_ComparesNumericThenPreRelease(string a, string b, int expectedSign)
        {
            Assert.Equal(expectedSign, Math.Sign(PipeConstants.CompareProductVersions(a, b)));
        }
    }
}
