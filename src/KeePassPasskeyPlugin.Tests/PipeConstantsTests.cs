// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
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

        [Fact]
        public void CompatibilityVersion_HasNoBuildMetadata()
        {
            Assert.DoesNotContain('+', PipeConstants.CompatibilityVersion);
        }
    }
}
