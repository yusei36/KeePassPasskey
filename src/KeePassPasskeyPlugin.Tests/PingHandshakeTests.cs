// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskey.Ipc;
using KeePassPasskeyShared.Ipc;
using Xunit;

namespace KeePassPasskeyPlugin.Tests
{
    public class PingHandshakeTests
    {
        [Fact]
        public void MatchingProtocolVersion_DatabaseOpen_ReturnsReady()
        {
            var r = RequestHandler.BuildPingResponse(PipeConstants.ProtocolVersion, databaseOpen: true);
            Assert.Equal(PingStatus.Ready, r.Status);
        }

        [Fact]
        public void MatchingProtocolVersion_NoDatabase_ReturnsNoDatabase()
        {
            var r = RequestHandler.BuildPingResponse(PipeConstants.ProtocolVersion, databaseOpen: false);
            Assert.Equal(PingStatus.NoDatabase, r.Status);
        }

        [Theory]
        [InlineData(0)] // legacy peer sends no protocolVersion field
        [InlineData(int.MaxValue)]
        public void DifferentProtocolVersion_ReturnsIncompatibleVersion(int clientProtocolVersion)
        {
            var r = RequestHandler.BuildPingResponse(clientProtocolVersion, databaseOpen: true);
            Assert.Equal(PingStatus.IncompatibleVersion, r.Status);
        }

        [Fact]
        public void Response_CarriesServerProtocolVersion()
        {
            var r = RequestHandler.BuildPingResponse(PipeConstants.ProtocolVersion, databaseOpen: true);
            Assert.Equal(PipeConstants.ProtocolVersion, r.ProtocolVersion);
        }
    }
}
