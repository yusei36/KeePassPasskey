// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskey.Ipc;
using KeePassPasskeyShared.Ipc;
using Newtonsoft.Json;
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

    public class ProtocolVersionGateTests
    {
        [Fact]
        public void MatchingProtocolVersion_IsAllowed()
        {
            var req = new SaveSettingsRequest { ProtocolVersion = PipeConstants.ProtocolVersion };
            Assert.Null(RequestHandler.CheckProtocolVersion(req));
        }

        [Fact]
        public void MissingProtocolVersion_IsAllowed()
        {
            var req = new SaveSettingsRequest { ProtocolVersion = null };
            Assert.Null(RequestHandler.CheckProtocolVersion(req));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(int.MaxValue)]
        public void MismatchedProtocolVersion_IsRejected(int clientProtocolVersion)
        {
            var req = new SaveSettingsRequest { ProtocolVersion = clientProtocolVersion };
            var error = RequestHandler.CheckProtocolVersion(req);
            Assert.Equal(PipeErrorCode.IncompatibleVersion, error?.ErrorCode);
        }

        [Fact]
        public void MismatchedPing_IsExemptSoTheHandshakeCanReport()
        {
            var req = new PingRequest { ProtocolVersion = int.MaxValue };
            Assert.Null(RequestHandler.CheckProtocolVersion(req));
        }

        [Fact]
        public void LegacyJsonWithoutProtocolVersion_DeserializesToNull()
        {
            var req = JsonConvert.DeserializeObject<PipeRequestBase>(@"{""type"":""save_settings""}")!;
            Assert.Null(req.ProtocolVersion);
        }

        [Fact]
        public void SerializedRequest_CarriesProtocolVersion()
        {
            var json = JsonConvert.SerializeObject(new SaveSettingsRequest { ProtocolVersion = PipeConstants.ProtocolVersion });
            var round = JsonConvert.DeserializeObject<PipeRequestBase>(json)!;
            Assert.Equal(PipeConstants.ProtocolVersion, round.ProtocolVersion);
        }
    }
}
