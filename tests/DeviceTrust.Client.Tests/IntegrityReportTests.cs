using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Protocol;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>Tests for probe results and how they are written into a signed report.</summary>
    public sealed class IntegrityReportTests
    {
        [Fact]
        public void ProbeResult_CarriesItsStatus()
        {
            Assert.Equal("ok", ProbeResult.Ok().Status);
            Assert.Equal("error", ProbeResult.Error("IOException", "denied").Status);
            Assert.Equal("unsupported", ProbeResult.Unsupported("no such probe").Status);
        }

        [Fact]
        public void ProbeResult_IgnoresNullFieldsAsTheKotlinCollectorDoes()
        {
            var probe = ProbeResult.Ok().With("present", "value").With("absent", null);

            Assert.True(probe.Fields.ContainsKey("present"));
            Assert.False(probe.Fields.ContainsKey("absent"));
        }

        [Fact]
        public void ProbeResult_TruncatesLongErrorText()
        {
            var probe = ProbeResult.Error("IOException", new string('x', 500));

            Assert.Equal(240, ((string)probe.Fields["error"]!).Length);
        }

        [Fact]
        public void WriteProbes_PreservesJsonTypesTheServerDistinguishes()
        {
            // The server reads tracer_pid as an integer and su_found as a boolean.
            // Writing either as a string would make the check silently never fire.
            var probes = new Dictionary<string, ProbeResult>(StringComparer.Ordinal)
            {
                ["tracer"] = ProbeResult.Ok().With("tracer_pid", 0).With("seccomp", 2),
                ["root_shell"] = ProbeResult.Ok().With("su_found", false).With("su_path", string.Empty),
                ["root_files"] = ProbeResult.Ok().With("found_paths", new List<string> { "/sbin/su" }),
                ["system_properties"] = ProbeResult.Ok().With(
                    "properties",
                    new Dictionary<string, string>(StringComparer.Ordinal) { ["ro.secure"] = "1" }),
            };

            using var document = JsonDocument.Parse(WriteProbes(probes));
            var root = document.RootElement;

            Assert.Equal(JsonValueKind.Number, root.GetProperty("tracer").GetProperty("tracer_pid").ValueKind);
            Assert.Equal(JsonValueKind.False, root.GetProperty("root_shell").GetProperty("su_found").ValueKind);
            Assert.Equal(JsonValueKind.Array, root.GetProperty("root_files").GetProperty("found_paths").ValueKind);
            Assert.Equal(
                JsonValueKind.Object,
                root.GetProperty("system_properties").GetProperty("properties").ValueKind);
            Assert.Equal(
                "1",
                root.GetProperty("system_properties").GetProperty("properties").GetProperty("ro.secure").GetString());
        }

        [Fact]
        public void WriteProbes_AlwaysIncludesStatus()
        {
            var probes = new Dictionary<string, ProbeResult>(StringComparer.Ordinal)
            {
                ["mounts"] = ProbeResult.Error("IOException", "permission denied"),
            };

            using var document = JsonDocument.Parse(WriteProbes(probes));

            Assert.Equal("error", document.RootElement.GetProperty("mounts").GetProperty("status").GetString());
        }

        [Fact]
        public void IntegrityCollection_KeepsTheNonceEchoForBindingChecks()
        {
            var collection = new IntegrityCollection(
                "android",
                1,
                "nonce-echo",
                new Dictionary<string, ProbeResult>(StringComparer.Ordinal));

            Assert.Equal("android", collection.Platform);
            Assert.Equal("nonce-echo", collection.ChallengeNonceEcho);
            Assert.Equal(1, collection.CollectorVersion);
        }

        [Fact]
        public void IntegrityDecision_ParsesAServerVerdict()
        {
            using var document = JsonDocument.Parse(
                "{\"report_id\":\"r-1\",\"score\":90,\"verdict\":\"block\",\"hard_block\":false,"
                + "\"reasons\":[{\"code\":\"android_frida_runtime_artifact\",\"points\":90,"
                + "\"message\":\"Frida artifacts were mapped in.\",\"hard\":false}],"
                + "\"mode\":\"enforce\",\"fresh_for_seconds\":600,\"remote_attestation\":\"not_used\","
                + "\"created_at\":\"2026-09-05T00:00:00Z\"}");

            var decision = IntegrityDecision.Parse(document.RootElement);

            Assert.Equal("block", decision.Verdict);
            Assert.Equal(90, decision.Score);
            Assert.Equal("enforce", decision.Mode);
            Assert.Equal("not_used", decision.RemoteAttestation);
            Assert.Single(decision.Reasons);
            Assert.Equal("android_frida_runtime_artifact", decision.Reasons[0].Code);
        }

        [Fact]
        public void IntegrityChallenge_ParsesTheRequiredProbeList()
        {
            using var document = JsonDocument.Parse(
                "{\"challenge_id\":\"c-1\",\"nonce\":\"bm9uY2U\",\"platform\":\"android\","
                + "\"required_probes\":[\"app_identity\",\"selinux\"],\"expires_at\":\"\","
                + "\"server_time\":\"\",\"collector_policy_version\":1}");

            var challenge = IntegrityChallenge.Parse(document.RootElement);

            Assert.Equal("c-1", challenge.ChallengeId);
            Assert.Equal("android", challenge.Platform);
            Assert.Equal(new[] { "app_identity", "selinux" }, challenge.RequiredProbes);
        }

        private static byte[] WriteProbes(IReadOnlyDictionary<string, ProbeResult> probes)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                ProbeJsonWriter.WriteProbes(writer, probes);
            }

            return buffer.ToArray();
        }
    }
}
