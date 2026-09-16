using System.Text.Json;

namespace DeviceTrust.Client.Storage
{
    /// <summary>
    /// Serialises <see cref="InstallationState"/> for a platform state store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Exists so a store living outside this assembly — the iOS Keychain one, for
    /// instance — writes exactly the same shape as the file-backed one, and so
    /// that a record written by one can be read by the other.
    /// </para>
    /// <para>
    /// It wraps a source-generated serializer context rather than reflection,
    /// which is what keeps the SDK usable inside a trimmed, AOT-compiled
    /// application; that matters on both mobile platforms, where device builds
    /// are AOT. The context itself stays internal because its generated members
    /// carry no XML documentation, and this package treats missing documentation
    /// on public API as an error.
    /// </para>
    /// </remarks>
    public static class InstallationStateSerializer
    {
        /// <summary>Serialises the state to JSON.</summary>
        public static string Serialize(InstallationState state)
        {
            return JsonSerializer.Serialize(state, InstallationStateJsonContext.Default.InstallationState);
        }

        /// <summary>
        /// Parses stored JSON, returning null when it cannot be read.
        /// </summary>
        /// <remarks>
        /// A corrupt record must never wedge the client: discarding it costs one
        /// re-enrolment, and the server recognises the installation key anyway
        /// and answers with the canonical installation id.
        /// </remarks>
        public static InstallationState? Deserialize(string json)
        {
            try
            {
                return JsonSerializer.Deserialize(json, InstallationStateJsonContext.Default.InstallationState);
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }
}
