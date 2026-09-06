using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Storage
{
    /// <summary>
    /// Source-generated serialization metadata for <see cref="InstallationState"/>.
    /// </summary>
    /// <remarks>
    /// Reflection-based <c>JsonSerializer</c> is not trim-safe, and an Android
    /// application built with <c>RunAOTCompilation</c> must be trimmed, so a
    /// reflection call here would stop the whole application building. The
    /// generated context costs nothing and removes that constraint.
    /// </remarks>
    [JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    [JsonSerializable(typeof(InstallationState))]
    internal sealed partial class InstallationStateJsonContext : JsonSerializerContext
    {
    }

    /// <summary>A JSON-file state store for desktop builds, CI and test harnesses.</summary>
    public sealed class FileInstallationStateStore : IInstallationStateStore
    {
        private readonly string _path;

        /// <summary>Creates a store backed by the file at <paramref name="path"/>.</summary>
        public FileInstallationStateStore(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("A state file path is required.", nameof(path));
            }

            _path = path;
        }

        /// <inheritdoc />
        public Task<InstallationState> LoadAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(_path))
            {
                return Task.FromResult(new InstallationState());
            }

            try
            {
                var text = File.ReadAllText(_path);
                var state = JsonSerializer.Deserialize(text, InstallationStateJsonContext.Default.InstallationState);
                return Task.FromResult(state ?? new InstallationState());
            }
            catch (JsonException)
            {
                // A corrupt state file must not wedge the client. Discarding it
                // costs one re-enrolment; the server recognises the key anyway
                // and answers with the canonical installation id.
                return Task.FromResult(new InstallationState());
            }
        }

        /// <inheritdoc />
        public Task SaveAsync(InstallationState state, CancellationToken cancellationToken = default)
        {
            if (state is null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            cancellationToken.ThrowIfCancellationRequested();
            state.UpdatedAt = DateTimeOffset.UtcNow;

            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory!);
            }

            File.WriteAllText(_path, JsonSerializer.Serialize(state, InstallationStateJsonContext.Default.InstallationState));
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(_path))
            {
                File.Delete(_path);
            }

            return Task.CompletedTask;
        }
    }
}
