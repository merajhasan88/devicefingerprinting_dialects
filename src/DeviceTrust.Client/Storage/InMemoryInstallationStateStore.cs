using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Storage
{
    /// <summary>A state store that keeps nothing between processes; useful for tests and one-shot runs.</summary>
    public sealed class InMemoryInstallationStateStore : IInstallationStateStore
    {
        private InstallationState _state = new InstallationState();

        /// <inheritdoc />
        public Task<InstallationState> LoadAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_state);
        }

        /// <inheritdoc />
        public Task SaveAsync(InstallationState state, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _state = state;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _state = new InstallationState();
            return Task.CompletedTask;
        }
    }
}
