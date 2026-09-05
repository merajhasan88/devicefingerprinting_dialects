using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Storage
{
    /// <summary>
    /// Persists the client's local, non-secret installation state.
    /// </summary>
    /// <remarks>
    /// On mobile this should be backed by the platform's secure storage
    /// (EncryptedSharedPreferences or the iOS keychain with
    /// <c>kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly</c>), matching what
    /// the Flutter client does with <c>flutter_secure_storage</c>. The private
    /// key is never part of this state, so a plain-file implementation is a
    /// reasonable choice for desktop and CI.
    /// </remarks>
    public interface IInstallationStateStore
    {
        /// <summary>Loads the stored state, or an empty record when nothing is stored.</summary>
        Task<InstallationState> LoadAsync(CancellationToken cancellationToken = default);

        /// <summary>Writes the state.</summary>
        Task SaveAsync(InstallationState state, CancellationToken cancellationToken = default);

        /// <summary>Removes all stored state.</summary>
        Task ClearAsync(CancellationToken cancellationToken = default);
    }
}
