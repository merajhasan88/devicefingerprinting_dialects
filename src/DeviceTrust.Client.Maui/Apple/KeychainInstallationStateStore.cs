using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Storage;
using Foundation;
using Security;

namespace DeviceTrust.Client.Maui.Apple
{
    /// <summary>
    /// Keeps the installation state in the iOS Keychain rather than in the app's
    /// container.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is not a convenience; on iOS it is a correctness requirement, and
    /// using a file would produce a silent, slow-burning defect.
    /// </para>
    /// <para>
    /// Deleting an iOS app wipes its data container but leaves Keychain items
    /// alone. The Secure Enclave key therefore survives a reinstall, which is
    /// the whole point of battery item 15. If the installation id lived in a
    /// file beside it, the reinstall would bring back the same key under a
    /// <b>new</b> installation id, and the two would disagree: the key says
    /// "the same installation", the id says "a new one". Nothing fails loudly.
    /// The server simply accumulates orphaned installation rows, each holding a
    /// key thumbprint it has already seen, and the reinstall-recognition
    /// property the iPhone is supposed to demonstrate quietly stops being
    /// demonstrated.
    /// </para>
    /// <para>
    /// Accessibility matches the key's own:
    /// <c>AfterFirstUnlockThisDeviceOnly</c>, so the record is readable by a
    /// background launch once the device has been unlocked since boot, and is
    /// excluded from iCloud Keychain and from encrypted backups. State that
    /// could restore onto a second device would undermine exactly the binding
    /// the key provides.
    /// </para>
    /// <para>
    /// A caveat worth stating rather than discovering: Keychain items are scoped
    /// by access group, which on a TrollStore-installed build comes from the
    /// <c>keychain-access-groups</c> entitlement. Change that value between
    /// builds and this record becomes unreachable in exactly the same way the
    /// Secure Enclave key does, so the two stay consistent — both lost, never
    /// one without the other.
    /// </para>
    /// </remarks>
    public sealed class KeychainInstallationStateStore : IInstallationStateStore
    {
        private const string DefaultService = "com.devicetrust.installation-state.v1";

        private readonly string _service;
        private readonly string _account;

        /// <summary>Creates a Keychain-backed state store.</summary>
        public KeychainInstallationStateStore(string? service = null, string? account = null)
        {
            _service = string.IsNullOrWhiteSpace(service) ? DefaultService : service!;
            _account = string.IsNullOrWhiteSpace(account) ? "installation" : account!;
        }

        /// <inheritdoc />
        public Task<InstallationState> LoadAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var query = BuildQuery();
            var record = SecKeyChain.QueryAsRecord(query, out var status);
            if (status != SecStatusCode.Success || record?.ValueData is null)
            {
                return Task.FromResult(new InstallationState());
            }

            try
            {
                var json = Encoding.UTF8.GetString(record.ValueData.ToArray());
                return Task.FromResult(InstallationStateSerializer.Deserialize(json) ?? new InstallationState());
            }
            finally
            {
                record.Dispose();
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

            var json = InstallationStateSerializer.Serialize(state);
            using var value = NSData.FromString(json, NSStringEncoding.UTF8);

            // SecItemUpdate only works on an item that exists, and SecItemAdd
            // fails with errSecDuplicateItem on one that does. Remove-then-add
            // is the simplest form that is correct in both cases; this record is
            // written rarely and is not contended.
            using (var existing = BuildQuery())
            {
                SecKeyChain.Remove(existing);
            }

            using var record = BuildQuery();
            record.ValueData = value;
            record.Accessible = SecAccessible.AfterFirstUnlockThisDeviceOnly;

            var status = SecKeyChain.Add(record);
            if (status != SecStatusCode.Success)
            {
                throw new InvalidOperationException(
                    "The installation state could not be written to the Keychain: " + status);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var query = BuildQuery();
            var status = SecKeyChain.Remove(query);
            if (status is not (SecStatusCode.Success or SecStatusCode.ItemNotFound))
            {
                throw new InvalidOperationException(
                    "The installation state could not be removed from the Keychain: " + status);
            }

            return Task.CompletedTask;
        }

        private SecRecord BuildQuery()
        {
            return new SecRecord(SecKind.GenericPassword)
            {
                Service = _service,
                Account = _account,
            };
        }
    }
}
