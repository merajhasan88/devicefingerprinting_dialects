using System;
using System.IO;
using System.Threading.Tasks;
using DeviceTrust.Client;
using DeviceTrust.Client.Keys;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>Behavioural tests for the key-store contract, using the software store.</summary>
    public sealed class SoftwareKeyStoreTests : IDisposable
    {
        private readonly string _directory;

        public SoftwareKeyStoreTests()
        {
            _directory = Path.Combine(Path.GetTempPath(), "devicetrust-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
        }

        [Fact]
        public void Constructor_RefusesToBeSelectedByAccident()
        {
            // The acknowledgement argument exists so that choosing a store with no
            // device binding is a deliberate, greppable decision at the call site.
            var error = Assert.Throws<InstallationKeyException>(
                () => new SoftwareInstallationKeyStore(KeyPath(), acknowledgeNotHardwareBacked: false));

            Assert.Equal("SOFTWARE_KEY_NOT_ACKNOWLEDGED", error.Code);
        }

        [Fact]
        public async Task GetOrCreateKey_ReportsCreatedOnlyOnTheFirstCall()
        {
            using var store = NewStore();

            var first = await store.GetOrCreateKeyAsync();
            var second = await store.GetOrCreateKeyAsync();

            Assert.True(first.Created);
            Assert.True(second.Created, "the same process should keep reporting the key it created this session");
            Assert.Equal(first.PublicKey.Thumbprint, second.PublicKey.Thumbprint);
        }

        [Fact]
        public async Task GetOrCreateKey_ReusesAKeyLeftOnDiskByAnEarlierProcess()
        {
            string thumbprint;
            using (var first = NewStore())
            {
                thumbprint = (await first.GetOrCreateKeyAsync()).PublicKey.Thumbprint;
            }

            using var second = NewStore();
            var metadata = await second.GetOrCreateKeyAsync();

            Assert.False(metadata.Created);
            Assert.Equal(thumbprint, metadata.PublicKey.Thumbprint);
        }

        [Fact]
        public async Task GetOrCreateKey_DescribesItselfHonestly()
        {
            using var store = NewStore();

            var metadata = await store.GetOrCreateKeyAsync();

            Assert.False(metadata.HardwareBacked);
            Assert.True(metadata.PrivateKeyExportable);
            Assert.Equal("software", metadata.SecurityLevel);
            Assert.Equal("ES256", metadata.Algorithm);
            Assert.Equal("asn1_der", metadata.SignatureFormat);
        }

        [Fact]
        public async Task Sign_ReturnsADerSignatureOverTheGivenBytes()
        {
            using var store = NewStore();
            await store.GetOrCreateKeyAsync();

            var signature = await store.SignAsync(new byte[] { 1, 2, 3, 4 });

            Assert.True(EcdsaSignatureFormat.LooksLikeDerSequence(signature));
        }

        [Fact]
        public async Task Sign_BeforeAnyKeyExistsFailsWithKeyNotFound()
        {
            using var store = NewStore();

            var error = await Assert.ThrowsAsync<InstallationKeyException>(
                () => store.SignAsync(new byte[] { 1 }));

            Assert.Equal("KEY_NOT_FOUND", error.Code);
        }

        [Fact]
        public async Task DeleteKey_MakesTheNextGetOrCreateProduceAFreshIdentity()
        {
            using var store = NewStore();
            var original = await store.GetOrCreateKeyAsync();

            await store.DeleteKeyAsync();
            var replacement = await store.GetOrCreateKeyAsync();

            Assert.True(replacement.Created);
            Assert.NotEqual(original.PublicKey.Thumbprint, replacement.PublicKey.Thumbprint);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }

        private SoftwareInstallationKeyStore NewStore()
        {
            return new SoftwareInstallationKeyStore(KeyPath(), acknowledgeNotHardwareBacked: true);
        }

        private string KeyPath()
        {
            return Path.Combine(_directory, "installation-key.p8");
        }
    }
}
