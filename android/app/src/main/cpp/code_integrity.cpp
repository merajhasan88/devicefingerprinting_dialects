// Native code-integrity probe.
//
// Runs IN the app's own process and reads the app's own already-mapped,
// readable r-x pages by direct pointer. That is the whole reason it is native:
// the Kotlin attempt opened /proc/self/mem, which SELinux denies to
// untrusted_app on Android 9/10; reading one's own mapped pages needs no such
// access and no ptrace.
//
// For each target library it compares EVERY executable mapping against the same
// bytes on disk. Iterating every VMA (not just the first) is essential: an
// inline hooker flips individual code pages writable to patch them, which
// splits a library's single r-x mapping into several, and the patched page is
// usually not the first. The dynamic linker does not modify .text at runtime
// (relocations land in the GOT/data segments), so on a clean device memory and
// disk are byte-identical; a hook overwrites a prologue and shows up here as a
// difference, whatever the hooking framework is called.
//
// Targets are grouped into three buckets so the server can weight them
// separately:
//   core - libc, libart. Validated at zero on clean hardware; scored today.
//   ext  - other high-value system hook targets, TLS included (cert-pinning
//          bypass patches libssl/libcrypto). Scored once baselined on device.
//   app  - the app's own native code (Flutter engine + Dart AOT). Catches
//          in-memory patching of the app itself. Scored once baselined.

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

namespace {

// Bytes compared per bucket at most. Deliberately far above any real target
// set, so every target mapping is measured IN FULL: the old 4 MiB cap per
// suffix left the rest of large mappings (libart, the Flutter engine and the
// Dart AOT code share the ".apk" suffix) unmeasured while reporting clean
// (review F4, DESIGN.md 63). Anything the budget still cuts off is reported
// as skipped_bytes, never silently dropped.
constexpr size_t kBucketBudget = 256u << 20;
constexpr size_t kChunk = 256u << 10;  // compared in 256 KiB chunks

const char *kCore[] = {"/libc.so", "/libart.so", nullptr};
const char *kExt[] = {
    "/libc++.so", "/libssl.so", "/libcrypto.so",
    "/libandroid_runtime.so", "/libbinder.so", nullptr,
};
// The app's own native code. A normal Flutter release APK does NOT extract its
// native libraries: they are mapped straight out of the (uncompressed) zip, so
// /proc/self/maps shows them backed by ".../base.apk" rather than
// ".../lib/arm64/libflutter.so". Matching only the .so names measured nothing
// on a real release build. ".apk" covers the mapped-from-archive case (base
// and split APKs); the .so names still cover builds that do extract.
const char *kApp[] = {"/libflutter.so", "/libapp.so", ".apk", nullptr};

// What one bucket measured. expected = compared + skipped + unreadable, so a
// bucket that measured less than its targets says so instead of reading clean.
struct Coverage {
    long expected = 0;    // bytes in the executable target mappings found
    long compared = 0;    // bytes actually compared against disk
    long skipped = 0;     // not compared: the bucket budget ran out
    long unreadable = 0;  // not compared: unlockable, unopenable or short read
    long diff = 0;        // compared bytes that differ from disk
    int found = 0;        // target libraries mapped at all
    int withDiff = 0;     // target libraries with at least one differing byte
};

struct Counters {
    int xomUnlocked = 0;      // execute-only mappings made readable for the copy
    int xomUnreadable = 0;    // execute-only mappings that could not be
    int restoreFailures = 0;  // protections that could not be put back
};

int protection_of(const char *perms) {
    int prot = PROT_NONE;
    if (perms[0] == 'r') prot |= PROT_READ;
    if (perms[1] == 'w') prot |= PROT_WRITE;
    if (perms[2] == 'x') prot |= PROT_EXEC;
    return prot;
}

// Puts a mapping's EXACT original protection back on every exit path. The old
// loop restored plain PROT_EXEC by hand at each early exit, and changed
// mappings it then skipped as non-targets (review F5).
class ProtectionGuard {
  public:
    explicit ProtectionGuard(int *failures) : failures_(failures) {}
    ProtectionGuard(const ProtectionGuard &) = delete;
    ProtectionGuard &operator=(const ProtectionGuard &) = delete;
    void arm(void *start, size_t len, int original) {
        start_ = start; len_ = len; original_ = original; armed_ = true;
    }
    ~ProtectionGuard() {
        if (armed_ && mprotect(start_, len_, original_) != 0) (*failures_)++;
    }
  private:
    int *failures_;
    void *start_ = nullptr;
    size_t len_ = 0;
    int original_ = PROT_NONE;
    bool armed_ = false;
};

bool ends_with(const char *text, const char *suffix) {
    size_t len = strlen(text), suffix_len = strlen(suffix);
    return len >= suffix_len && strcmp(text + len - suffix_len, suffix) == 0;
}

// Compare `limit` bytes of one mapping with the file bytes at `offset`.
// Returns the bytes compared; adds differing bytes to *diff.
size_t compare_mapping(const unsigned char *mem, int fd, unsigned long offset,
                       size_t limit, unsigned char *buf, long *diff) {
    size_t done = 0;
    while (done < limit) {
        size_t want = limit - done < kChunk ? limit - done : kChunk;
        ssize_t got = pread(fd, buf, want, (off_t) (offset + done));
        if (got <= 0) break;
        for (ssize_t i = 0; i < got; i++) if (mem[done + i] != buf[i]) (*diff)++;
        done += (size_t) got;
        if ((size_t) got < want) break;  // short read: the rest is unreadable
    }
    return done;
}

// Compare every executable mapping ending with `suffix` against disk, adding
// what was measured to `cov`. Returns whether any mapping matched.
bool compare_one(const char *suffix, Coverage *cov, Counters *counters,
                 unsigned char *buf) {
    FILE *maps = fopen("/proc/self/maps", "re");
    if (!maps) return false;
    bool any = false;
    long diffBefore = cov->diff;
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start = 0, end = 0, offset = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int matched = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %*d %511[^\n]",
                             &start, &end, perms, &offset, path);
        if (matched < 5 || perms[2] != 'x') continue;
        char *p = path;
        while (*p == ' ') p++;
        // Select the target BEFORE touching any protection: a mapping that is
        // not measured is never modified (review F5).
        if (!ends_with(p, suffix) || end <= start) continue;
        any = true;
        size_t span = end - start;
        cov->expected += (long) span;
        size_t used = (size_t) (cov->compared + cov->unreadable);
        size_t room = used < kBucketBudget ? kBucketBudget - used : 0;
        size_t limit = span < room ? span : room;
        cov->skipped += (long) (span - limit);
        if (limit == 0) continue;

        // Android 10+ maps system libraries EXECUTE-ONLY (--xp); dereferencing
        // such a page segfaults. Add PROT_READ for the copy only; the guard
        // restores the original protection whatever happens next. If adding it
        // is refused, the bytes are unreadable -- counted, never clean.
        ProtectionGuard guard(&counters->restoreFailures);
        if (perms[0] != 'r') {
            int original = protection_of(perms);
            if (mprotect((void *) start, span, original | PROT_READ) != 0) {
                counters->xomUnreadable++;
                cov->unreadable += (long) limit;
                continue;
            }
            guard.arm((void *) start, span, original);
            counters->xomUnlocked++;
        }
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            cov->unreadable += (long) limit;
            continue;
        }
        size_t done = compare_mapping((const unsigned char *) start, fd, offset,
                                      limit, buf, &cov->diff);
        close(fd);
        cov->compared += (long) done;
        cov->unreadable += (long) (limit - done);
    }
    fclose(maps);
    if (any) {
        cov->found++;
        if (cov->diff > diffBefore) cov->withDiff++;
    }
    return any;
}

// Sum a bucket; append the name of any library that differs to `names`.
void compare_bucket(const char **suffixes, Coverage *cov, Counters *counters,
                    unsigned char *buf, char *names, size_t names_cap) {
    for (int i = 0; suffixes[i] != nullptr; i++) {
        long before = cov->diff;
        if (!compare_one(suffixes[i], cov, counters, buf)) continue;
        if (cov->diff > before) {
            const char *n = suffixes[i] + 1;  // drop leading '/'
            size_t used = strlen(names);
            size_t need = strlen(n) + (used ? 1 : 0);
            if (used + need + 1 < names_cap) {
                if (used) strcat(names, ",");
                strcat(names, n);
            }
        }
    }
}

bool complete(const Coverage &cov) {
    return cov.expected > 0 && cov.compared == cov.expected;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_devicefingerprinting_IntegrityProbeManager_nativeCodeIntegrity(
        JNIEnv *env, jobject /* this */) {
    Coverage core, ext, app;
    Counters counters;
    char names[512] = {0};
    unsigned char *buf = (unsigned char *) malloc(kChunk);
    if (!buf) return nullptr;
    compare_bucket(kCore, &core, &counters, buf, names, sizeof(names));
    compare_bucket(kExt, &ext, &counters, buf, names, sizeof(names));
    compare_bucket(kApp, &app, &counters, buf, names, sizeof(names));
    free(buf);

    bool checked = (core.found + ext.found + app.found) > 0;
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"checked\":%s,"
             "\"diff_bytes\":%ld,"                 // core diff
             "\"core_compared_bytes\":%ld,\"core_diff_bytes\":%ld,"
             "\"core_expected_bytes\":%ld,\"core_skipped_bytes\":%ld,"
             "\"core_unreadable_bytes\":%ld,\"core_complete\":%s,"
             "\"ext_compared_bytes\":%ld,\"ext_diff_bytes\":%ld,\"ext_libs_diff\":%d,"
             "\"ext_expected_bytes\":%ld,\"ext_skipped_bytes\":%ld,"
             "\"ext_unreadable_bytes\":%ld,\"ext_complete\":%s,"
             "\"app_compared_bytes\":%ld,\"app_diff_bytes\":%ld,\"app_libs_diff\":%d,"
             "\"app_expected_bytes\":%ld,\"app_skipped_bytes\":%ld,"
             "\"app_unreadable_bytes\":%ld,\"app_complete\":%s,"
             "\"xom_regions_unlocked\":%d,\"xom_regions_unreadable\":%d,"
             "\"protect_restore_failures\":%d,"
             "\"diffed_libs\":\"%s\"}",
             checked ? "true" : "false",
             core.diff,
             core.compared, core.diff,
             core.expected, core.skipped, core.unreadable, complete(core) ? "true" : "false",
             ext.compared, ext.diff, ext.withDiff,
             ext.expected, ext.skipped, ext.unreadable, complete(ext) ? "true" : "false",
             app.compared, app.diff, app.withDiff,
             app.expected, app.skipped, app.unreadable, complete(app) ? "true" : "false",
             counters.xomUnlocked, counters.xomUnreadable,
             counters.restoreFailures,
             names);

    return env->NewStringUTF(json);
}
