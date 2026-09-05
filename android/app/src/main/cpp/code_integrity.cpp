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

namespace {

constexpr size_t kMaxPerLib = 4u << 20;  // 4 MiB budget per library

const char *kCore[] = {"/libc.so", "/libart.so", nullptr};
const char *kExt[] = {
    "/libc++.so", "/libssl.so", "/libcrypto.so",
    "/libandroid_runtime.so", "/libbinder.so", nullptr,
};
const char *kApp[] = {"/libflutter.so", "/libapp.so", nullptr};

// Compare every executable mapping ending with `suffix` against disk.
// Returns differing bytes (>=0) and sets *compared, or -1 if none matched.
long compare_one(const char *suffix, long *compared) {
    *compared = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return -1;
    size_t suffix_len = strlen(suffix);
    long diff = 0;
    size_t done = 0;
    bool any = false;
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        if (done >= kMaxPerLib) break;
        unsigned long start = 0, end = 0, offset = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int matched = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %*d %511[^\n]",
                             &start, &end, perms, &offset, path);
        if (matched < 5 || perms[2] != 'x') continue;
        char *p = path;
        while (*p == ' ') p++;
        size_t len = strlen(p);
        if (len < suffix_len || strcmp(p + len - suffix_len, suffix) != 0) continue;
        size_t span = end - start;
        if (span == 0) continue;
        if (span > kMaxPerLib - done) span = kMaxPerLib - done;
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        unsigned char *disk = (unsigned char *) malloc(span);
        if (!disk) { close(fd); continue; }
        ssize_t got = pread(fd, disk, span, (off_t) offset);
        close(fd);
        if (got <= 0) { free(disk); continue; }
        const unsigned char *mem = (const unsigned char *) start;
        for (ssize_t i = 0; i < got; i++) if (mem[i] != disk[i]) diff++;
        free(disk);
        done += (size_t) got;
        any = true;
    }
    fclose(maps);
    if (!any) return -1;
    *compared = (long) done;
    return diff;
}

// Sum a bucket; append the name of any library that differs to `names`.
void compare_bucket(const char **suffixes, long *compared, long *diff,
                    int *checked, int *withDiff, char *names, size_t names_cap) {
    *compared = 0; *diff = 0; *checked = 0; *withDiff = 0;
    for (int i = 0; suffixes[i] != nullptr; i++) {
        long c = 0;
        long d = compare_one(suffixes[i], &c);
        if (d < 0) continue;  // library not mapped; skip
        (*checked)++;
        *compared += c;
        *diff += d;
        if (d > 0) {
            (*withDiff)++;
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

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_devicefingerprinting_IntegrityProbeManager_nativeCodeIntegrity(
        JNIEnv *env, jobject /* this */) {
    long coreC, coreD, extC, extD, appC, appD;
    int coreN, coreW, extN, extW, appN, appW;
    char names[512] = {0};

    compare_bucket(kCore, &coreC, &coreD, &coreN, &coreW, names, sizeof(names));
    compare_bucket(kExt, &extC, &extD, &extN, &extW, names, sizeof(names));
    compare_bucket(kApp, &appC, &appD, &appN, &appW, names, sizeof(names));

    bool checked = (coreN + extN + appN) > 0;
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"checked\":%s,"
             "\"diff_bytes\":%ld,"                 // core diff, scored today
             "\"core_compared_bytes\":%ld,\"core_diff_bytes\":%ld,"
             "\"ext_compared_bytes\":%ld,\"ext_diff_bytes\":%ld,\"ext_libs_diff\":%d,"
             "\"app_compared_bytes\":%ld,\"app_diff_bytes\":%ld,\"app_libs_diff\":%d,"
             "\"diffed_libs\":\"%s\"}",
             checked ? "true" : "false",
             coreD,
             coreC, coreD,
             extC, extD, extW,
             appC, appD, appW,
             names);

    return env->NewStringUTF(json);
}
