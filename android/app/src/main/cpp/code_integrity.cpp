// Native code-integrity probe.
//
// Runs IN the app's own process, so it reads the app's own mapped executable
// pages by direct pointer. That is the whole reason this lives in native code:
// the Kotlin attempt opened /proc/self/mem, which SELinux denies to
// untrusted_app on Android 9/10. A process reading its own already-mapped,
// readable pages needs no such access and no ptrace.
//
// For each target library it compares EVERY executable mapping against the
// same bytes on disk. Iterating every VMA (not just the first) is essential:
// an inline hooker flips individual code pages writable to patch them, which
// splits the library's single r-x mapping into several, and the patched page
// is often not the first. The executable segment is otherwise not modified at
// runtime by the dynamic linker (relocations land in the GOT/data segments),
// so on a clean device memory and disk are byte-identical. A hook overwrites a
// function prologue, which shows up here as a difference regardless of what the
// hooking framework is called.

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

namespace {

// Per-library budget: enough to cover libc/libart .text across split VMAs
// without making the scan slow.
constexpr size_t kMaxPerLib = 4u << 20;

// Compare every executable mapping whose path ends with `suffix` against disk.
// Returns total differing bytes, or a negative status if nothing was compared:
//   -2 no matching executable mapping found, -1 maps unreadable.
// Sets *compared to the total bytes compared.
long compare_library(const char *suffix, long *compared) {
    *compared = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return -1;

    size_t suffix_len = strlen(suffix);
    long total_diff = 0;
    size_t total_compared = 0;
    bool any = false;
    char line[1024];

    while (fgets(line, sizeof(line), maps)) {
        if (total_compared >= kMaxPerLib) break;
        unsigned long start = 0, end = 0, offset = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int matched = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %*d %511[^\n]",
                             &start, &end, perms, &offset, path);
        if (matched < 5) continue;
        if (perms[2] != 'x') continue;  // executable pages only
        char *p = path;
        while (*p == ' ') p++;
        size_t len = strlen(p);
        if (len < suffix_len) continue;
        if (strcmp(p + len - suffix_len, suffix) != 0) continue;

        size_t span = end - start;
        if (span == 0) continue;
        if (span > kMaxPerLib - total_compared) span = kMaxPerLib - total_compared;

        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        unsigned char *disk = (unsigned char *) malloc(span);
        if (!disk) { close(fd); continue; }
        ssize_t got = pread(fd, disk, span, (off_t) offset);
        close(fd);
        if (got <= 0) { free(disk); continue; }
        size_t n = (size_t) got;

        const unsigned char *mem = (const unsigned char *) start;
        for (size_t i = 0; i < n; i++) {
            if (mem[i] != disk[i]) total_diff++;
        }
        free(disk);
        total_compared += n;
        any = true;
    }
    fclose(maps);
    if (!any) return -2;
    *compared = (long) total_compared;
    return total_diff;
}

}  // namespace

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_example_devicefingerprinting_IntegrityProbeManager_nativeCodeIntegrity(
        JNIEnv *env, jobject /* this */) {
    // Layout: [status, libcCompared, libcDiff, libartCompared, libartDiff]
    // status: 0 ok, negative = the libc error code.
    jlong values[5] = {0, 0, 0, 0, 0};

    long compared = 0;
    long libc = compare_library("/libc.so", &compared);
    if (libc < 0) {
        values[0] = (jlong) libc;
    } else {
        values[1] = (jlong) compared;
        values[2] = (jlong) libc;
    }

    long compared2 = 0;
    long libart = compare_library("/libart.so", &compared2);
    if (libart >= 0) {
        values[3] = (jlong) compared2;
        values[4] = (jlong) libart;
    }

    jlongArray out = env->NewLongArray(5);
    if (out != nullptr) env->SetLongArrayRegion(out, 0, 5, values);
    return out;
}
