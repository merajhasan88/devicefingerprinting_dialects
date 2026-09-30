// Host regression test for the native code-integrity scanner (DESIGN.md 63).
//
// Adapted from the 2026-09-29 review's reproduction, which asserted the two
// defects; these assertions are inverted. It includes the unchanged scanner
// source and runs its real mapping-selection and comparison loops against
// file-backed executable mappings on a Linux host. It is not an Android run:
// ARM and handset behaviour still need the device battery.
//
//   clang++ -std=c++17 -O1 -Wall -Wextra -Itools/native \
//       -Iandroid/app/src/main/cpp tools/native/check_code_integrity.cpp \
//       -o /tmp/check_code_integrity && (cd /tmp && ./check_code_integrity)
//
// Run it from a writable scratch directory: it creates and removes small
// fixture files there.
#include "code_integrity.cpp"
#include <assert.h>
#include <string>

static int failures = 0;

static void expect(bool ok, const char *what) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) failures++;
}

static std::string permissions(void *p) {
    FILE *maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[1024], perms[8];
    unsigned long start, end;
    std::string result;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3
            && (unsigned long) p >= start && (unsigned long) p < end) {
            result = perms;
            break;
        }
    }
    fclose(maps);
    return result.substr(0, 3);
}

static void *map_file(const char *path, size_t size, int prot, int *fd_out) {
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0 && ftruncate(fd, (off_t) size) == 0);
    void *m = mmap(nullptr, size, prot, MAP_PRIVATE, fd, 0);
    assert(m != MAP_FAILED);
    *fd_out = fd;
    return m;
}

static Coverage scan(const char *suffix, Counters *counters) {
    Coverage cov;
    unsigned char *buf = (unsigned char *) malloc(kChunk);
    compare_one(suffix, &cov, counters, buf);
    free(buf);
    return cov;
}

int main() {
    setbuf(stdout, nullptr);
    const size_t page = (size_t) sysconf(_SC_PAGESIZE);

    // F5: a non-target execute-only mapping must never be touched.
    int xfd;
    void *xom = map_file("regression-nontarget.xom", page, PROT_EXEC, &xfd);
    expect(permissions(xom) == "--x", "fixture: non-target mapping starts --x");
    Counters c1;
    Coverage none = scan("/no-such-library.so", &c1);
    expect(permissions(xom) == "--x", "non-target execute-only mapping keeps --x");
    expect(none.expected == 0 && c1.xomUnlocked == 0 && c1.xomUnreadable == 0,
           "non-target mapping is neither counted nor unlocked");
    munmap(xom, page);
    close(xfd);
    unlink("regression-nontarget.xom");

    // F5: a target execute-only mapping is read, then restored exactly.
    int tfd;
    void *target = map_file("regression-xom.apk", 4 * page, PROT_EXEC, &tfd);
    Counters c2;
    Coverage xcov = scan(".apk", &c2);
    expect(permissions(target) == "--x", "target execute-only mapping restored to --x");
    expect(c2.xomUnlocked == 1 && c2.restoreFailures == 0, "one unlock, restored without failure");
    expect(xcov.compared == (long) (4 * page) && xcov.diff == 0 && complete(xcov),
           "execute-only target compared in full and clean");

    // F5: a short read (file truncated under the mapping) leaves the
    // protection restored and the missing bytes reported as unreadable.
    assert(ftruncate(tfd, (off_t) page) == 0);
    Counters c3;
    Coverage scov = scan(".apk", &c3);
    expect(permissions(target) == "--x", "short-read path restores --x");
    expect(scov.compared == (long) page && scov.unreadable == (long) (3 * page)
           && !complete(scov), "short read reported as unreadable, bucket incomplete");
    munmap(target, 4 * page);
    close(tfd);
    unlink("regression-xom.apk");

    // F4: a modification far into a large mapping is measured, not skipped.
    const size_t size = 6u << 20;
    int lfd;
    unsigned char *large = (unsigned char *) map_file("regression-coverage.apk", size,
                                                      PROT_READ | PROT_WRITE, &lfd);
    memset(large + (5u << 20), 0x7f, 4);
    assert(mprotect(large, size, PROT_READ | PROT_EXEC) == 0);
    Counters c4;
    Coverage late = scan(".apk", &c4);
    printf("     late modification: expected=%ld compared=%ld diff=%ld\n",
           late.expected, late.compared, late.diff);
    expect(late.compared == (long) size && late.diff == 4 && complete(late),
           "4 bytes changed at 5 MiB of a 6 MiB mapping are detected");

    // Control from the review: an early change is detected too, and the two add.
    assert(mprotect(large, size, PROT_READ | PROT_WRITE) == 0);
    large[page] = (unsigned char) (large[page] ^ 0xff);
    assert(mprotect(large, size, PROT_READ | PROT_EXEC) == 0);
    Counters c5;
    Coverage both = scan(".apk", &c5);
    expect(both.diff == 5, "one more changed byte early in the mapping is counted (5 total)");
    expect(permissions(large) == "r-x", "a readable target keeps r-x");

    // The JNI entry point reports coverage per bucket.
    JNIEnv env;
    const char *json = Java_com_example_devicefingerprinting_IntegrityProbeManager_nativeCodeIntegrity(&env, nullptr);
    expect(json && strstr(json, "\"app_complete\":true") && strstr(json, "\"app_expected_bytes\":6291456")
           && strstr(json, "\"protect_restore_failures\":0"),
           "JSON carries app coverage (expected, complete) and restore failures");
    if (json) printf("     %s\n", json);
    munmap(large, size);
    close(lfd);
    unlink("regression-coverage.apk");

    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "OK", failures);
    return failures ? 1 : 0;
}
