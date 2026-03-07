#!/bin/bash
# End-to-end test using libnfs C client.
# Requires libnfs-dev installed and the NFS server binary built.
set -e

SERVER_BIN="${1:-../../target/release/nfs4-serve}"
PORT=2049

# Build test program
cat > /tmp/nfs_e2e_test.c << 'EOF'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfsc/libnfs.h>

#define CHECK(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: " msg "\n", ##__VA_ARGS__); \
        exit(1); \
    } \
} while(0)

int main(void) {
    struct nfs_context *nfs;
    struct nfsdir *nfsdir;
    struct nfsdirent *nfsdirent;
    struct nfsfh *nfsfh;
    int ret, count;

    nfs = nfs_init_context();
    nfs_set_version(nfs, 4);

    ret = nfs_mount(nfs, "127.0.0.1", "/");
    CHECK(ret == 0, "mount: %s", nfs_get_error(nfs));
    printf("PASS: mount\n");

    // 1. Create file
    ret = nfs_creat(nfs, "/test1.txt", 0644, &nfsfh);
    CHECK(ret == 0, "creat: %s", nfs_get_error(nfs));
    printf("PASS: creat\n");

    // 2. Write data
    const char *data = "Hello, NFSv4 World! Testing 1 2 3.";
    ret = nfs_write(nfs, nfsfh, strlen(data), (char *)data);
    CHECK(ret == (int)strlen(data), "write: got %d, want %d", ret, (int)strlen(data));
    nfs_close(nfs, nfsfh);
    printf("PASS: write %d bytes\n", ret);

    // 3. Read back
    ret = nfs_open(nfs, "/test1.txt", O_RDONLY, &nfsfh);
    CHECK(ret == 0, "open(read): %s", nfs_get_error(nfs));
    char buf[256] = {0};
    ret = nfs_read(nfs, nfsfh, 256, buf);
    CHECK(ret == (int)strlen(data), "read: got %d bytes", ret);
    CHECK(memcmp(buf, data, ret) == 0, "read data mismatch");
    nfs_close(nfs, nfsfh);
    printf("PASS: read %d bytes verified\n", ret);

    // 4. Stat file
    struct nfs_stat_64 st;
    ret = nfs_stat64(nfs, "/test1.txt", &st);
    CHECK(ret == 0, "stat: %s", nfs_get_error(nfs));
    CHECK(st.nfs_size == (int)strlen(data), "stat size: got %lld want %d", (long long)st.nfs_size, (int)strlen(data));
    printf("PASS: stat size=%lld\n", (long long)st.nfs_size);

    // 5. mkdir
    ret = nfs_mkdir(nfs, "/mydir");
    CHECK(ret == 0, "mkdir: %s", nfs_get_error(nfs));
    printf("PASS: mkdir\n");

    // 6. Create file in subdirectory
    ret = nfs_creat(nfs, "/mydir/nested.txt", 0644, &nfsfh);
    CHECK(ret == 0, "creat nested: %s", nfs_get_error(nfs));
    nfs_write(nfs, nfsfh, 5, "inner");
    nfs_close(nfs, nfsfh);
    printf("PASS: create nested file\n");

    // 7. Read directory
    ret = nfs_opendir(nfs, "/", &nfsdir);
    CHECK(ret == 0, "opendir: %s", nfs_get_error(nfs));
    count = 0;
    while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
        if (strcmp(nfsdirent->name, ".") != 0 && strcmp(nfsdirent->name, "..") != 0) {
            count++;
        }
    }
    nfs_closedir(nfs, nfsdir);
    CHECK(count == 2, "readdir: expected 2 entries, got %d", count);
    printf("PASS: readdir found %d entries\n", count);

    // 8. Read subdirectory
    ret = nfs_opendir(nfs, "/mydir", &nfsdir);
    CHECK(ret == 0, "opendir mydir: %s", nfs_get_error(nfs));
    count = 0;
    while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
        if (strcmp(nfsdirent->name, ".") != 0 && strcmp(nfsdirent->name, "..") != 0) {
            count++;
        }
    }
    nfs_closedir(nfs, nfsdir);
    CHECK(count == 1, "readdir mydir: expected 1, got %d", count);
    printf("PASS: readdir subdir\n");

    // 9. Rename
    ret = nfs_rename(nfs, "/test1.txt", "/renamed.txt");
    CHECK(ret == 0, "rename: %s", nfs_get_error(nfs));
    // Verify old name gone
    ret = nfs_stat64(nfs, "/test1.txt", &st);
    CHECK(ret != 0, "rename: old name still exists");
    ret = nfs_stat64(nfs, "/renamed.txt", &st);
    CHECK(ret == 0, "rename: new name missing: %s", nfs_get_error(nfs));
    printf("PASS: rename\n");

    // 10. Unlink
    ret = nfs_unlink(nfs, "/renamed.txt");
    CHECK(ret == 0, "unlink: %s", nfs_get_error(nfs));
    printf("PASS: unlink\n");

    // 11. Unlink nested
    ret = nfs_unlink(nfs, "/mydir/nested.txt");
    CHECK(ret == 0, "unlink nested: %s", nfs_get_error(nfs));

    // 12. Rmdir
    ret = nfs_rmdir(nfs, "/mydir");
    CHECK(ret == 0, "rmdir: %s", nfs_get_error(nfs));
    printf("PASS: rmdir\n");

    // 13. Verify empty root
    ret = nfs_opendir(nfs, "/", &nfsdir);
    CHECK(ret == 0, "final opendir: %s", nfs_get_error(nfs));
    count = 0;
    while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
        if (strcmp(nfsdirent->name, ".") != 0 && strcmp(nfsdirent->name, "..") != 0) {
            count++;
        }
    }
    nfs_closedir(nfs, nfsdir);
    CHECK(count == 0, "final: expected 0 entries, got %d", count);
    printf("PASS: empty root\n");

    nfs_umount(nfs);
    nfs_destroy_context(nfs);
    printf("\nAll %d tests passed!\n", 13);
    return 0;
}
EOF

gcc -o /tmp/nfs_e2e_test /tmp/nfs_e2e_test.c -lnfs || exit 1

# Start server
"$SERVER_BIN" &
SERVER_PID=$!
sleep 1

# Run test
/tmp/nfs_e2e_test
EXIT=$?

kill $SERVER_PID 2>/dev/null
exit $EXIT
