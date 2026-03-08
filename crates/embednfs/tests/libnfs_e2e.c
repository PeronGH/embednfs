/*
 * End-to-end NFS test using libnfs.
 *
 * Usage: ./embednfs_e2e_test <port> <test_name>
 *
 * test_name is one of: mount, create_write_read, stat, mkdir_readdir,
 *                       rename, unlink_rmdir, full
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw-nfs4.h>

#define CHECK(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: " msg "\n", ##__VA_ARGS__); \
        exit(1); \
    } \
} while(0)

static struct nfs_context *do_mount(const char *port) {
    struct nfs_context *nfs = nfs_init_context();
    CHECK(nfs != NULL, "nfs_init_context");

    /*
     * Use nfs_parse_url_incomplete to configure the NFS port via URL args.
     * This sets the internal nfsport so we don't need the portmapper.
     */
    char url[256];
    snprintf(url, sizeof(url), "nfs://127.0.0.1/?nfsport=%s&version=4", port);
    struct nfs_url *parsed = nfs_parse_url_incomplete(nfs, url);
    CHECK(parsed != NULL, "parse URL: %s", nfs_get_error(nfs));
    nfs_destroy_url(parsed);

    int ret = nfs_mount(nfs, "127.0.0.1", "/");
    CHECK(ret == 0, "mount failed (port %s): %s", port, nfs_get_error(nfs));
    printf("PASS: mount (port %s)\n", port);
    return nfs;
}

static void test_mount(const char *port) {
    struct nfs_context *nfs = do_mount(port);
    nfs_umount(nfs);
    nfs_destroy_context(nfs);
}

static void test_create_write_read(const char *port) {
    struct nfs_context *nfs = do_mount(port);
    struct nfsfh *nfsfh;
    int ret;

    /* Create and open file for read+write */
    ret = nfs_open(nfs, "/test1.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "open(create): %s", nfs_get_error(nfs));
    printf("PASS: create\n");

    /* Write data */
    const char *data = "Hello, NFSv4 World! Testing 1 2 3.";
    ret = nfs_write(nfs, nfsfh, strlen(data), (char *)data);
    CHECK(ret == (int)strlen(data), "write: got %d, want %d: %s",
          ret, (int)strlen(data), nfs_get_error(nfs));
    nfs_close(nfs, nfsfh);
    printf("PASS: write %d bytes\n", ret);

    /* Read back */
    ret = nfs_open(nfs, "/test1.txt", O_RDONLY, &nfsfh);
    CHECK(ret == 0, "open(read): %s", nfs_get_error(nfs));
    char buf[256] = {0};
    ret = nfs_read(nfs, nfsfh, 256, buf);
    CHECK(ret == (int)strlen(data), "read: got %d bytes, want %d: %s",
          ret, (int)strlen(data), nfs_get_error(nfs));
    CHECK(memcmp(buf, data, ret) == 0, "read data mismatch");
    nfs_close(nfs, nfsfh);
    printf("PASS: read %d bytes verified\n", ret);

    /* Cleanup */
    nfs_unlink(nfs, "/test1.txt");
    nfs_umount(nfs);
    nfs_destroy_context(nfs);
}

static void test_stat(const char *port) {
    struct nfs_context *nfs = do_mount(port);
    struct nfsfh *nfsfh;
    int ret;

    /* Create and write a file */
    ret = nfs_open(nfs, "/stattest.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "creat: %s", nfs_get_error(nfs));
    const char *data = "stat test data";
    nfs_write(nfs, nfsfh, strlen(data), (char *)data);
    nfs_close(nfs, nfsfh);

    /* Stat it */
    struct nfs_stat_64 st;
    ret = nfs_stat64(nfs, "/stattest.txt", &st);
    CHECK(ret == 0, "stat: %s", nfs_get_error(nfs));
    CHECK(st.nfs_size == (uint64_t)strlen(data),
          "stat size: got %lld want %d",
          (long long)st.nfs_size, (int)strlen(data));
    printf("PASS: stat size=%lld\n", (long long)st.nfs_size);

    /* Cleanup */
    nfs_unlink(nfs, "/stattest.txt");
    nfs_umount(nfs);
    nfs_destroy_context(nfs);
}

static void test_mkdir_readdir(const char *port) {
    struct nfs_context *nfs = do_mount(port);
    struct nfsfh *nfsfh;
    struct nfsdir *nfsdir;
    struct nfsdirent *nfsdirent;
    int ret, count;

    /* Create a directory */
    ret = nfs_mkdir(nfs, "/mydir");
    CHECK(ret == 0, "mkdir: %s", nfs_get_error(nfs));
    printf("PASS: mkdir\n");

    /* Create a file in root and one in subdir */
    ret = nfs_open(nfs, "/rootfile.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "creat rootfile: %s", nfs_get_error(nfs));
    nfs_close(nfs, nfsfh);

    ret = nfs_open(nfs, "/mydir/nested.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "creat nested: %s", nfs_get_error(nfs));
    nfs_write(nfs, nfsfh, 5, "inner");
    nfs_close(nfs, nfsfh);
    printf("PASS: create nested file\n");

    /* Read root directory */
    ret = nfs_opendir(nfs, "/", &nfsdir);
    CHECK(ret == 0, "opendir /: %s", nfs_get_error(nfs));
    count = 0;
    while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
        if (strcmp(nfsdirent->name, ".") != 0 &&
            strcmp(nfsdirent->name, "..") != 0) {
            count++;
        }
    }
    nfs_closedir(nfs, nfsdir);
    CHECK(count == 2, "readdir /: expected 2 entries, got %d", count);
    printf("PASS: readdir / found %d entries\n", count);

    /* Read subdirectory */
    ret = nfs_opendir(nfs, "/mydir", &nfsdir);
    CHECK(ret == 0, "opendir /mydir: %s", nfs_get_error(nfs));
    count = 0;
    while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
        if (strcmp(nfsdirent->name, ".") != 0 &&
            strcmp(nfsdirent->name, "..") != 0) {
            count++;
        }
    }
    nfs_closedir(nfs, nfsdir);
    CHECK(count == 1, "readdir /mydir: expected 1, got %d", count);
    printf("PASS: readdir /mydir\n");

    /* Cleanup */
    nfs_unlink(nfs, "/mydir/nested.txt");
    nfs_unlink(nfs, "/rootfile.txt");
    nfs_rmdir(nfs, "/mydir");
    nfs_umount(nfs);
    nfs_destroy_context(nfs);
}

static void test_rename(const char *port) {
    struct nfs_context *nfs = do_mount(port);
    struct nfsfh *nfsfh;
    struct nfs_stat_64 st;
    int ret;

    /* Create a file */
    ret = nfs_open(nfs, "/before.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "creat: %s", nfs_get_error(nfs));
    nfs_write(nfs, nfsfh, 4, "data");
    nfs_close(nfs, nfsfh);

    /* Rename it */
    ret = nfs_rename(nfs, "/before.txt", "/after.txt");
    CHECK(ret == 0, "rename: %s", nfs_get_error(nfs));

    /* Old name should be gone */
    ret = nfs_stat64(nfs, "/before.txt", &st);
    CHECK(ret != 0, "rename: old name still exists");

    /* New name should exist */
    ret = nfs_stat64(nfs, "/after.txt", &st);
    CHECK(ret == 0, "rename: new name missing: %s", nfs_get_error(nfs));
    printf("PASS: rename\n");

    /* Cleanup */
    nfs_unlink(nfs, "/after.txt");
    nfs_umount(nfs);
    nfs_destroy_context(nfs);
}

static void test_unlink_rmdir(const char *port) {
    struct nfs_context *nfs = do_mount(port);
    struct nfsfh *nfsfh;
    struct nfsdir *nfsdir;
    struct nfsdirent *nfsdirent;
    int ret, count;

    /* Create a dir with a file */
    nfs_mkdir(nfs, "/tmpdir");
    ret = nfs_open(nfs, "/tmpdir/file.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "creat: %s", nfs_get_error(nfs));
    nfs_close(nfs, nfsfh);

    /* Also a root file */
    ret = nfs_open(nfs, "/tmp.txt", O_RDWR | O_CREAT, &nfsfh);
    CHECK(ret == 0, "creat root: %s", nfs_get_error(nfs));
    nfs_close(nfs, nfsfh);

    /* Unlink files */
    ret = nfs_unlink(nfs, "/tmpdir/file.txt");
    CHECK(ret == 0, "unlink nested: %s", nfs_get_error(nfs));

    ret = nfs_unlink(nfs, "/tmp.txt");
    CHECK(ret == 0, "unlink root: %s", nfs_get_error(nfs));
    printf("PASS: unlink\n");

    /* Rmdir */
    ret = nfs_rmdir(nfs, "/tmpdir");
    CHECK(ret == 0, "rmdir: %s", nfs_get_error(nfs));
    printf("PASS: rmdir\n");

    /* Verify empty root */
    ret = nfs_opendir(nfs, "/", &nfsdir);
    CHECK(ret == 0, "final opendir: %s", nfs_get_error(nfs));
    count = 0;
    while ((nfsdirent = nfs_readdir(nfs, nfsdir)) != NULL) {
        if (strcmp(nfsdirent->name, ".") != 0 &&
            strcmp(nfsdirent->name, "..") != 0) {
            count++;
        }
    }
    nfs_closedir(nfs, nfsdir);
    CHECK(count == 0, "final: expected 0 entries, got %d", count);
    printf("PASS: empty root verified\n");

    nfs_umount(nfs);
    nfs_destroy_context(nfs);
}

static void test_full(const char *port) {
    test_create_write_read(port);
    test_stat(port);
    test_mkdir_readdir(port);
    test_rename(port);
    test_unlink_rmdir(port);
    printf("\nAll tests passed!\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <test_name>\n", argv[0]);
        return 1;
    }

    const char *port = argv[1];
    const char *test = argv[2];

    if (strcmp(test, "mount") == 0) test_mount(port);
    else if (strcmp(test, "create_write_read") == 0) test_create_write_read(port);
    else if (strcmp(test, "stat") == 0) test_stat(port);
    else if (strcmp(test, "mkdir_readdir") == 0) test_mkdir_readdir(port);
    else if (strcmp(test, "rename") == 0) test_rename(port);
    else if (strcmp(test, "unlink_rmdir") == 0) test_unlink_rmdir(port);
    else if (strcmp(test, "full") == 0) test_full(port);
    else {
        fprintf(stderr, "Unknown test: %s\n", test);
        return 1;
    }

    return 0;
}
