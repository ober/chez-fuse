/*
 * chez-fuse mount helper — tiny C shim for platform-specific mount/unmount.
 * Compiled as a shared library, loaded by Chez Scheme via load-shared-object.
 *
 * Exports:
 *   int chez_fuse_open_device(void)
 *   int chez_fuse_mount(int fd, const char *mountpoint, const char *fsname,
 *                       int uid, int gid, int allow_other)
 *   int chez_fuse_unmount(const char *mountpoint)
 *   int chez_fuse_unmount_lazy(const char *mountpoint)
 *   int chez_fuse_get_errno(void)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#if defined(FREEBSD)
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#elif defined(LINUX)
#include <sys/mount.h>
#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif
#elif defined(DARWIN)
/* macOS uses FUSE-T or macFUSE — needs separate handling */
#endif

/* Open /dev/fuse and return the file descriptor, or -1 on error.
 * Sets O_CLOEXEC so forked children don't inherit the fd. */
int chez_fuse_open_device(void) {
    int fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    return fd;
}

/* Return the current errno value (for Scheme to inspect after failures). */
int chez_fuse_get_errno(void) {
    return errno;
}

/* Block a signal. Returns 0 on success. */
int chez_fuse_block_signal(int signum) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return sigprocmask(SIG_BLOCK, &set, NULL);
}

/* Unblock a signal. Returns 0 on success. */
int chez_fuse_unblock_signal(int signum) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return sigprocmask(SIG_UNBLOCK, &set, NULL);
}

#if defined(FREEBSD)

/*
 * FreeBSD mount via nmount(2).
 * FreeBSD auto-unmounts when the /dev/fuse fd is closed.
 * Returns 0 on success, -1 on failure (check chez_fuse_get_errno).
 */
int chez_fuse_mount(int fd, const char *mountpoint, const char *fsname,
                    int uid, int gid, int allow_other) {
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", fd);

    /* Build iovec dynamically based on options */
    struct iovec iov[12];
    int niov = 0;

#define IOV_SET(key, val) do { \
    iov[niov].iov_base = (void*)(key); \
    iov[niov].iov_len = strlen(key) + 1; \
    niov++; \
    iov[niov].iov_base = (void*)(val); \
    iov[niov].iov_len = strlen(val) + 1; \
    niov++; \
} while(0)

    IOV_SET("fstype", "fusefs");
    IOV_SET("fspath", mountpoint);
    IOV_SET("from", fsname);
    IOV_SET("fd", fd_str);

    if (allow_other) {
        IOV_SET("allow_other", "");
    }

#undef IOV_SET

    return nmount(iov, niov, MNT_NOSUID);
}

int chez_fuse_unmount(const char *mountpoint) {
    return unmount(mountpoint, 0);
}

int chez_fuse_unmount_lazy(const char *mountpoint) {
    return unmount(mountpoint, MNT_FORCE);
}

#elif defined(LINUX)

/*
 * Linux mount via mount(2).
 * Returns 0 on success, -1 on failure.
 */
int chez_fuse_mount(int fd, const char *mountpoint, const char *fsname,
                    int uid, int gid, int allow_other) {
    char opts[512];
    if (allow_other) {
        snprintf(opts, sizeof(opts),
                 "fd=%d,rootmode=40755,user_id=%d,group_id=%d,allow_other",
                 fd, uid, gid);
    } else {
        snprintf(opts, sizeof(opts),
                 "fd=%d,rootmode=40755,user_id=%d,group_id=%d",
                 fd, uid, gid);
    }

    char fstype[128];
    snprintf(fstype, sizeof(fstype), "fuse.%s", fsname);

    int rc = mount(fsname, mountpoint, fstype, MS_NOSUID | MS_NODEV, opts);
    if (rc != 0 && errno == ENODEV) {
        /* Fallback to generic "fuse" type */
        rc = mount(fsname, mountpoint, "fuse", MS_NOSUID | MS_NODEV, opts);
    }
    return rc;
}

int chez_fuse_unmount(const char *mountpoint) {
    return umount2(mountpoint, 0);
}

int chez_fuse_unmount_lazy(const char *mountpoint) {
    return umount2(mountpoint, MNT_DETACH);
}

#elif defined(DARWIN)

int chez_fuse_mount(int fd, const char *mountpoint, const char *fsname,
                    int uid, int gid, int allow_other) {
    (void)fd; (void)mountpoint; (void)fsname; (void)uid; (void)gid;
    (void)allow_other;
    errno = ENOSYS;
    return -1;
}

int chez_fuse_unmount(const char *mountpoint) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "umount '%s' 2>/dev/null", mountpoint);
    return system(cmd);
}

int chez_fuse_unmount_lazy(const char *mountpoint) {
    return chez_fuse_unmount(mountpoint);
}

#else

int chez_fuse_mount(int fd, const char *mountpoint, const char *fsname,
                    int uid, int gid, int allow_other) {
    (void)fd; (void)mountpoint; (void)fsname; (void)uid; (void)gid;
    (void)allow_other;
    errno = ENOSYS;
    return -1;
}

int chez_fuse_unmount(const char *mountpoint) {
    (void)mountpoint;
    errno = ENOSYS;
    return -1;
}

int chez_fuse_unmount_lazy(const char *mountpoint) {
    (void)mountpoint;
    errno = ENOSYS;
    return -1;
}

#endif
