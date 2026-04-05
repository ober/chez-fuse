/*
 * chez-fuse mount helper — C shim for platform-specific operations.
 * Compiled as a shared library, loaded by Chez Scheme via load-shared-object.
 *
 * Exports:
 *   Mount/unmount:
 *     int chez_fuse_open_device(void)
 *     int chez_fuse_mount(int fd, const char *mountpoint, const char *fsname,
 *                         int uid, int gid, int allow_other)
 *     int chez_fuse_unmount(const char *mountpoint)
 *     int chez_fuse_unmount_lazy(const char *mountpoint)
 *     int chez_fuse_get_errno(void)
 *
 *   Secure memory (mlock'd, excluded from core dumps):
 *     void *chez_fuse_secmem_alloc(size_t size)
 *     void  chez_fuse_secmem_free(void *ptr, size_t size)
 *     void  chez_fuse_secmem_copy_in(void *dst, const uint8_t *src, size_t len)
 *     void  chez_fuse_secmem_copy_out(uint8_t *dst, const void *src, size_t len)
 *     void  chez_fuse_secmem_zero(void *ptr, size_t size)
 *
 *   Process tree inspection:
 *     int   chez_fuse_getpid(void)
 *     int   chez_fuse_getppid_of(int pid)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

#if defined(FREEBSD)
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#elif defined(LINUX)
#include <sys/mount.h>
#include <sys/prctl.h>
#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif
#elif defined(DARWIN)
#include <libproc.h>
#include <sys/proc_info.h>
#endif

/* ====================================================================
 * Secure memory — mlock'd, core-dump excluded, volatile-zeroed on free
 * ==================================================================== */

void *chez_fuse_secmem_alloc(size_t size) {
    /* Use mmap for page-aligned allocation we fully control */
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;

    /* Lock into RAM — prevent swapping */
    mlock(p, size);  /* best-effort; may fail without RLIMIT_MEMLOCK */

    /* Exclude from core dumps */
#if defined(FREEBSD)
    madvise(p, size, MADV_NOCORE);
#elif defined(LINUX)
    madvise(p, size, MADV_DONTDUMP);
#endif

    memset(p, 0, size);
    return p;
}

void chez_fuse_secmem_free(void *ptr, size_t size) {
    if (!ptr) return;
    /* Volatile-safe zeroing — compiler cannot optimize this away */
    volatile unsigned char *vp = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < size; i++) vp[i] = 0;
    munlock(ptr, size);
    munmap(ptr, size);
}

void chez_fuse_secmem_zero(void *ptr, size_t size) {
    if (!ptr) return;
    volatile unsigned char *vp = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < size; i++) vp[i] = 0;
}

void chez_fuse_secmem_copy_in(void *dst, const unsigned char *src, size_t len) {
    memcpy(dst, src, len);
}

void chez_fuse_secmem_copy_out(unsigned char *dst, const void *src, size_t len) {
    memcpy(dst, src, len);
}

/* ====================================================================
 * Process tree inspection
 * ==================================================================== */

int chez_fuse_getpid(void) {
    return (int)getpid();
}

#if defined(FREEBSD)

/* Get parent PID of any process via sysctl. Returns -1 on error. */
int chez_fuse_getppid_of(int pid) {
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &kp, &len, NULL, 0) < 0) return -1;
    if (len == 0) return -1;  /* process doesn't exist */
    return (int)kp.ki_ppid;
}

#elif defined(LINUX)

/* Get parent PID by reading /proc/<pid>/stat. Returns -1 on error. */
int chez_fuse_getppid_of(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    /* Format: pid (comm) state ppid ... */
    /* comm can contain spaces and parens, so find last ')' first */
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return -1;
    buf[n] = '\0';
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    int ppid = -1;
    /* After ')' comes: space, state char, space, ppid */
    if (sscanf(p + 2, "%*c %d", &ppid) != 1) return -1;
    return ppid;
}

#elif defined(DARWIN)

int chez_fuse_getppid_of(int pid) {
    struct proc_bsdinfo info;
    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (ret <= 0) return -1;
    return (int)info.pbi_ppid;
}

#else

int chez_fuse_getppid_of(int pid) {
    (void)pid;
    return -1;
}

#endif

/* ====================================================================
 * FUSE device and errno
 * ==================================================================== */

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

/* ====================================================================
 * Platform-specific mount/unmount
 * ==================================================================== */

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
    struct iovec iov[14];
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
    /* FreeBSD fusefs requires "from" to be the /dev/fuse device path.
     * The user-visible label (fsname) is passed as "subtype". */
    IOV_SET("from", "/dev/fuse");
    IOV_SET("subtype", fsname);
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
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Child: exec umount directly — no shell, no injection */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execl("/sbin/umount", "umount", mountpoint, (char *)NULL);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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
