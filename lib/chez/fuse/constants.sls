(library (chez fuse constants)
  (export
    ;; Protocol version
    FUSE-KERNEL-VERSION FUSE-KERNEL-MINOR-VERSION
    FUSE-MIN-READ-BUFFER FUSE-MAX-BUFFER-SIZE
    FUSE-ROOT-ID

    ;; Header sizes
    FUSE-IN-HEADER-SIZE FUSE-OUT-HEADER-SIZE

    ;; Opcodes
    FUSE-LOOKUP FUSE-FORGET FUSE-GETATTR FUSE-SETATTR
    FUSE-READLINK FUSE-SYMLINK FUSE-MKNOD FUSE-MKDIR
    FUSE-UNLINK FUSE-RMDIR FUSE-RENAME FUSE-LINK
    FUSE-OPEN FUSE-READ FUSE-WRITE FUSE-STATFS
    FUSE-RELEASE FUSE-FSYNC FUSE-SETXATTR FUSE-GETXATTR
    FUSE-LISTXATTR FUSE-REMOVEXATTR FUSE-FLUSH FUSE-INIT
    FUSE-OPENDIR FUSE-READDIR FUSE-RELEASEDIR FUSE-FSYNCDIR
    FUSE-GETLK FUSE-SETLK FUSE-SETLKW FUSE-ACCESS
    FUSE-CREATE FUSE-INTERRUPT FUSE-BMAP FUSE-DESTROY
    FUSE-BATCH-FORGET FUSE-FALLOCATE FUSE-READDIRPLUS
    FUSE-RENAME2 FUSE-LSEEK FUSE-COPY-FILE-RANGE

    ;; INIT capability flags
    FUSE-ASYNC-READ FUSE-POSIX-LOCKS FUSE-FILE-OPS
    FUSE-ATOMIC-O-TRUNC FUSE-EXPORT-SUPPORT FUSE-BIG-WRITES
    FUSE-DONT-MASK FUSE-SPLICE-WRITE FUSE-SPLICE-MOVE
    FUSE-SPLICE-READ FUSE-FLOCK-LOCKS FUSE-HAS-IOCTL-DIR
    FUSE-AUTO-INVAL-DATA FUSE-DO-READDIRPLUS FUSE-READDIRPLUS-AUTO
    FUSE-ASYNC-DIO FUSE-WRITEBACK-CACHE FUSE-NO-OPEN-SUPPORT
    FUSE-PARALLEL-DIROPS FUSE-HANDLE-KILLPRIV FUSE-POSIX-ACL
    FUSE-ABORT-ERROR FUSE-MAX-PAGES FUSE-CACHE-SYMLINKS
    FUSE-NO-OPENDIR-SUPPORT FUSE-EXPLICIT-INVAL-DATA
    FUSE-INIT-EXT

    ;; FATTR flags (setattr valid mask)
    FATTR-MODE FATTR-UID FATTR-GID FATTR-SIZE
    FATTR-ATIME FATTR-MTIME FATTR-FH
    FATTR-ATIME-NOW FATTR-MTIME-NOW FATTR-CTIME

    ;; FOPEN flags
    FOPEN-DIRECT-IO FOPEN-KEEP-CACHE FOPEN-NONSEEKABLE
    FOPEN-CACHE-DIR FOPEN-STREAM

    ;; File type bits (for stat mode)
    S-IFMT S-IFIFO S-IFCHR S-IFDIR S-IFBLK S-IFREG S-IFLNK S-IFSOCK

    ;; Permission bits
    S-ISUID S-ISGID S-ISVTX
    S-IRWXU S-IRUSR S-IWUSR S-IXUSR
    S-IRWXG S-IRGRP S-IWGRP S-IXGRP
    S-IRWXO S-IROTH S-IWOTH S-IXOTH

    ;; Directory entry types (DT_*)
    DT-UNKNOWN DT-FIFO DT-CHR DT-DIR DT-BLK DT-REG DT-LNK DT-SOCK DT-WHT

    ;; Open flags
    O-RDONLY O-WRONLY O-RDWR O-CREAT O-EXCL O-TRUNC O-APPEND

    ;; Access flags
    F-OK R-OK W-OK X-OK

    ;; Errno values
    EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF ECHILD
    EAGAIN ENOMEM EACCES EFAULT EBUSY EEXIST EXDEV ENODEV ENOTDIR
    EISDIR EINVAL ENFILE EMFILE ENOTTY EFBIG ENOSPC ESPIPE EROFS
    EMLINK EPIPE EDOM ERANGE ENOSYS ENOTEMPTY ENAMETOOLONG ELOOP
    ENODATA ENOTCONN EOVERFLOW EOPNOTSUPP ENOTSUP

    ;; Helpers
    fuse-rec-align)

  (import (rnrs))

  ;; ---- Protocol version ----
  (define FUSE-KERNEL-VERSION 7)
  (define FUSE-KERNEL-MINOR-VERSION 35)  ;; target FreeBSD-compatible subset
  (define FUSE-MIN-READ-BUFFER 8192)
  (define FUSE-MAX-BUFFER-SIZE (+ 131072 4096))  ;; max_write + header room
  (define FUSE-ROOT-ID 1)

  ;; ---- Header sizes ----
  (define FUSE-IN-HEADER-SIZE 40)
  (define FUSE-OUT-HEADER-SIZE 16)

  ;; ---- Opcodes ----
  (define FUSE-LOOKUP          1)
  (define FUSE-FORGET          2)
  (define FUSE-GETATTR         3)
  (define FUSE-SETATTR         4)
  (define FUSE-READLINK        5)
  (define FUSE-SYMLINK         6)
  (define FUSE-MKNOD           8)
  (define FUSE-MKDIR           9)
  (define FUSE-UNLINK         10)
  (define FUSE-RMDIR          11)
  (define FUSE-RENAME         12)
  (define FUSE-LINK           13)
  (define FUSE-OPEN           14)
  (define FUSE-READ           15)
  (define FUSE-WRITE          16)
  (define FUSE-STATFS         17)
  (define FUSE-RELEASE        18)
  (define FUSE-FSYNC          20)
  (define FUSE-SETXATTR       21)
  (define FUSE-GETXATTR       22)
  (define FUSE-LISTXATTR      23)
  (define FUSE-REMOVEXATTR    24)
  (define FUSE-FLUSH          25)
  (define FUSE-INIT           26)
  (define FUSE-OPENDIR        27)
  (define FUSE-READDIR        28)
  (define FUSE-RELEASEDIR     29)
  (define FUSE-FSYNCDIR       30)
  (define FUSE-GETLK          31)
  (define FUSE-SETLK          32)
  (define FUSE-SETLKW         33)
  (define FUSE-ACCESS         34)
  (define FUSE-CREATE         35)
  (define FUSE-INTERRUPT      36)
  (define FUSE-BMAP           37)
  (define FUSE-DESTROY        38)
  (define FUSE-BATCH-FORGET   42)
  (define FUSE-FALLOCATE      43)
  (define FUSE-READDIRPLUS    44)
  (define FUSE-RENAME2        45)
  (define FUSE-LSEEK          46)
  (define FUSE-COPY-FILE-RANGE 47)

  ;; ---- INIT capability flags ----
  (define FUSE-ASYNC-READ           #x00000001)
  (define FUSE-POSIX-LOCKS          #x00000002)
  (define FUSE-FILE-OPS             #x00000004)
  (define FUSE-ATOMIC-O-TRUNC       #x00000008)
  (define FUSE-EXPORT-SUPPORT       #x00000010)
  (define FUSE-BIG-WRITES           #x00000020)
  (define FUSE-DONT-MASK            #x00000040)
  (define FUSE-SPLICE-WRITE         #x00000080)
  (define FUSE-SPLICE-MOVE          #x00000100)
  (define FUSE-SPLICE-READ          #x00000200)
  (define FUSE-FLOCK-LOCKS          #x00000400)
  (define FUSE-HAS-IOCTL-DIR        #x00000800)
  (define FUSE-AUTO-INVAL-DATA      #x00001000)
  (define FUSE-DO-READDIRPLUS       #x00002000)
  (define FUSE-READDIRPLUS-AUTO     #x00004000)
  (define FUSE-ASYNC-DIO            #x00008000)
  (define FUSE-WRITEBACK-CACHE      #x00010000)
  (define FUSE-NO-OPEN-SUPPORT      #x00020000)
  (define FUSE-PARALLEL-DIROPS      #x00040000)
  (define FUSE-HANDLE-KILLPRIV      #x00080000)
  (define FUSE-POSIX-ACL            #x00100000)
  (define FUSE-ABORT-ERROR          #x00200000)
  (define FUSE-MAX-PAGES            #x00400000)
  (define FUSE-CACHE-SYMLINKS       #x00800000)
  (define FUSE-NO-OPENDIR-SUPPORT   #x01000000)
  (define FUSE-EXPLICIT-INVAL-DATA  #x02000000)
  (define FUSE-INIT-EXT             #x40000000)

  ;; ---- FATTR flags ----
  (define FATTR-MODE       #x001)
  (define FATTR-UID        #x002)
  (define FATTR-GID        #x004)
  (define FATTR-SIZE       #x008)
  (define FATTR-ATIME      #x010)
  (define FATTR-MTIME      #x020)
  (define FATTR-FH         #x040)
  (define FATTR-ATIME-NOW  #x080)
  (define FATTR-MTIME-NOW  #x100)
  (define FATTR-CTIME      #x400)

  ;; ---- FOPEN flags ----
  (define FOPEN-DIRECT-IO     #x01)
  (define FOPEN-KEEP-CACHE    #x02)
  (define FOPEN-NONSEEKABLE   #x04)
  (define FOPEN-CACHE-DIR     #x08)
  (define FOPEN-STREAM        #x10)

  ;; ---- File type bits ----
  (define S-IFMT   #o170000)
  (define S-IFIFO  #o010000)
  (define S-IFCHR  #o020000)
  (define S-IFDIR  #o040000)
  (define S-IFBLK  #o060000)
  (define S-IFREG  #o100000)
  (define S-IFLNK  #o120000)
  (define S-IFSOCK #o140000)

  ;; ---- Permission bits ----
  (define S-ISUID  #o004000)
  (define S-ISGID  #o002000)
  (define S-ISVTX  #o001000)
  (define S-IRWXU  #o000700)
  (define S-IRUSR  #o000400)
  (define S-IWUSR  #o000200)
  (define S-IXUSR  #o000100)
  (define S-IRWXG  #o000070)
  (define S-IRGRP  #o000040)
  (define S-IWGRP  #o000020)
  (define S-IXGRP  #o000010)
  (define S-IRWXO  #o000007)
  (define S-IROTH  #o000004)
  (define S-IWOTH  #o000002)
  (define S-IXOTH  #o000001)

  ;; ---- DT_* directory entry types ----
  (define DT-UNKNOWN  0)
  (define DT-FIFO     1)
  (define DT-CHR      2)
  (define DT-DIR      4)
  (define DT-BLK      6)
  (define DT-REG      8)
  (define DT-LNK     10)
  (define DT-SOCK    12)
  (define DT-WHT     14)

  ;; ---- Open flags ----
  (define O-RDONLY   #x0000)
  (define O-WRONLY   #x0001)
  (define O-RDWR     #x0002)
  (define O-CREAT    #x0040)
  (define O-EXCL     #x0080)
  (define O-TRUNC    #x0200)
  (define O-APPEND   #x0400)

  ;; ---- Access flags ----
  (define F-OK 0)
  (define R-OK 4)
  (define W-OK 2)
  (define X-OK 1)

  ;; ---- Errno values ----
  ;; POSIX values — same on Linux and FreeBSD for the common set
  (define EPERM           1)
  (define ENOENT          2)
  (define ESRCH           3)
  (define EINTR           4)
  (define EIO             5)
  (define ENXIO           6)
  (define E2BIG           7)
  (define ENOEXEC         8)
  (define EBADF           9)
  (define ECHILD         10)
  (define EAGAIN         11)
  (define ENOMEM         12)
  (define EACCES         13)
  (define EFAULT         14)
  (define EBUSY          16)
  (define EEXIST         17)
  (define EXDEV          18)
  (define ENODEV         19)
  (define ENOTDIR        20)
  (define EISDIR         21)
  (define EINVAL         22)
  (define ENFILE         23)
  (define EMFILE         24)
  (define ENOTTY         25)
  (define EFBIG          27)
  (define ENOSPC         28)
  (define ESPIPE         29)
  (define EROFS          30)
  (define EMLINK         31)
  (define EPIPE          32)
  (define EDOM           33)
  (define ERANGE         34)
  (define ENOSYS         38)
  (define ENOTEMPTY      39)
  (define ENAMETOOLONG   36)
  (define ELOOP          40)
  (define ENODATA        61)
  (define ENOTCONN      107)
  (define EOVERFLOW      75)
  (define EOPNOTSUPP     95)
  (define ENOTSUP        95)

  ;; ---- Helpers ----
  ;; 8-byte alignment for FUSE records
  (define (fuse-rec-align x)
    (bitwise-and (+ x 7) (bitwise-not 7)))

) ;; end library
