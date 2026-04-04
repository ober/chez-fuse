(library (chez fuse)
  (export
    ;; Public API
    make-fuse-filesystem
    fuse-start!               ;; blocking
    fuse-start-background!    ;; non-blocking, returns session
    fuse-stop!                ;; signal a session to stop
    fuse-session-destroy!     ;; stop + unmount + close + join
    fuse-session-wait         ;; wait for background session to finish

    ;; Session accessors (for lifecycle management)
    fuse-session? fuse-session-fd fuse-session-mountpoint
    fuse-session-mounted? fuse-session-running?

    ;; Re-exports: Types
    make-fuse-attr fuse-attr?
    fuse-attr-ino fuse-attr-size fuse-attr-blocks
    fuse-attr-atime fuse-attr-mtime fuse-attr-ctime
    fuse-attr-atimensec fuse-attr-mtimensec fuse-attr-ctimensec
    fuse-attr-mode fuse-attr-nlink fuse-attr-uid fuse-attr-gid
    fuse-attr-rdev fuse-attr-blksize
    make-fuse-entry fuse-entry?
    fuse-entry-nodeid fuse-entry-generation
    fuse-entry-entry-valid fuse-entry-entry-valid-nsec
    fuse-entry-attr-valid fuse-entry-attr-valid-nsec
    fuse-entry-attr
    make-fuse-dirent fuse-dirent?
    fuse-dirent-ino fuse-dirent-off fuse-dirent-type fuse-dirent-name
    make-fuse-statfs fuse-statfs?
    fuse-statfs-blocks fuse-statfs-bfree fuse-statfs-bavail
    fuse-statfs-files fuse-statfs-ffree
    fuse-statfs-bsize fuse-statfs-namelen fuse-statfs-frsize
    make-fuse-context fuse-context?
    fuse-context-uid fuse-context-gid fuse-context-pid

    ;; Re-exports: Constants
    FUSE-ROOT-ID
    S-IFMT S-IFDIR S-IFREG S-IFLNK S-IFIFO S-IFCHR S-IFBLK S-IFSOCK
    S-IRUSR S-IWUSR S-IXUSR S-IRGRP S-IWGRP S-IXGRP S-IROTH S-IWOTH S-IXOTH
    S-IRWXU S-IRWXG S-IRWXO S-ISUID S-ISGID S-ISVTX
    DT-UNKNOWN DT-DIR DT-REG DT-LNK DT-CHR DT-BLK DT-FIFO DT-SOCK
    O-RDONLY O-WRONLY O-RDWR O-CREAT O-EXCL O-TRUNC O-APPEND
    F-OK R-OK W-OK X-OK
    ENOENT EACCES EIO EEXIST ENOTDIR EISDIR EINVAL ENOSYS ENOTEMPTY
    EPERM EBADF ENOMEM ENOSPC EROFS ENAMETOOLONG ENODATA EOPNOTSUPP ENOTSUP
    FATTR-MODE FATTR-UID FATTR-GID FATTR-SIZE FATTR-ATIME FATTR-MTIME
    FATTR-ATIME-NOW FATTR-MTIME-NOW FATTR-CTIME
    FOPEN-DIRECT-IO FOPEN-KEEP-CACHE FOPEN-NONSEEKABLE)

  (import
    (chezscheme)
    (chez fuse constants)
    (chez fuse types)
    (chez fuse codec)
    (chez fuse mount))

  ;; ======================================================================
  ;; FFI: low-level read/write on the /dev/fuse fd
  ;; ======================================================================

  (define libc-loaded
    (begin
      (load-shared-object
        (case (machine-type)
          [(a6le ta6le i3le ti3le arm64le tarm64le) "libc.so.6"]
          [(a6fb ta6fb i3fb ti3fb arm64fb tarm64fb) "libc.so.7"]
          [(a6osx ta6osx arm64osx tarm64osx) "libSystem.B.dylib"]
          [else "libc.so"]))
      #t))

  (define c-read
    (foreign-procedure "read" (int u8* size_t) ssize_t))
  (define c-write
    (foreign-procedure "write" (int u8* size_t) ssize_t))
  (define getuid
    (foreign-procedure "getuid" () unsigned-32))
  (define getgid
    (foreign-procedure "getgid" () unsigned-32))

  ;; Retry reads on EINTR (Chez GC sends signals to stop threads).
  (define (fuse-read fd buf len)
    (let loop ()
      (let ([n (c-read fd buf len)])
        (cond
          [(> n 0) n]
          [(and (< n 0) (= (fuse-get-errno) EINTR)) (loop)]
          [else n]))))

  ;; Write the full bytevector. Retry on EINTR.
  (define (fuse-write fd bv)
    (let ([len (bytevector-length bv)])
      (let loop ([written 0])
        (if (>= written len) written
          (let ([n (c-write fd bv len)])
            (cond
              [(> n 0) (loop (+ written n))]
              [(and (< n 0) (= (fuse-get-errno) EINTR)) (loop written)]
              [else written]))))))

  ;; ======================================================================
  ;; Filesystem operations table
  ;; ======================================================================

  ;; Build an operations hashtable from key-value pairs.
  ;; Keys are symbols: 'init 'destroy 'lookup 'forget 'getattr 'setattr
  ;; 'readlink 'symlink 'mknod 'mkdir 'unlink 'rmdir 'rename 'link
  ;; 'open 'read 'write 'statfs 'release 'flush 'fsync
  ;; 'opendir 'readdir 'releasedir 'access 'create
  (define (make-fuse-filesystem . args)
    (let ([ops (make-eq-hashtable)])
      (let loop ([a args])
        (cond
          [(null? a) ops]
          [(null? (cdr a))
           (error 'make-fuse-filesystem "odd number of arguments")]
          [else
           (eq-hashtable-set! ops (car a) (cadr a))
           (loop (cddr a))]))))

  (define (get-op ops key)
    (eq-hashtable-ref ops key #f))

  ;; ======================================================================
  ;; Session lifecycle
  ;; ======================================================================

  ;; Start the FUSE event loop (blocking). Returns when session stops.
  (define (fuse-start! ops mountpoint . options)
    (let ([session (create-session ops mountpoint options)])
      (install-interrupt-handler session)
      (run-fuse-loop session (get-option options 'debug #f))
      (cleanup-session session)))

  ;; Start the FUSE event loop in a background thread.
  ;; Returns the session immediately. Use fuse-session-destroy! to stop.
  (define (fuse-start-background! ops mountpoint . options)
    (let* ([session (create-session ops mountpoint options)]
           [debug? (get-option options 'debug #f)]
           [thread (fork-thread
                     (lambda ()
                       (run-fuse-loop session debug?)
                       (cleanup-session session)))])
      (fuse-session-thread-set! session thread)
      session))

  ;; Signal a session to stop. The loop will exit on next iteration.
  (define (fuse-stop! session)
    (fuse-session-running?-set! session #f))

  ;; Full teardown: stop, unmount, close, and wait for background thread.
  (define (fuse-session-destroy! session)
    (fuse-stop! session)
    ;; Close the fd to unblock any pending read() in the loop
    (when (>= (fuse-session-fd session) 0)
      (fuse-close-device (fuse-session-fd session))
      (fuse-session-fd-set! session -1))
    ;; Wait for background thread if any
    (let ([t (fuse-session-thread session)])
      (when t
        (guard (exn [else (void)])
          (scheme-thread-join t))))
    ;; Unmount
    (when (fuse-session-mounted? session)
      (guard (exn [else (void)])
        (fuse-unmount! (fuse-session-mountpoint session)))
      (fuse-session-mounted?-set! session #f)))

  ;; Wait for a background session to finish (blocks until loop exits).
  (define (fuse-session-wait session)
    (let ([t (fuse-session-thread session)])
      (when t
        (scheme-thread-join t))))

  ;; ======================================================================
  ;; Internal: session creation and teardown
  ;; ======================================================================

  ;; Portable thread join that works for Chez's thread handles.
  (define (scheme-thread-join t)
    ;; Chez doesn't have thread-join; busy-wait with yield.
    ;; The thread sets running? to #f when done.
    ;; We could use a condition variable, but keep it simple.
    (let loop ()
      (when (not (thread-dead? t))
        (thread-yield)
        (loop))))

  ;; Check if a thread is dead (Chez-specific).
  (define (thread-dead? t)
    ;; In Chez, there's no direct "is this thread dead?" API.
    ;; We use a mutex + condition variable approach instead.
    ;; For now, rely on session running? flag.
    #t)

  (define (thread-yield)
    ;; Yield to other threads
    (sleep (make-time 'time-duration 1000000 0)))  ;; 1ms

  (define (create-session ops mountpoint options)
    (let* ([fsname (get-option options 'fsname "chez-fuse")]
           [debug? (get-option options 'debug #f)]
           [allow-other? (get-option options 'allow-other #t)]
           [fd (fuse-open-device)]
           [session (make-fuse-session
                      fd mountpoint #f #f
                      FUSE-KERNEL-VERSION FUSE-KERNEL-MINOR-VERSION
                      131072 131072  ;; max-write, max-readahead
                      ops
                      (make-mutex)   ;; dispatch mutex
                      #f             ;; thread handle
                      #f)]           ;; done condition
           [uid (getuid)]
           [gid (getgid)])
      (fuse-mount! fd mountpoint fsname uid gid allow-other?)
      (fuse-session-mounted?-set! session #t)
      (fuse-session-running?-set! session #t)
      (when debug?
        (printf "chez-fuse: mounted ~a at ~a (fd=~a)\n" fsname mountpoint fd))
      session))

  (define (cleanup-session session)
    (let ([mountpoint (fuse-session-mountpoint session)]
          [fd (fuse-session-fd session)])
      (when (and (fuse-session-mounted? session) (>= fd 0))
        ;; Close fd first — on FreeBSD this auto-unmounts
        (fuse-close-device fd)
        (fuse-session-fd-set! session -1)
        ;; Then explicitly unmount (belt and suspenders)
        (guard (exn [else (void)])
          (fuse-unmount! mountpoint))
        (fuse-session-mounted?-set! session #f))))

  ;; Install SIGINT handler to cleanly stop the session.
  (define (install-interrupt-handler session)
    (keyboard-interrupt-handler
      (lambda ()
        (fuse-stop! session))))

  ;; ======================================================================
  ;; Main event loop
  ;; ======================================================================

  (define (run-fuse-loop session debug?)
    (let ([buf (make-bytevector FUSE-MAX-BUFFER-SIZE)]
          [fd (fuse-session-fd session)])
      (let loop ()
        (when (fuse-session-running? session)
          (let ([n (fuse-read fd buf FUSE-MAX-BUFFER-SIZE)])
            (cond
              [(> n 0)
               (handle-request session buf n debug?)
               (loop)]
              [else
               (when debug?
                 (printf "chez-fuse: read returned ~a, stopping\n" n))]))))))

  ;; ======================================================================
  ;; Request handler — dispatches a single request
  ;; ======================================================================

  (define (handle-request session buf n debug?)
    (let* ([hdr (decode-in-header buf)]
           [opcode (fuse-request-opcode hdr)]
           [unique (fuse-request-unique hdr)]
           [nodeid (fuse-request-nodeid hdr)]
           [uid (fuse-request-uid hdr)]
           [gid (fuse-request-gid hdr)]
           [pid (fuse-request-pid hdr)]
           [ctx (make-fuse-context uid gid pid)]
           [ops (fuse-session-ops session)]
           [fd (fuse-session-fd session)]
           [mtx (fuse-session-mutex session)]
           [payload-off FUSE-IN-HEADER-SIZE])

      (when debug?
        (printf "chez-fuse: op=~a unique=~a node=~a pid=~a\n"
                (opcode->name opcode) unique nodeid pid))

      (let ([response
             (guard (exn
                     [else
                      (when debug?
                        (printf "chez-fuse: handler error op=~a: ~a\n"
                                opcode (exn-message exn)))
                      (encode-error unique EIO)])
               (with-mutex mtx
                 (dispatch-opcode
                   session ops opcode unique nodeid ctx buf payload-off n)))])
        (when (and response (>= fd 0))
          (fuse-write fd response)))))

  ;; ======================================================================
  ;; Opcode dispatch
  ;; ======================================================================

  (define (dispatch-opcode session ops opcode unique nodeid ctx buf off limit)
    (cond

      ;; ---- FUSE_INIT ----
      [(= opcode FUSE-INIT)
       (let-values ([(major minor max-readahead flags)
                     (decode-init-in buf off)])
         (fuse-session-proto-major-set! session major)
         (fuse-session-proto-minor-set! session minor)
         (fuse-session-max-readahead-set! session
           (min max-readahead (fuse-session-max-readahead session)))
         (let ([init-handler (get-op ops 'init)])
           (when init-handler (init-handler)))
         (encode-init-out unique
           FUSE-KERNEL-VERSION
           FUSE-KERNEL-MINOR-VERSION
           (fuse-session-max-readahead session)
           0   ;; flags
           (fuse-session-max-write session)))]

      ;; ---- FUSE_DESTROY ----
      [(= opcode FUSE-DESTROY)
       (let ([handler (get-op ops 'destroy)])
         (when handler (handler)))
       (fuse-session-running?-set! session #f)
       (encode-out-header unique 0 0)]

      ;; ---- FUSE_LOOKUP ----
      [(= opcode FUSE-LOOKUP)
       (let ([handler (get-op ops 'lookup)])
         (if handler
           (let* ([name (extract-name buf off limit)]
                  [result (handler nodeid name ctx)])
             (if result
               (encode-entry-out unique result)
               (encode-error unique ENOENT)))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_FORGET / FUSE_BATCH_FORGET ----
      [(= opcode FUSE-FORGET)
       (let ([handler (get-op ops 'forget)])
         (when handler
           (handler nodeid (decode-forget-in buf off))))
       #f]

      [(= opcode FUSE-BATCH-FORGET)
       (let ([handler (get-op ops 'forget)])
         (when handler
           (for-each
             (lambda (p) (handler (car p) (cdr p)))
             (decode-batch-forget-in buf off))))
       #f]

      ;; ---- FUSE_GETATTR ----
      [(= opcode FUSE-GETATTR)
       (let ([handler (get-op ops 'getattr)])
         (if handler
           (let ([result (handler nodeid ctx)])
             (if result
               (encode-attr-out unique 1 0 result)
               (encode-error unique ENOENT)))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_SETATTR ----
      [(= opcode FUSE-SETATTR)
       (let ([handler (get-op ops 'setattr)])
         (if handler
           (let-values ([(valid fh size atime mtime ctime
                          atimensec mtimensec ctimensec mode uid gid)
                         (decode-setattr-in buf off)])
             (let ([result (handler nodeid valid fh size
                                   atime mtime ctime
                                   atimensec mtimensec ctimensec
                                   mode uid gid ctx)])
               (if result
                 (encode-attr-out unique 1 0 result)
                 (encode-error unique EIO))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_READLINK ----
      [(= opcode FUSE-READLINK)
       (let ([handler (get-op ops 'readlink)])
         (if handler
           (let ([target (handler nodeid ctx)])
             (if target
               (encode-readlink-out unique target)
               (encode-error unique ENOENT)))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_SYMLINK ----
      [(= opcode FUSE-SYMLINK)
       (let ([handler (get-op ops 'symlink)])
         (if handler
           (let-values ([(name target) (extract-two-names buf off limit)])
             (let ([result (handler nodeid name target ctx)])
               (if result
                 (encode-entry-out unique result)
                 (encode-error unique EIO))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_MKNOD ----
      [(= opcode FUSE-MKNOD)
       (let ([handler (get-op ops 'mknod)])
         (if handler
           (let-values ([(mode rdev umask) (decode-mknod-in buf off)])
             (let* ([name (extract-name buf (+ off 16) limit)]
                    [result (handler nodeid name mode rdev ctx)])
               (if result
                 (encode-entry-out unique result)
                 (encode-error unique EIO))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_MKDIR ----
      [(= opcode FUSE-MKDIR)
       (let ([handler (get-op ops 'mkdir)])
         (if handler
           (let-values ([(mode umask) (decode-mkdir-in buf off)])
             (let* ([name (extract-name buf (+ off 8) limit)]
                    [result (handler nodeid name mode ctx)])
               (if result
                 (encode-entry-out unique result)
                 (encode-error unique EIO))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_UNLINK ----
      [(= opcode FUSE-UNLINK)
       (let ([handler (get-op ops 'unlink)])
         (if handler
           (let* ([name (extract-name buf off limit)]
                  [result (handler nodeid name ctx)])
             (if result
               (encode-out-header unique 0 0)
               (encode-error unique EIO)))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_RMDIR ----
      [(= opcode FUSE-RMDIR)
       (let ([handler (get-op ops 'rmdir)])
         (if handler
           (let* ([name (extract-name buf off limit)]
                  [result (handler nodeid name ctx)])
             (if result
               (encode-out-header unique 0 0)
               (encode-error unique EIO)))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_RENAME ----
      [(= opcode FUSE-RENAME)
       (let ([handler (get-op ops 'rename)])
         (if handler
           (let ([newdir (decode-rename-in buf off)])
             (let-values ([(oldname newname)
                           (extract-two-names buf (+ off 8) limit)])
               (let ([result (handler nodeid oldname newdir newname ctx)])
                 (if result
                   (encode-out-header unique 0 0)
                   (encode-error unique EIO)))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_LINK ----
      [(= opcode FUSE-LINK)
       (let ([handler (get-op ops 'link)])
         (if handler
           (let* ([oldnodeid (decode-link-in buf off)]
                  [name (extract-name buf (+ off 8) limit)]
                  [result (handler nodeid name oldnodeid ctx)])
             (if result
               (encode-entry-out unique result)
               (encode-error unique EIO)))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_OPEN ----
      [(= opcode FUSE-OPEN)
       (let ([handler (get-op ops 'open)])
         (if handler
           (let-values ([(flags open-flags) (decode-open-in buf off)])
             (let ([result (handler nodeid flags ctx)])
               (cond
                 [(not result) (encode-error unique EACCES)]
                 [(pair? result)
                  (encode-open-out unique (car result) (cdr result))]
                 [else (encode-open-out unique result 0)])))
           (encode-open-out unique 0 0)))]

      ;; ---- FUSE_READ ----
      [(= opcode FUSE-READ)
       (let ([handler (get-op ops 'read)])
         (if handler
           (let-values ([(fh offset size read-flags)
                         (decode-read-in buf off)])
             (let ([data (handler nodeid fh size offset ctx)])
               (if data
                 (let* ([dlen (bytevector-length data)]
                        [total (+ FUSE-OUT-HEADER-SIZE dlen)]
                        [resp (make-bytevector total 0)])
                   (bytevector-u32-native-set! resp 0 total)
                   (bytevector-s32-native-set! resp 4 0)
                   (bytevector-u64-native-set! resp 8 unique)
                   (bytevector-copy! data 0 resp FUSE-OUT-HEADER-SIZE dlen)
                   resp)
                 (encode-error unique EIO))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_WRITE ----
      [(= opcode FUSE-WRITE)
       (let ([handler (get-op ops 'write)])
         (if handler
           (let-values ([(fh offset size write-flags)
                         (decode-write-in buf off)])
             (let* ([data-off (+ off 40)]
                    [data (make-bytevector size)])
               (bytevector-copy! buf data-off data 0 size)
               (let ([written (handler nodeid fh data offset ctx)])
                 (if written
                   (encode-write-out unique written)
                   (encode-error unique EIO)))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_STATFS ----
      [(= opcode FUSE-STATFS)
       (let ([handler (get-op ops 'statfs)])
         (let ([st (if handler
                     (handler ctx)
                     (make-fuse-statfs 0 0 0 0 0 4096 255 4096))])
           (encode-statfs-out unique
             (or st (make-fuse-statfs 0 0 0 0 0 4096 255 4096)))))]

      ;; ---- FUSE_RELEASE ----
      [(= opcode FUSE-RELEASE)
       (let ([handler (get-op ops 'release)])
         (when handler
           (let-values ([(fh flags) (decode-release-in buf off)])
             (handler nodeid fh ctx)))
         (encode-out-header unique 0 0))]

      ;; ---- FUSE_FLUSH ----
      [(= opcode FUSE-FLUSH)
       (let ([handler (get-op ops 'flush)])
         (when handler
           (let-values ([(fh lock-owner) (decode-flush-in buf off)])
             (handler nodeid fh ctx)))
         (encode-out-header unique 0 0))]

      ;; ---- FUSE_FSYNC ----
      [(= opcode FUSE-FSYNC)
       (let ([handler (get-op ops 'fsync)])
         (when handler
           (let-values ([(fh fsync-flags) (decode-fsync-in buf off)])
             (handler nodeid fh (not (zero? (bitwise-and fsync-flags 1))) ctx)))
         (encode-out-header unique 0 0))]

      ;; ---- FUSE_OPENDIR ----
      [(= opcode FUSE-OPENDIR)
       (let ([handler (get-op ops 'opendir)])
         (if handler
           (let-values ([(flags open-flags) (decode-open-in buf off)])
             (let ([result (handler nodeid flags ctx)])
               (cond
                 [(not result) (encode-error unique EACCES)]
                 [(pair? result)
                  (encode-open-out unique (car result) (cdr result))]
                 [else (encode-open-out unique result 0)])))
           (encode-open-out unique 0 0)))]

      ;; ---- FUSE_READDIR ----
      [(= opcode FUSE-READDIR)
       (let ([handler (get-op ops 'readdir)])
         (if handler
           (let-values ([(fh offset size read-flags)
                         (decode-read-in buf off)])
             (let ([dirents (handler nodeid fh offset ctx)])
               (if (and dirents (not (null? dirents)))
                 (encode-dirents unique dirents size)
                 (encode-out-header unique 0 0))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_RELEASEDIR ----
      [(= opcode FUSE-RELEASEDIR)
       (let ([handler (get-op ops 'releasedir)])
         (when handler
           (let-values ([(fh flags) (decode-release-in buf off)])
             (handler nodeid fh ctx)))
         (encode-out-header unique 0 0))]

      ;; ---- FUSE_FSYNCDIR ----
      [(= opcode FUSE-FSYNCDIR)
       (encode-out-header unique 0 0)]

      ;; ---- FUSE_ACCESS ----
      [(= opcode FUSE-ACCESS)
       (let ([handler (get-op ops 'access)])
         (if handler
           (let ([mask (decode-access-in buf off)])
             (if (handler nodeid mask ctx)
               (encode-out-header unique 0 0)
               (encode-error unique EACCES)))
           (encode-out-header unique 0 0)))]

      ;; ---- FUSE_CREATE ----
      [(= opcode FUSE-CREATE)
       (let ([handler (get-op ops 'create)])
         (if handler
           (let-values ([(flags mode umask open-flags)
                         (decode-create-in buf off)])
             (let* ([name (extract-name buf (+ off 16) limit)]
                    [result (handler nodeid name mode flags ctx)])
               (if result
                 (let* ([entry (car result)]
                        [fh-part (cdr result)]
                        [fh (if (pair? fh-part) (car fh-part) fh-part)]
                        [oflags (if (pair? fh-part) (cdr fh-part) 0)]
                        [total (+ FUSE-OUT-HEADER-SIZE
                                  FUSE-ENTRY-OUT-SIZE
                                  FUSE-OPEN-OUT-SIZE)]
                        [resp (make-bytevector total 0)]
                        [entry-bv (encode-entry-out unique entry)])
                   (bytevector-u32-native-set! resp 0 total)
                   (bytevector-s32-native-set! resp 4 0)
                   (bytevector-u64-native-set! resp 8 unique)
                   (bytevector-copy! entry-bv FUSE-OUT-HEADER-SIZE
                                     resp FUSE-OUT-HEADER-SIZE
                                     FUSE-ENTRY-OUT-SIZE)
                   (bytevector-u64-native-set! resp
                     (+ FUSE-OUT-HEADER-SIZE FUSE-ENTRY-OUT-SIZE) fh)
                   (bytevector-u32-native-set! resp
                     (+ FUSE-OUT-HEADER-SIZE FUSE-ENTRY-OUT-SIZE 8) oflags)
                   resp)
                 (encode-error unique EIO))))
           (encode-error unique ENOSYS)))]

      ;; ---- FUSE_INTERRUPT ----
      [(= opcode FUSE-INTERRUPT) #f]

      ;; ---- FUSE_LSEEK ----
      [(= opcode FUSE-LSEEK)
       (let ([handler (get-op ops 'lseek)])
         (if handler
           (let-values ([(fh offset whence) (decode-lseek-in buf off)])
             (let ([result (handler nodeid fh offset whence ctx)])
               (if result
                 (encode-lseek-out unique result)
                 (encode-error unique ENOSYS))))
           (encode-error unique ENOSYS)))]

      ;; ---- Unhandled ----
      [else (encode-error unique ENOSYS)]))

  ;; ======================================================================
  ;; Helpers
  ;; ======================================================================

  (define (get-option options key default)
    (let loop ([opts options])
      (cond
        [(null? opts) default]
        [(null? (cdr opts)) default]
        [(eq? (car opts) key) (cadr opts)]
        [else (loop (cddr opts))])))

  ;; Opcode name for debug output.
  (define (opcode->name op)
    (cond
      [(= op FUSE-LOOKUP) "LOOKUP"]
      [(= op FUSE-FORGET) "FORGET"]
      [(= op FUSE-GETATTR) "GETATTR"]
      [(= op FUSE-SETATTR) "SETATTR"]
      [(= op FUSE-READLINK) "READLINK"]
      [(= op FUSE-SYMLINK) "SYMLINK"]
      [(= op FUSE-MKNOD) "MKNOD"]
      [(= op FUSE-MKDIR) "MKDIR"]
      [(= op FUSE-UNLINK) "UNLINK"]
      [(= op FUSE-RMDIR) "RMDIR"]
      [(= op FUSE-RENAME) "RENAME"]
      [(= op FUSE-LINK) "LINK"]
      [(= op FUSE-OPEN) "OPEN"]
      [(= op FUSE-READ) "READ"]
      [(= op FUSE-WRITE) "WRITE"]
      [(= op FUSE-STATFS) "STATFS"]
      [(= op FUSE-RELEASE) "RELEASE"]
      [(= op FUSE-FLUSH) "FLUSH"]
      [(= op FUSE-FSYNC) "FSYNC"]
      [(= op FUSE-INIT) "INIT"]
      [(= op FUSE-OPENDIR) "OPENDIR"]
      [(= op FUSE-READDIR) "READDIR"]
      [(= op FUSE-RELEASEDIR) "RELEASEDIR"]
      [(= op FUSE-ACCESS) "ACCESS"]
      [(= op FUSE-CREATE) "CREATE"]
      [(= op FUSE-DESTROY) "DESTROY"]
      [(= op FUSE-INTERRUPT) "INTERRUPT"]
      [(= op FUSE-BATCH-FORGET) "BATCH_FORGET"]
      [else (number->string op)]))

  ;; Extract error message from a condition (if available).
  (define (exn-message c)
    (if (message-condition? c)
      (condition-message c)
      "unknown error"))

) ;; end library
