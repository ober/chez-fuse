(library (chez fuse access)
  (export
    ;; Access controller
    make-access-controller    ;; → controller (trusts current PID and descendants)
    access-check              ;; controller pid → #t (trusted) or #f (denied)
    access-controller-lock!   ;; controller → void (deny all, clear cache)
    access-controller-unlock! ;; controller → void (re-enable normal checks)
    access-controller-locked? ;; controller → boolean

    ;; Stealth deny helpers (for FUSE dispatch)
    stealth-deny-attr         ;; → fuse-attr (empty root-like)
    stealth-deny-readdir      ;; → list of dirents (just . and ..)

    ;; Process tree inspection
    pid-is-descendant?)       ;; pid ancestor-pid → boolean

  (import
    (rnrs)
    (only (chezscheme)
          foreign-procedure make-time time-second current-time
          make-eq-hashtable eq-hashtable-ref eq-hashtable-set!
          eq-hashtable-delete! make-mutex with-mutex)
    (chez fuse constants)
    (chez fuse types)
    (chez fuse mount))  ;; ensure shared lib loaded

  ;; ---- FFI: process tree ----

  (define _lib-loaded (begin (ensure-mount-lib!) #t))

  (define c-getpid
    (foreign-procedure "chez_fuse_getpid" () int))
  (define c-getppid-of
    (foreign-procedure "chez_fuse_getppid_of" (int) int))

  ;; ---- Process tree walking ----

  ;; Walk the parent chain of pid up to init (PID 1).
  ;; Returns #t if ancestor-pid is found in the chain.
  ;; Max depth prevents runaway loops from PID reuse races.
  (define (pid-is-descendant? pid ancestor-pid)
    (let loop ([current pid] [depth 0])
      (cond
        [(= current ancestor-pid) #t]
        [(<= current 1) #f]        ;; reached init or invalid
        [(> depth 64) #f]           ;; safety limit
        [else
         (let ([ppid (c-getppid-of current)])
           (if (< ppid 0) #f       ;; process gone or error
             (loop ppid (+ depth 1))))])))

  ;; ---- Access controller ----

  ;; Cache entry: (pid . expiry-time)
  ;; Trusted PIDs are cached for a short TTL to avoid repeated sysctl calls.
  ;; Denied PIDs are NOT cached (process might become a child later, though
  ;; unlikely — and we want to re-check in case of PID reuse).
  (define CACHE-TTL 5)  ;; seconds

  (define-record-type access-controller-state
    (fields
      (immutable owner-pid)   ;; PID of jsh (the trusted root process)
      (mutable locked?)       ;; #t → deny all (vault locked)
      (mutable cache)         ;; eq-hashtable: pid → expiry-time
      (mutable mutex)))

  (define (make-access-controller)
    (make-access-controller-state
      (c-getpid) #f (make-eq-hashtable) (make-mutex)))

  (define (access-controller-locked? ac)
    (access-controller-state-locked? ac))

  (define (access-controller-lock! ac)
    (with-mutex (access-controller-state-mutex ac)
      (access-controller-state-locked?-set! ac #t)
      ;; Clear the trust cache
      (access-controller-state-cache-set! ac (make-eq-hashtable))))

  (define (access-controller-unlock! ac)
    (with-mutex (access-controller-state-mutex ac)
      (access-controller-state-locked?-set! ac #f)))

  ;; Check if a PID is trusted (is jsh or a descendant of jsh).
  ;; Returns #t for trusted, #f for denied.
  (define (access-check ac pid)
    (with-mutex (access-controller-state-mutex ac)
      (cond
        ;; Locked → deny all
        [(access-controller-state-locked? ac) #f]
        ;; Owner PID → always trusted
        [(= pid (access-controller-state-owner-pid ac)) #t]
        ;; Check cache
        [else
         (let* ([cache (access-controller-state-cache ac)]
                [now   (time-second (current-time))]
                [expiry (eq-hashtable-ref cache pid #f)])
           (cond
             ;; Cache hit, not expired
             [(and expiry (> expiry now)) #t]
             ;; Cache miss or expired — do the walk
             [else
              (let ([trusted? (pid-is-descendant?
                                pid
                                (access-controller-state-owner-pid ac))])
                (when trusted?
                  ;; Cache positive result
                  (eq-hashtable-set! cache pid (+ now CACHE-TTL)))
                trusted?)]))])))

  ;; ---- Stealth deny responses ----
  ;; These create responses that make the vault look like an empty directory
  ;; to unauthorized processes. No error codes — just... nothing there.

  (define (stealth-deny-attr)
    ;; Return a minimal directory attr for the root node.
    ;; This makes the mountpoint itself appear to exist (it must, since it's
    ;; a mount point) but contain nothing.
    (let ([now (time-second (current-time))])
      (make-fuse-attr
        FUSE-ROOT-ID   ;; ino
        0              ;; size
        0              ;; blocks
        now now now    ;; atime mtime ctime
        0 0 0          ;; nanoseconds
        (bitwise-ior S-IFDIR #o755)  ;; mode
        2              ;; nlink
        0 0            ;; uid gid
        0              ;; rdev
        4096)))        ;; blksize

  (define (stealth-deny-readdir ino)
    ;; Return just . and .. — an empty directory.
    (list
      (make-fuse-dirent ino 1 DT-DIR ".")
      (make-fuse-dirent ino 2 DT-DIR "..")))

) ;; end library
