(library (chez fuse secmem)
  (export
    ;; Low-level secure memory (mlock'd, dump-excluded, volatile-zeroed)
    secmem-alloc          ;; size → foreign-pointer or #f
    secmem-free!          ;; ptr size → void
    secmem-zero!          ;; ptr size → void

    ;; Secure key holder — wraps a fixed-size key in mlock'd memory
    make-secure-key       ;; bytevector → secure-key (copies bv, then zeros bv)
    secure-key?
    secure-key-borrow     ;; secure-key → bytevector (CALLER MUST ZERO AFTER USE)
    secure-key-destroy!   ;; secure-key → void (zeros and frees)
    secure-key-size       ;; secure-key → integer
    secure-key-live?      ;; secure-key → boolean (not yet destroyed?)

    ;; Convenience: run a thunk with the key as a temporary bytevector
    call-with-secure-key) ;; secure-key (lambda (bv) ...) → result

  (import
    (rnrs)
    (only (chezscheme)
          foreign-procedure load-shared-object
          machine-type void)
    (chez fuse mount))  ;; ensure shared lib is loaded

  ;; Ensure the shared library is loaded before defining FFI bindings.
  (define _lib-loaded (begin (ensure-mount-lib!) #t))

  (define c-secmem-alloc
    (foreign-procedure "chez_fuse_secmem_alloc" (size_t) uptr))
  (define c-secmem-free
    (foreign-procedure "chez_fuse_secmem_free" (uptr size_t) void))
  (define c-secmem-zero
    (foreign-procedure "chez_fuse_secmem_zero" (uptr size_t) void))
  (define c-secmem-copy-in
    (foreign-procedure "chez_fuse_secmem_copy_in" (uptr u8* size_t) void))
  (define c-secmem-copy-out
    (foreign-procedure "chez_fuse_secmem_copy_out" (u8* uptr size_t) void))

  ;; ---- Low-level API ----

  (define (secmem-alloc size)
    (let ([ptr (c-secmem-alloc size)])
      (if (= ptr 0) #f ptr)))

  (define (secmem-free! ptr size)
    (c-secmem-free ptr size))

  (define (secmem-zero! ptr size)
    (c-secmem-zero ptr size))

  ;; ---- Secure key holder ----
  ;; Stores a cryptographic key in mlock'd memory outside the GC heap.
  ;; The GC cannot copy, move, or leave stale copies of this data.

  (define-record-type secure-key-record
    (fields
      (mutable ptr)     ;; foreign pointer (uptr), 0 when destroyed
      (immutable size)  ;; key size in bytes
      (mutable live?))) ;; #t until destroyed

  (define (secure-key? x) (secure-key-record? x))
  (define (secure-key-size sk) (secure-key-record-size sk))
  (define (secure-key-live? sk) (secure-key-record-live? sk))

  ;; Create a secure key from a bytevector. The bytevector is zeroed after copy.
  (define (make-secure-key bv)
    (let* ([len (bytevector-length bv)]
           [ptr (secmem-alloc len)])
      (unless ptr
        (error 'make-secure-key "failed to allocate secure memory"))
      (c-secmem-copy-in ptr bv len)
      ;; Zero the source bytevector — the caller's copy is now dead
      (bytevector-fill! bv 0)
      (make-secure-key-record ptr len #t)))

  ;; Borrow the key as a temporary bytevector.
  ;; WARNING: The caller MUST zero this bytevector when done.
  ;; Use call-with-secure-key instead when possible.
  (define (secure-key-borrow sk)
    (unless (secure-key-record-live? sk)
      (error 'secure-key-borrow "key has been destroyed"))
    (let* ([len (secure-key-record-size sk)]
           [bv  (make-bytevector len 0)])
      (c-secmem-copy-out bv (secure-key-record-ptr sk) len)
      bv))

  ;; Destroy the key — zero and free the mlock'd memory.
  (define (secure-key-destroy! sk)
    (when (secure-key-record-live? sk)
      (secmem-free! (secure-key-record-ptr sk) (secure-key-record-size sk))
      (secure-key-record-ptr-set! sk 0)
      (secure-key-record-live?-set! sk #f)))

  ;; Run proc with the key as a temporary bytevector, guaranteed to be
  ;; zeroed afterward even if proc raises an exception.
  (define (call-with-secure-key sk proc)
    (unless (secure-key-record-live? sk)
      (error 'call-with-secure-key "key has been destroyed"))
    (let ([bv (secure-key-borrow sk)])
      (dynamic-wind
        (lambda () (void))
        (lambda () (proc bv))
        (lambda () (bytevector-fill! bv 0)))))

) ;; end library
