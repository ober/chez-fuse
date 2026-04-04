(library (chez fuse mount)
  (export
    fuse-open-device
    fuse-mount!
    fuse-unmount!
    fuse-unmount-lazy!
    fuse-get-errno
    fuse-close-device
    fuse-block-signal
    fuse-unblock-signal

    ;; Ensure the shared library is loaded (used by secmem, access)
    ensure-mount-lib!)

  (import
    (rnrs)
    (only (chezscheme)
          load-shared-object foreign-procedure
          format))

  ;; Load the C mount helper shared library.
  (define mount-lib-loaded?
    (let ([loaded #f])
      (lambda ()
        (unless loaded
          (guard (exn [else
            (guard (exn2 [else
              (guard (exn3 [else
                (error 'chez-fuse
                  "cannot load libchez_fuse_mount.so — run 'make' first")])
                (load-shared-object "libchez_fuse_mount.so"))])
              (load-shared-object "./src/libchez_fuse_mount.so"))])
            (load-shared-object "./libchez_fuse_mount.so"))
          (set! loaded #t)))))

  ;; Public: ensure the shared lib is loaded (called by secmem, access modules)
  (define (ensure-mount-lib!)
    (mount-lib-loaded?))

  ;; FFI bindings
  (define c-open-device #f)
  (define c-mount #f)
  (define c-unmount #f)
  (define c-unmount-lazy #f)
  (define c-get-errno #f)
  (define c-close #f)
  (define c-block-signal #f)
  (define c-unblock-signal #f)

  (define (ensure-ffi!)
    (mount-lib-loaded?)
    (unless c-open-device
      (set! c-open-device
        (foreign-procedure "chez_fuse_open_device" () int))
      (set! c-mount
        (foreign-procedure "chez_fuse_mount" (int string string int int int) int))
      (set! c-unmount
        (foreign-procedure "chez_fuse_unmount" (string) int))
      (set! c-unmount-lazy
        (foreign-procedure "chez_fuse_unmount_lazy" (string) int))
      (set! c-get-errno
        (foreign-procedure "chez_fuse_get_errno" () int))
      (set! c-close
        (foreign-procedure "close" (int) int))
      (set! c-block-signal
        (foreign-procedure "chez_fuse_block_signal" (int) int))
      (set! c-unblock-signal
        (foreign-procedure "chez_fuse_unblock_signal" (int) int))))

  ;; Open /dev/fuse. Returns the file descriptor or raises an error.
  (define (fuse-open-device)
    (ensure-ffi!)
    (let ([fd (c-open-device)])
      (when (< fd 0)
        (error 'fuse-open-device
          (format "failed to open /dev/fuse (errno ~a)" (c-get-errno))))
      fd))

  ;; Mount the FUSE filesystem at mountpoint.
  ;; allow-other?: if #t, other users can access the mount
  (define (fuse-mount! fd mountpoint fsname uid gid allow-other?)
    (ensure-ffi!)
    (let ([rc (c-mount fd mountpoint fsname uid gid (if allow-other? 1 0))])
      (when (< rc 0)
        (let ([err (c-get-errno)])
          (error 'fuse-mount!
            (format "mount failed at ~a (errno ~a)" mountpoint err))))))

  ;; Unmount the filesystem.
  (define (fuse-unmount! mountpoint)
    (ensure-ffi!)
    (c-unmount mountpoint))

  ;; Lazy/forced unmount (for cleanup).
  (define (fuse-unmount-lazy! mountpoint)
    (ensure-ffi!)
    (c-unmount-lazy mountpoint))

  ;; Get the current C errno value.
  (define (fuse-get-errno)
    (ensure-ffi!)
    (c-get-errno))

  ;; Close the /dev/fuse file descriptor.
  (define (fuse-close-device fd)
    (ensure-ffi!)
    (c-close fd))

  ;; Signal management for clean shutdown.
  (define (fuse-block-signal signum)
    (ensure-ffi!)
    (c-block-signal signum))

  (define (fuse-unblock-signal signum)
    (ensure-ffi!)
    (c-unblock-signal signum))

) ;; end library
