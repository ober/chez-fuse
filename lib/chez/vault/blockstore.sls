(library (chez vault blockstore)
  (export
    make-blockstore
    blockstore-create!       ;; path total-blocks → void (initializes bs)
    blockstore-open!         ;; path → total-blocks (opens existing file, sets bs fields)
    blockstore-close!
    blockstore-set-key!
    blockstore-clear-key!
    blockstore-read-header   ;; → 256-byte bv
    blockstore-write-header! ;; bv → void
    blockstore-read-block    ;; block-num → BLOCK-PAYLOAD bv or #f
    blockstore-write-block!  ;; block-num payload → void
    blockstore-sync!
    blockstore-total-blocks
    blockstore-key-live?)

  (import (chezscheme)
          (chez vault format)
          (chez vault crypto)
          (chez fuse mount)     ;; ensure shared lib loaded
          (chez fuse secmem))

  ;; ---- OS file I/O FFI ----
  ;; Load libc for pread, pwrite, open, close, fsync.

  (define _libc-loaded
    (begin
      (load-shared-object
        (case (machine-type)
          [(a6fb ta6fb i3fb ti3fb arm64fb tarm64fb) "libc.so.7"]
          [(a6le ta6le i3le ti3le arm64le tarm64le) "libc.so.6"]
          [else "libc.so"]))
      #t))

  (define c-open
    (foreign-procedure "open" (string int int) int))
  (define c-close
    (foreign-procedure "close" (int) int))
  (define c-pread
    (foreign-procedure "pread" (int u8* unsigned-64 integer-64) integer-64))
  (define c-pwrite
    (foreign-procedure "pwrite" (int u8* unsigned-64 integer-64) integer-64))
  (define c-fsync
    (foreign-procedure "fsync" (int) int))

  ;; Platform-specific open(2) flags
  (define O-RDWR  2)
  (define O-CREAT (case (machine-type)
                    [(a6fb ta6fb i3fb ti3fb arm64fb tarm64fb) #x200]  ;; FreeBSD
                    [else #x40]))  ;; Linux
  (define O-TRUNC (case (machine-type)
                    [(a6fb ta6fb i3fb ti3fb arm64fb tarm64fb) #x400]  ;; FreeBSD
                    [else #x200])) ;; Linux
  (define MODE-0600 #o600)

  ;; ---- Blockstore record ----

  (define-record-type blockstore-state
    (fields
      (mutable fd)
      (mutable total-blocks)
      (mutable master-key)   ;; #f or secure-key (mlock'd, outside GC heap)
      (mutable mutex)))

  (define (make-blockstore)
    (make-blockstore-state -1 0 #f (make-mutex)))

  (define (blockstore-total-blocks bs)
    (blockstore-state-total-blocks bs))

  ;; ---- File offset arithmetic ----

  (define (block-offset block-num)
    ;; Byte offset in file for block block-num (0-based)
    (+ HEADER-SIZE (* block-num BLOCK-SIZE)))

  ;; ---- Raw I/O ----

  (define (raw-read! bs offset bv)
    (let* ([fd  (blockstore-state-fd bs)]
           [len (bytevector-length bv)]
           [n   (c-pread fd bv len offset)])
      (unless (= n len)
        (error 'blockstore-raw-read "short read" n len offset))))

  (define (raw-write! bs offset bv)
    (let* ([fd  (blockstore-state-fd bs)]
           [len (bytevector-length bv)]
           [n   (c-pwrite fd bv len offset)])
      (unless (= n len)
        (error 'blockstore-raw-write "short write" n len offset))))

  ;; ---- Create ----

  (define (blockstore-create! bs path total-blocks)
    ;; Create a new vault file, pre-fill header + all blocks with random data.
    ;; The random fill makes free blocks indistinguishable from used ones.
    (let ([fd (c-open path (bitwise-ior O-RDWR O-CREAT O-TRUNC) MODE-0600)])
      (when (< fd 0)
        (error 'blockstore-create! "cannot create vault file" path))
      (blockstore-state-fd-set! bs fd)
      (blockstore-state-total-blocks-set! bs total-blocks)
      ;; Write 256-byte zero header (will be overwritten by vault-create!)
      (let ([hdr (make-bytevector HEADER-SIZE 0)])
        (c-pwrite fd hdr HEADER-SIZE 0))
      ;; Pre-fill blocks with random data (1 MB chunks)
      (let* ([chunk-blocks (min total-blocks (quotient (* 1024 1024) BLOCK-SIZE))]
             [chunk-bytes  (* chunk-blocks BLOCK-SIZE)])
        (let loop ([remaining total-blocks] [file-off HEADER-SIZE])
          (when (> remaining 0)
            (let* ([this-n  (min remaining chunk-blocks)]
                   [this-sz (* this-n BLOCK-SIZE)]
                   [data    (vault-rand-bytes this-sz)])
              (c-pwrite fd data this-sz file-off)
              (loop (- remaining this-n)
                    (+ file-off this-sz))))))))

  ;; ---- Open ----

  (define (blockstore-open! bs path)
    ;; Open existing vault file; read total-blocks from stored header.
    ;; Returns total-blocks.
    (let ([fd (c-open path O-RDWR 0)])
      (when (< fd 0)
        (error 'blockstore-open! "cannot open vault file" path))
      (blockstore-state-fd-set! bs fd)
      ;; Peek at header to get total_blocks (before we have the master key)
      (let ([hdr-bv (make-bytevector HEADER-SIZE 0)])
        (c-pread fd hdr-bv HEADER-SIZE 0)
        ;; Validate magic before trying to decode
        (let ([magic (bv-u32le hdr-bv 0)])
          (unless (= magic VAULT-MAGIC)
            (c-close fd)
            (error 'blockstore-open! "not a vault file (bad magic)" path)))
        ;; total_blocks is at offset 10
        (let ([total (bv-u64le hdr-bv 10)])
          (blockstore-state-total-blocks-set! bs total)
          total))))

  ;; ---- Close ----

  (define (blockstore-close! bs)
    (blockstore-clear-key! bs)
    (let ([fd (blockstore-state-fd bs)])
      (when (>= fd 0)
        (c-fsync fd)
        (c-close fd)
        (blockstore-state-fd-set! bs -1))))

  ;; ---- Key management ----
  ;; Master key is stored in mlock'd memory outside the GC heap.
  ;; It is never exposed as a plain bytevector at rest — only borrowed
  ;; temporarily for crypto operations, then immediately zeroed.

  (define (blockstore-set-key! bs key-bv)
    ;; Move the 32-byte master key into secure memory.
    ;; key-bv is zeroed by make-secure-key.
    (let ([old (blockstore-state-master-key bs)])
      (when old (secure-key-destroy! old)))
    (let ([copy (make-bytevector VAULT-KEY-LEN 0)])
      (bytevector-copy! key-bv 0 copy 0 VAULT-KEY-LEN)
      (blockstore-state-master-key-set! bs (make-secure-key copy))))

  (define (blockstore-clear-key! bs)
    ;; Securely destroy the master key (zeros mlock'd memory + munmap).
    (let ([sk (blockstore-state-master-key bs)])
      (when (and sk (secure-key? sk) (secure-key-live? sk))
        (secure-key-destroy! sk)))
    (blockstore-state-master-key-set! bs #f))

  (define (blockstore-key-live? bs)
    ;; Is the master key currently available?
    (let ([sk (blockstore-state-master-key bs)])
      (and sk (secure-key? sk) (secure-key-live? sk))))

  ;; ---- Header I/O (unencrypted) ----

  (define (blockstore-read-header bs)
    (let ([bv (make-bytevector HEADER-SIZE 0)])
      (raw-read! bs 0 bv)
      bv))

  (define (blockstore-write-header! bs bv)
    (raw-write! bs 0 bv))

  ;; ---- Block I/O (encrypted) ----
  ;; The master key is borrowed from secure memory only for the duration
  ;; of the crypto operation. The temporary bytevector is zeroed afterward.

  (define (blockstore-read-block bs block-num)
    ;; Returns decrypted BLOCK-PAYLOAD-byte bv, or #f on auth failure / I/O error.
    (with-mutex (blockstore-state-mutex bs)
      (let ([sk (blockstore-state-master-key bs)])
        (and sk (secure-key? sk) (secure-key-live? sk)
             (let* ([raw-bv (make-bytevector BLOCK-SIZE 0)]
                    [offset (block-offset block-num)])
               (guard (exn [#t #f])
                 (raw-read! bs offset raw-bv)
                 (call-with-secure-key sk
                   (lambda (mk-bv)
                     (let* ([bk  (vault-block-key mk-bv block-num)]
                            [result (vault-decrypt-block bk raw-bv)])
                       (bytevector-fill! bk 0)
                       result)))))))))

  (define (blockstore-write-block! bs block-num payload-bv)
    ;; Encrypts payload and writes to disk. payload-bv must be BLOCK-PAYLOAD bytes.
    (with-mutex (blockstore-state-mutex bs)
      (let ([sk (blockstore-state-master-key bs)])
        (unless (and sk (secure-key? sk) (secure-key-live? sk))
          (error 'blockstore-write-block! "no master key set"))
        (unless (= (bytevector-length payload-bv) BLOCK-PAYLOAD)
          (error 'blockstore-write-block! "wrong payload size"
                 (bytevector-length payload-bv)))
        (call-with-secure-key sk
          (lambda (mk-bv)
            (let* ([bk        (vault-block-key mk-bv block-num)]
                   [encrypted (vault-encrypt-block bk payload-bv)]
                   [offset    (block-offset block-num)])
              (bytevector-fill! bk 0)
              (raw-write! bs offset encrypted)))))))

  ;; ---- Sync ----

  (define (blockstore-sync! bs)
    (let ([fd (blockstore-state-fd bs)])
      (when (>= fd 0)
        (c-fsync fd))))

) ;; end library
