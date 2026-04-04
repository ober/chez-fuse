(library (chez fuse codec)
  (export
    ;; Decoders
    decode-in-header
    decode-init-in
    decode-getattr-in
    decode-setattr-in
    decode-open-in
    decode-read-in
    decode-write-in
    decode-release-in
    decode-flush-in
    decode-fsync-in
    decode-mkdir-in
    decode-mknod-in
    decode-rename-in
    decode-link-in
    decode-create-in
    decode-access-in
    decode-forget-in
    decode-batch-forget-in
    decode-interrupt-in
    decode-lseek-in
    decode-fallocate-in
    extract-name           ;; extract null-terminated name from buffer
    extract-two-names      ;; extract two null-terminated names (symlink, rename)

    ;; Encoders
    encode-out-header
    encode-error
    encode-attr-out
    encode-entry-out
    encode-open-out
    encode-write-out
    encode-statfs-out
    encode-init-out
    encode-lseek-out
    encode-readlink-out
    encode-dirent          ;; single directory entry
    encode-dirents         ;; pack list of dirents into buffer

    ;; Sizes
    FUSE-ATTR-SIZE
    FUSE-ENTRY-OUT-SIZE
    FUSE-ATTR-OUT-SIZE
    FUSE-OPEN-OUT-SIZE
    FUSE-WRITE-OUT-SIZE
    FUSE-STATFS-OUT-SIZE
    FUSE-INIT-OUT-SIZE
    FUSE-DIRENT-HEADER-SIZE)

  (import
    (rnrs)
    (chez fuse constants)
    (chez fuse types))

  ;; ---- Struct sizes ----
  (define FUSE-ATTR-SIZE           88)
  (define FUSE-ENTRY-OUT-SIZE     128)  ;; 40 + 88
  (define FUSE-ATTR-OUT-SIZE      104)  ;; 16 + 88
  (define FUSE-OPEN-OUT-SIZE       16)
  (define FUSE-WRITE-OUT-SIZE       8)
  (define FUSE-STATFS-OUT-SIZE     80)
  (define FUSE-INIT-OUT-SIZE       64)
  (define FUSE-DIRENT-HEADER-SIZE  24)  ;; ino(8) + off(8) + namelen(4) + type(4)
  (define FUSE-LSEEK-OUT-SIZE       8)

  ;; ---- Native byte order helpers ----
  ;; FUSE protocol is always host-endian (kernel and daemon on same machine).
  (define (u32-ref bv off) (bytevector-u32-native-ref bv off))
  (define (u64-ref bv off) (bytevector-u64-native-ref bv off))
  (define (s32-ref bv off) (bytevector-s32-native-ref bv off))

  (define (u32-set! bv off v) (bytevector-u32-native-set! bv off v))
  (define (u64-set! bv off v) (bytevector-u64-native-set! bv off v))
  (define (s32-set! bv off v) (bytevector-s32-native-set! bv off v))
  (define (u16-set! bv off v) (bytevector-u16-native-set! bv off v))

  ;; ========================================================================
  ;; DECODERS — parse incoming request payloads from raw buffer
  ;; All offsets are relative to start of payload (after in-header at byte 40).
  ;; ========================================================================

  ;; Decode the 40-byte fuse_in_header.
  (define (decode-in-header buf)
    (make-fuse-request
      (u32-ref buf 0)    ;; len
      (u32-ref buf 4)    ;; opcode
      (u64-ref buf 8)    ;; unique
      (u64-ref buf 16)   ;; nodeid
      (u32-ref buf 24)   ;; uid
      (u32-ref buf 28)   ;; gid
      (u32-ref buf 32))) ;; pid

  ;; FUSE_INIT (opcode 26) — returns (values major minor max-readahead flags)
  (define (decode-init-in buf off)
    (values
      (u32-ref buf off)          ;; major
      (u32-ref buf (+ off 4))   ;; minor
      (u32-ref buf (+ off 8))   ;; max_readahead
      (u32-ref buf (+ off 12)))) ;; flags

  ;; FUSE_GETATTR (opcode 3) — returns (values getattr-flags fh)
  (define (decode-getattr-in buf off)
    (values
      (u32-ref buf off)           ;; getattr_flags
      (u64-ref buf (+ off 8))))  ;; fh

  ;; FUSE_SETATTR (opcode 4) — returns (values valid fh size atime mtime ctime
  ;;   atimensec mtimensec ctimensec mode uid gid)
  (define (decode-setattr-in buf off)
    (values
      (u32-ref buf off)            ;; valid (FATTR_* bitmask)
      (u64-ref buf (+ off 8))    ;; fh
      (u64-ref buf (+ off 16))   ;; size
      (u64-ref buf (+ off 32))   ;; atime
      (u64-ref buf (+ off 40))   ;; mtime
      (u64-ref buf (+ off 48))   ;; ctime
      (u32-ref buf (+ off 56))   ;; atimensec
      (u32-ref buf (+ off 60))   ;; mtimensec
      (u32-ref buf (+ off 64))   ;; ctimensec
      (u32-ref buf (+ off 68))   ;; mode
      (u32-ref buf (+ off 76))   ;; uid
      (u32-ref buf (+ off 80)))) ;; gid

  ;; FUSE_OPEN / FUSE_OPENDIR (opcode 14, 27) — returns (values flags open-flags)
  (define (decode-open-in buf off)
    (values
      (u32-ref buf off)           ;; flags (open(2) flags)
      (u32-ref buf (+ off 4))))  ;; open_flags

  ;; FUSE_READ / FUSE_READDIR (opcode 15, 28) — returns (values fh offset size read-flags)
  (define (decode-read-in buf off)
    (values
      (u64-ref buf off)            ;; fh
      (u64-ref buf (+ off 8))    ;; offset
      (u32-ref buf (+ off 16))   ;; size
      (u32-ref buf (+ off 20)))) ;; read_flags

  ;; FUSE_WRITE (opcode 16) — returns (values fh offset size write-flags)
  ;; Write data follows at (+ off 40).
  (define (decode-write-in buf off)
    (values
      (u64-ref buf off)            ;; fh
      (u64-ref buf (+ off 8))    ;; offset
      (u32-ref buf (+ off 16))   ;; size
      (u32-ref buf (+ off 20)))) ;; write_flags

  ;; FUSE_RELEASE / FUSE_RELEASEDIR (opcode 18, 29) — returns (values fh flags)
  (define (decode-release-in buf off)
    (values
      (u64-ref buf off)            ;; fh
      (u32-ref buf (+ off 8))))  ;; flags

  ;; FUSE_FLUSH (opcode 25) — returns (values fh lock-owner)
  (define (decode-flush-in buf off)
    (values
      (u64-ref buf off)             ;; fh
      (u64-ref buf (+ off 16))))   ;; lock_owner

  ;; FUSE_FSYNC / FUSE_FSYNCDIR (opcode 20, 30) — returns (values fh fsync-flags)
  (define (decode-fsync-in buf off)
    (values
      (u64-ref buf off)            ;; fh
      (u32-ref buf (+ off 8))))  ;; fsync_flags

  ;; FUSE_MKDIR (opcode 9) — returns (values mode umask)
  ;; Name follows at (+ off 8).
  (define (decode-mkdir-in buf off)
    (values
      (u32-ref buf off)           ;; mode
      (u32-ref buf (+ off 4))))  ;; umask

  ;; FUSE_MKNOD (opcode 8) — returns (values mode rdev umask)
  ;; Name follows at (+ off 16).
  (define (decode-mknod-in buf off)
    (values
      (u32-ref buf off)            ;; mode
      (u32-ref buf (+ off 4))    ;; rdev
      (u32-ref buf (+ off 8))))  ;; umask

  ;; FUSE_RENAME (opcode 12) — returns newdir
  ;; Old name and new name follow as two null-terminated strings.
  (define (decode-rename-in buf off)
    (u64-ref buf off))   ;; newdir nodeid

  ;; FUSE_LINK (opcode 13) — returns oldnodeid
  ;; New name follows as null-terminated string.
  (define (decode-link-in buf off)
    (u64-ref buf off))   ;; oldnodeid

  ;; FUSE_CREATE (opcode 35) — returns (values flags mode umask open-flags)
  ;; Name follows at (+ off 16).
  (define (decode-create-in buf off)
    (values
      (u32-ref buf off)            ;; flags (open(2))
      (u32-ref buf (+ off 4))    ;; mode
      (u32-ref buf (+ off 8))    ;; umask
      (u32-ref buf (+ off 12)))) ;; open_flags

  ;; FUSE_ACCESS (opcode 34) — returns mask
  (define (decode-access-in buf off)
    (u32-ref buf off))   ;; mask (R_OK | W_OK | X_OK | F_OK)

  ;; FUSE_FORGET (opcode 2) — returns nlookup
  (define (decode-forget-in buf off)
    (u64-ref buf off))   ;; nlookup

  ;; FUSE_BATCH_FORGET (opcode 42) — returns list of (nodeid . nlookup)
  (define (decode-batch-forget-in buf off)
    (let ([count (u32-ref buf off)])
      (let loop ([i 0] [pos (+ off 8)] [acc '()])
        (if (= i count)
          (reverse acc)
          (loop (+ i 1) (+ pos 16)
                (cons (cons (u64-ref buf pos)
                            (u64-ref buf (+ pos 8)))
                      acc))))))

  ;; FUSE_INTERRUPT (opcode 36) — returns unique-id of request to interrupt
  (define (decode-interrupt-in buf off)
    (u64-ref buf off))

  ;; FUSE_LSEEK (opcode 46) — returns (values fh offset whence)
  (define (decode-lseek-in buf off)
    (values
      (u64-ref buf off)
      (u64-ref buf (+ off 8))
      (u32-ref buf (+ off 16))))

  ;; FUSE_FALLOCATE (opcode 43) — returns (values fh offset length mode)
  (define (decode-fallocate-in buf off)
    (values
      (u64-ref buf off)
      (u64-ref buf (+ off 8))
      (u64-ref buf (+ off 16))
      (u32-ref buf (+ off 24))))

  ;; ---- Name extraction helpers ----

  ;; Extract a null-terminated string starting at offset in buf.
  ;; Returns the string (not including the null terminator).
  (define (extract-name buf off limit)
    (let loop ([end off])
      (cond
        [(>= end limit) (utf8->string (bv-slice buf off end))]
        [(= (bytevector-u8-ref buf end) 0)
         (utf8->string (bv-slice buf off end))]
        [else (loop (+ end 1))])))

  ;; Extract two consecutive null-terminated strings starting at offset.
  ;; Returns (values name1 name2). Used by SYMLINK and RENAME.
  (define (extract-two-names buf off limit)
    (let ([name1-end
           (let loop ([i off])
             (cond
               [(>= i limit) i]
               [(= (bytevector-u8-ref buf i) 0) i]
               [else (loop (+ i 1))]))])
      (let ([name1 (utf8->string (bv-slice buf off name1-end))]
            [name2-start (+ name1-end 1)])
        (let ([name2 (extract-name buf name2-start limit)])
          (values name1 name2)))))

  ;; Helper: copy a sub-range of a bytevector.
  (define (bv-slice bv start end)
    (let* ([len (- end start)]
           [result (make-bytevector len)])
      (bytevector-copy! bv start result 0 len)
      result))

  ;; ========================================================================
  ;; ENCODERS — build response bytevectors
  ;; ========================================================================

  ;; Encode a 16-byte fuse_out_header.
  (define (encode-out-header unique error payload-size)
    (let ([bv (make-bytevector FUSE-OUT-HEADER-SIZE 0)])
      (u32-set! bv 0 (+ FUSE-OUT-HEADER-SIZE payload-size))  ;; len
      (s32-set! bv 4 error)                                    ;; error
      (u64-set! bv 8 unique)                                   ;; unique
      bv))

  ;; Encode an error-only response (no payload).
  (define (encode-error unique errno-val)
    (encode-out-header unique (- errno-val) 0))

  ;; Encode fuse_attr (88 bytes) into bv at offset.
  (define (encode-attr! bv off attr)
    (u64-set! bv off       (fuse-attr-ino attr))
    (u64-set! bv (+ off 8)  (fuse-attr-size attr))
    (u64-set! bv (+ off 16) (fuse-attr-blocks attr))
    (u64-set! bv (+ off 24) (fuse-attr-atime attr))
    (u64-set! bv (+ off 32) (fuse-attr-mtime attr))
    (u64-set! bv (+ off 40) (fuse-attr-ctime attr))
    (u32-set! bv (+ off 48) (fuse-attr-atimensec attr))
    (u32-set! bv (+ off 52) (fuse-attr-mtimensec attr))
    (u32-set! bv (+ off 56) (fuse-attr-ctimensec attr))
    (u32-set! bv (+ off 60) (fuse-attr-mode attr))
    (u32-set! bv (+ off 64) (fuse-attr-nlink attr))
    (u32-set! bv (+ off 68) (fuse-attr-uid attr))
    (u32-set! bv (+ off 72) (fuse-attr-gid attr))
    (u32-set! bv (+ off 76) (fuse-attr-rdev attr))
    (u32-set! bv (+ off 80) (fuse-attr-blksize attr))
    (u32-set! bv (+ off 84) 0))  ;; flags (padding for compat)

  ;; Encode fuse_attr_out: 16 bytes header + 88 bytes attr = 104 bytes payload.
  ;; Returns complete response bytevector (header + payload).
  (define (encode-attr-out unique attr-valid attr-valid-nsec attr)
    (let* ([payload-size FUSE-ATTR-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      ;; out_header
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)           ;; error = 0
      (u64-set! bv 8 unique)
      ;; attr_out header
      (u64-set! bv 16 attr-valid)
      (u32-set! bv 24 attr-valid-nsec)
      ;; bv[28..31] = dummy/padding (already 0)
      ;; attr at offset 32
      (encode-attr! bv 32 attr)
      bv))

  ;; Encode fuse_entry_out: 128 bytes payload.
  ;; Returns complete response bytevector.
  (define (encode-entry-out unique entry)
    (let* ([payload-size FUSE-ENTRY-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      ;; out_header
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      ;; entry_out
      (u64-set! bv 16 (fuse-entry-nodeid entry))
      (u64-set! bv 24 (fuse-entry-generation entry))
      (u64-set! bv 32 (fuse-entry-entry-valid entry))
      (u64-set! bv 40 (fuse-entry-attr-valid entry))
      (u32-set! bv 48 (fuse-entry-entry-valid-nsec entry))
      (u32-set! bv 52 (fuse-entry-attr-valid-nsec entry))
      ;; attr at offset 56
      (encode-attr! bv 56 (fuse-entry-attr entry))
      bv))

  ;; Encode fuse_open_out: 16 bytes payload.
  (define (encode-open-out unique fh open-flags)
    (let* ([payload-size FUSE-OPEN-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      (u64-set! bv 16 fh)
      (u32-set! bv 24 open-flags)
      ;; bv[28..31] = padding
      bv))

  ;; Encode fuse_write_out: 8 bytes payload.
  (define (encode-write-out unique size)
    (let* ([payload-size FUSE-WRITE-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      (u32-set! bv 16 size)
      ;; bv[20..23] = padding
      bv))

  ;; Encode fuse_statfs_out (fuse_kstatfs): 80 bytes payload.
  (define (encode-statfs-out unique st)
    (let* ([payload-size FUSE-STATFS-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      (u64-set! bv 16 (fuse-statfs-blocks st))
      (u64-set! bv 24 (fuse-statfs-bfree st))
      (u64-set! bv 32 (fuse-statfs-bavail st))
      (u64-set! bv 40 (fuse-statfs-files st))
      (u64-set! bv 48 (fuse-statfs-ffree st))
      (u32-set! bv 56 (fuse-statfs-bsize st))
      (u32-set! bv 60 (fuse-statfs-namelen st))
      (u32-set! bv 64 (fuse-statfs-frsize st))
      ;; bv[68..95] = padding/spare
      bv))

  ;; Encode fuse_init_out: 64 bytes payload.
  (define (encode-init-out unique major minor max-readahead flags max-write)
    (let* ([payload-size FUSE-INIT-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      ;; init_out payload at offset 16
      (u32-set! bv 16 major)
      (u32-set! bv 20 minor)
      (u32-set! bv 24 max-readahead)
      (u32-set! bv 28 flags)
      (u16-set! bv 32 32)   ;; max_background
      (u16-set! bv 34 24)   ;; congestion_threshold
      (u32-set! bv 36 max-write)
      (u32-set! bv 40 1)    ;; time_gran = 1ns
      ;; rest is zeros (unused)
      bv))

  ;; Encode fuse_lseek_out: 8 bytes payload.
  (define (encode-lseek-out unique offset)
    (let* ([payload-size FUSE-LSEEK-OUT-SIZE]
           [total (+ FUSE-OUT-HEADER-SIZE payload-size)]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      (u64-set! bv 16 offset)
      bv))

  ;; Encode readlink response: raw string data.
  (define (encode-readlink-out unique target)
    (let* ([data (string->utf8 target)]
           [total (+ FUSE-OUT-HEADER-SIZE (bytevector-length data))]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      (bytevector-copy! data 0 bv FUSE-OUT-HEADER-SIZE (bytevector-length data))
      bv))

  ;; Encode a single fuse_dirent into a bytevector.
  ;; Returns the bytevector (8-byte aligned).
  (define (encode-dirent dirent)
    (let* ([name-bv (string->utf8 (fuse-dirent-name dirent))]
           [namelen (bytevector-length name-bv)]
           [reclen (fuse-rec-align (+ FUSE-DIRENT-HEADER-SIZE namelen))]
           [bv (make-bytevector reclen 0)])
      (u64-set! bv 0 (fuse-dirent-ino dirent))
      (u64-set! bv 8 (fuse-dirent-off dirent))
      (u32-set! bv 16 namelen)
      (u32-set! bv 20 (fuse-dirent-type dirent))
      (bytevector-copy! name-bv 0 bv 24 namelen)
      bv))

  ;; Pack a list of fuse-dirent records into a single response bytevector
  ;; that fits within max-size bytes. Returns complete response (header + dirents).
  (define (encode-dirents unique dirents max-size)
    (let loop ([ds dirents] [chunks '()] [total-payload 0])
      (if (null? ds)
        (finalize-dirents unique (reverse chunks) total-payload)
        (let* ([encoded (encode-dirent (car ds))]
               [elen (bytevector-length encoded)]
               [new-total (+ total-payload elen)])
          (if (> new-total max-size)
            (finalize-dirents unique (reverse chunks) total-payload)
            (loop (cdr ds) (cons encoded chunks) new-total))))))

  ;; Assemble header + dirent chunks into a single bytevector.
  (define (finalize-dirents unique chunks total-payload)
    (let* ([total (+ FUSE-OUT-HEADER-SIZE total-payload)]
           [bv (make-bytevector total 0)])
      (u32-set! bv 0 total)
      (s32-set! bv 4 0)
      (u64-set! bv 8 unique)
      (let loop ([cs chunks] [pos FUSE-OUT-HEADER-SIZE])
        (unless (null? cs)
          (let ([chunk (car cs)])
            (bytevector-copy! chunk 0 bv pos (bytevector-length chunk))
            (loop (cdr cs) (+ pos (bytevector-length chunk))))))
      bv))

) ;; end library
