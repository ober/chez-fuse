(library (chez vault)
  (export
    ;; Lifecycle
    vault-create!      ;; path passphrase total-blocks → vault
    vault-open         ;; path passphrase → vault
    vault-close!       ;; vault → void
    vault-lock!        ;; vault → void (clear key, deny all I/O)
    vault-unlock!      ;; vault passphrase → void (re-derive key)
    vault-locked?      ;; vault → boolean
    vault->fuse-ops    ;; vault → ops-hashtable (with access gating)
    ;; Shell integration
    vault-mount!       ;; path passphrase mountpoint . opts → (cons vault session)
    vault-unmount!)    ;; (cons vault session) → void

  (import
    (chezscheme)
    (chez fuse)
    (chez fuse constants)
    (chez fuse types)
    (chez fuse access)
    (chez fuse secmem)
    (chez vault format)
    (chez vault crypto)
    (chez vault blockstore))

  ;; ======================================================================
  ;; In-memory inode record
  ;; inode-num == block-num == FUSE ino (identity mapping)
  ;; ======================================================================

  (define-record-type vault-inode
    (fields
      (mutable ino)       ;; block-num = FUSE ino
      (mutable type)
      (mutable mode)
      (mutable uid)
      (mutable gid)
      (mutable size)
      (mutable ctime)
      (mutable mtime)
      (mutable atime)
      (mutable nlink)
      (mutable name-bv)  ;; bytevector
      (mutable direct)   ;; vector of DIRECT-BLOCKS u64 block numbers
      (mutable indirect) ;; u64 block number
      ))

  ;; ======================================================================
  ;; Vault state record
  ;; ======================================================================

  (define-record-type vault-state
    (fields
      (mutable bs)              ;; blockstore-state
      (mutable master-key)      ;; secure-key (mlock'd) — also set in bs
      (mutable root-block)      ;; block-num of root inode
      (mutable bitmap-start)    ;; first bitmap block number
      (mutable bitmap-nblocks)  ;; number of bitmap blocks
      (mutable generation)      ;; superblock generation counter
      (mutable policy-block)    ;; block-num for persistent policies (or VAULT-BLOCK-INVALID)
      (mutable bitmap)          ;; flat bytevector, in-memory
      (mutable bitmap-dirty?)
      (mutable next-fh)         ;; file handle counter
      (mutable open-fhs)        ;; eq-hashtable: fh -> inode-block-num
      (mutable access)          ;; access-controller (or #f)
      (mutable header-bv)       ;; cached raw header (for lock/unlock re-derive)
      (mutable mutex)))

  ;; ======================================================================
  ;; Inode read/write
  ;; ======================================================================

  (define (read-inode vault block-num)
    (let ([payload (blockstore-read-block (vault-state-bs vault) block-num)])
      (and payload
           (let-values ([(inum type mode uid gid size ctime mtime atime nlink nbv direct indirect)
                         (decode-inode payload)])
             (make-vault-inode inum type mode uid gid size ctime mtime atime nlink nbv direct indirect)))))

  (define (write-inode! vault inode)
    (blockstore-write-block!
      (vault-state-bs vault)
      (vault-inode-ino inode)
      (encode-inode
        (vault-inode-ino      inode)
        (vault-inode-type     inode)
        (vault-inode-mode     inode)
        (vault-inode-uid      inode)
        (vault-inode-gid      inode)
        (vault-inode-size     inode)
        (vault-inode-ctime    inode)
        (vault-inode-mtime    inode)
        (vault-inode-atime    inode)
        (vault-inode-nlink    inode)
        (vault-inode-name-bv  inode)
        (vault-inode-direct   inode)
        (vault-inode-indirect inode))))

  (define (inode->fuse-attr inode)
    (make-fuse-attr
      (vault-inode-ino inode)
      (vault-inode-size inode)
      (quotient (+ (vault-inode-size inode) 511) 512)
      (vault-inode-atime inode) (vault-inode-mtime inode) (vault-inode-ctime inode)
      0 0 0
      (vault-inode-mode inode)
      (vault-inode-nlink inode)
      (vault-inode-uid inode) (vault-inode-gid inode)
      0 BLOCK-SIZE))

  (define (inode->fuse-entry inode)
    (make-fuse-entry
      (vault-inode-ino inode) 0
      1 0 1 0
      (inode->fuse-attr inode)))

  ;; ======================================================================
  ;; Bitmap operations
  ;; ======================================================================

  (define (bitmap-get vault n)
    (let* ([bm    (vault-state-bitmap vault)]
           [byte  (quotient n 8)]
           [bit   (remainder n 8)])
      (and (< byte (bytevector-length bm))
           (not (zero? (bitwise-and (bytevector-u8-ref bm byte)
                                    (bitwise-arithmetic-shift-left 1 bit)))))))

  (define (bitmap-set! vault n used?)
    (let* ([bm   (vault-state-bitmap vault)]
           [byte (quotient n 8)]
           [bit  (remainder n 8)]
           [old  (bytevector-u8-ref bm byte)]
           [mask (bitwise-arithmetic-shift-left 1 bit)])
      (bytevector-u8-set! bm byte
        (if used?
          (bitwise-ior old mask)
          (bitwise-and old (bitwise-not mask))))
      (vault-state-bitmap-dirty?-set! vault #t)))

  (define (bitmap-alloc! vault)
    ;; Linear scan: find first free bit, mark it used, return block number.
    (let* ([total (blockstore-total-blocks (vault-state-bs vault))]
           [bm    (vault-state-bitmap vault)]
           [bm-bytes (bytevector-length bm)])
      (let loop ([byte-idx 0])
        (cond
          [(>= (* byte-idx 8) total) #f]   ;; vault full
          [(>= byte-idx bm-bytes) #f]
          [(= (bytevector-u8-ref bm byte-idx) #xff)
           (loop (+ byte-idx 1))]
          [else
           ;; Find free bit in this byte
           (let bit-loop ([bit 0])
             (if (= bit 8) (loop (+ byte-idx 1))
               (let ([n (+ (* byte-idx 8) bit)])
                 (if (and (< n total)
                          (zero? (bitwise-and (bytevector-u8-ref bm byte-idx)
                                              (bitwise-arithmetic-shift-left 1 bit))))
                   (begin
                     (bitmap-set! vault n #t)
                     n)
                   (bit-loop (+ bit 1))))))]))))

  (define (bitmap-free! vault n)
    (bitmap-set! vault n #f))

  (define (flush-bitmap! vault)
    (when (vault-state-bitmap-dirty? vault)
      (let ([bm     (vault-state-bitmap vault)]
            [start  (vault-state-bitmap-start vault)]
            [nblks  (vault-state-bitmap-nblocks vault)])
        (let loop ([i 0])
          (when (< i nblks)
            (let* ([src-off (* i BLOCK-PAYLOAD)]
                   [src-end (min (bytevector-length bm) (+ src-off BLOCK-PAYLOAD))]
                   [src-len (- src-end src-off)]
                   [block   (make-bytevector BLOCK-PAYLOAD 0)])
              (when (> src-len 0)
                (bytevector-copy! bm src-off block 0 src-len))
              (blockstore-write-block! (vault-state-bs vault) (+ start i) block)
              (loop (+ i 1)))))
        (vault-state-bitmap-dirty?-set! vault #f))))

  (define (flush-superblock! vault)
    (let ([gen (+ (vault-state-generation vault) 1)])
      (vault-state-generation-set! vault gen)
      (blockstore-write-block!
        (vault-state-bs vault) 0
        (encode-superblock
          (vault-state-root-block vault)
          (vault-state-bitmap-start vault)
          (vault-state-bitmap-nblocks vault)
          gen
          (vault-state-policy-block vault)))))

  ;; ======================================================================
  ;; File handle management
  ;; ======================================================================

  (define (alloc-fh! vault block-num)
    (let ([fh (vault-state-next-fh vault)])
      (vault-state-next-fh-set! vault (+ fh 1))
      (eq-hashtable-set! (vault-state-open-fhs vault) fh block-num)
      fh))

  (define (release-fh! vault fh)
    (hashtable-delete! (vault-state-open-fhs vault) fh))

  ;; ======================================================================
  ;; Block allocation helpers
  ;; ======================================================================

  (define (alloc-zero-block! vault)
    ;; Allocate a block, write zeros, return block number.
    (let ([n (bitmap-alloc! vault)])
      (when n
        (blockstore-write-block! (vault-state-bs vault) n
                                 (make-bytevector BLOCK-PAYLOAD 0)))
      n))

  (define (alloc-invalid-indirect-block! vault)
    ;; Allocate an indirect block filled with VAULT-BLOCK-INVALID (all 0xFF bytes).
    ;; Each 8-byte slot = 0xFFFFFFFFFFFFFFFF
    (let ([n (bitmap-alloc! vault)])
      (when n
        (blockstore-write-block! (vault-state-bs vault) n
                                 (make-bytevector BLOCK-PAYLOAD #xff)))
      n))

  ;; ======================================================================
  ;; Data block resolution (file/dir inode → physical block number)
  ;; ======================================================================

  (define (resolve-data-block vault inode logical-idx)
    ;; Returns physical block number or #f (not allocated).
    (if (< logical-idx DIRECT-BLOCKS)
      (let ([blk (vector-ref (vault-inode-direct inode) logical-idx)])
        (if (= blk VAULT-BLOCK-INVALID) #f blk))
      (let ([ind-blk (vault-inode-indirect inode)])
        (if (= ind-blk VAULT-BLOCK-INVALID) #f
          (let ([ind-pay (blockstore-read-block (vault-state-bs vault) ind-blk)])
            (and ind-pay
                 (let ([ptr-idx (- logical-idx DIRECT-BLOCKS)]
                       )
                   (if (>= ptr-idx PTRS-PER-BLOCK) #f
                     (let ([blk (bv-u64le ind-pay (* ptr-idx 8))])
                       (if (= blk VAULT-BLOCK-INVALID) #f blk))))))))))

  (define (ensure-data-block! vault inode-block-num inode logical-idx)
    ;; Get existing block or allocate a new one; returns physical block number.
    (let ([existing (resolve-data-block vault inode logical-idx)])
      (if existing existing
        (let ([new-blk (alloc-zero-block! vault)])
          (when new-blk
            (if (< logical-idx DIRECT-BLOCKS)
              (begin
                (vector-set! (vault-inode-direct inode) logical-idx new-blk)
                (write-inode! vault inode))
              ;; Need indirect pointer
              (begin
                (when (= (vault-inode-indirect inode) VAULT-BLOCK-INVALID)
                  (let ([ind (alloc-invalid-indirect-block! vault)])
                    (when ind
                      (vault-inode-indirect-set! inode ind)
                      (write-inode! vault inode))))
                (let ([ind-blk (vault-inode-indirect inode)])
                  (when (not (= ind-blk VAULT-BLOCK-INVALID))
                    (let ([ind-pay (blockstore-read-block (vault-state-bs vault) ind-blk)])
                      (when ind-pay
                        (let ([ptr-idx (- logical-idx DIRECT-BLOCKS)])
                          (bv-set-u64le! ind-pay (* ptr-idx 8) new-blk)
                          (blockstore-write-block! (vault-state-bs vault) ind-blk ind-pay)))))))))
          new-blk))))

  ;; ======================================================================
  ;; File data read / write
  ;; ======================================================================

  (define (file-read vault inode size offset)
    (let* ([file-sz (vault-inode-size inode)]
           [start   (min offset file-sz)]
           [count   (min size (- file-sz start))])
      (if (<= count 0)
        (make-bytevector 0)
        (let ([result (make-bytevector count 0)])
          (let loop ([remaining count] [fpos start] [rpos 0])
            (when (> remaining 0)
              (let* ([lidx    (quotient fpos BLOCK-PAYLOAD)]
                     [boff    (remainder fpos BLOCK-PAYLOAD)]
                     [phys    (resolve-data-block vault inode lidx)]
                     [to-copy (min remaining (- BLOCK-PAYLOAD boff))])
                (when phys
                  (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
                    (when pay
                      (bytevector-copy! pay boff result rpos to-copy))))
                (loop (- remaining to-copy)
                      (+ fpos to-copy)
                      (+ rpos to-copy)))))
          result))))

  (define (file-write! vault inode-block-num inode data offset)
    ;; Write data at offset; extend file if necessary.
    ;; Returns number of bytes written.
    (let* ([write-len (bytevector-length data)]
           [new-end   (+ offset write-len)])
      (let loop ([written 0])
        (when (< written write-len)
          (let* ([fpos    (+ offset written)]
                 [lidx    (quotient fpos BLOCK-PAYLOAD)]
                 [boff    (remainder fpos BLOCK-PAYLOAD)]
                 [to-copy (min (- write-len written) (- BLOCK-PAYLOAD boff))]
                 [phys    (ensure-data-block! vault inode-block-num inode lidx)])
            (when phys
              ;; Read-modify-write if partial block
              (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
                (when pay
                  (bytevector-copy! data written pay boff to-copy)
                  (blockstore-write-block! (vault-state-bs vault) phys pay))))
            (loop (+ written to-copy)))))
      ;; Update inode size and mtime
      (when (> new-end (vault-inode-size inode))
        (vault-inode-size-set! inode new-end))
      (vault-inode-mtime-set! inode (time-second (current-time)))
      (write-inode! vault inode)
      write-len))

  (define (file-truncate! vault inode-block-num inode new-size)
    (let ([old-size (vault-inode-size inode)])
      (cond
        [(= old-size new-size) (void)]
        [(< new-size old-size)
         ;; Shrink: zero out tail of last block; free excess blocks
         (let* ([last-lidx (if (zero? new-size) -1 (quotient (- new-size 1) BLOCK-PAYLOAD))]
                [last-boff (if (zero? new-size) 0 (remainder new-size BLOCK-PAYLOAD))])
           ;; Zero tail of last partial block
           (when (and (>= last-lidx 0) (> last-boff 0))
             (let ([phys (resolve-data-block vault inode last-lidx)])
               (when phys
                 (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
                   (when pay
                     (let loop ([i last-boff])
                       (when (< i BLOCK-PAYLOAD)
                         (bytevector-u8-set! pay i 0)
                         (loop (+ i 1))))
                     (blockstore-write-block! (vault-state-bs vault) phys pay))))))
           ;; Free blocks beyond last-lidx
           (let loop ([i (+ last-lidx 1)])
             (let ([phys (resolve-data-block vault inode i)])
               (when phys
                 (bitmap-free! vault phys)
                 (if (< i DIRECT-BLOCKS)
                   (vector-set! (vault-inode-direct inode) i VAULT-BLOCK-INVALID)
                   (let ([ind-blk (vault-inode-indirect inode)])
                     (when (not (= ind-blk VAULT-BLOCK-INVALID))
                       (let ([ind-pay (blockstore-read-block (vault-state-bs vault) ind-blk)])
                         (when ind-pay
                           (let ([ptr-idx (- i DIRECT-BLOCKS)])
                             (bv-set-u64le! ind-pay (* ptr-idx 8) VAULT-BLOCK-INVALID)
                             (blockstore-write-block! (vault-state-bs vault) ind-blk ind-pay)))))))
                 (loop (+ i 1))))))
         (vault-inode-size-set! inode new-size)]
        [else
         ;; Extend: just update size (data blocks will read as zeros)
         (vault-inode-size-set! inode new-size)])
      (vault-inode-ctime-set! inode (time-second (current-time)))
      (write-inode! vault inode)))

  ;; ======================================================================
  ;; Directory operations
  ;; ======================================================================

  (define (dir-lookup vault dir-inode name)
    ;; Scan all directory data blocks for an entry matching name.
    ;; Returns child block-num or #f.
    (let loop ([lidx 0])
      (let ([phys (resolve-data-block vault dir-inode lidx)])
        (if (not phys) #f
          (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
            (if (not pay) #f
              (let slot-loop ([slot 0])
                (if (>= slot DIRENTS-PER-BLOCK)
                  (loop (+ lidx 1))
                  (let-values ([(iblk nbv) (decode-dirent pay (* slot DIRENT-SIZE))])
                    (cond
                      [(= iblk 0) (slot-loop (+ slot 1))]  ;; free slot
                      [(string=? (utf8->string nbv) name) iblk]
                      [else (slot-loop (+ slot 1))]))))))))))

  (define (dir-add! vault dir-block-num dir-inode child-block-num name)
    ;; Add a directory entry. Finds first free slot in existing blocks,
    ;; or allocates a new data block.
    (let ([name-bv (string->utf8 name)]
          [done?   #f])
      (let block-loop ([lidx 0])
        (unless done?
          (let ([phys (resolve-data-block vault dir-inode lidx)])
            (if (not phys)
              ;; Need a new data block for the directory
              (let ([new-blk (ensure-data-block! vault dir-block-num dir-inode lidx)])
                (when new-blk
                  (let ([pay (make-bytevector BLOCK-PAYLOAD 0)])
                    (bytevector-copy! (encode-dirent child-block-num name-bv) 0 pay 0 DIRENT-SIZE)
                    (blockstore-write-block! (vault-state-bs vault) new-blk pay)
                    (set! done? #t))))
              (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
                (when pay
                  (let slot-loop ([slot 0])
                    (if (>= slot DIRENTS-PER-BLOCK)
                      (block-loop (+ lidx 1))
                      (let-values ([(iblk nbv) (decode-dirent pay (* slot DIRENT-SIZE))])
                        (if (= iblk 0)
                          ;; Free slot
                          (begin
                            (bytevector-copy! (encode-dirent child-block-num name-bv)
                                              0 pay (* slot DIRENT-SIZE) DIRENT-SIZE)
                            (blockstore-write-block! (vault-state-bs vault) phys pay)
                            (set! done? #t))
                          (slot-loop (+ slot 1))))))))))))))

  (define (dir-remove! vault dir-inode name)
    ;; Zero out the directory entry for name. Returns #t if found, #f if not.
    (let ([found? #f])
      (let block-loop ([lidx 0])
        (unless found?
          (let ([phys (resolve-data-block vault dir-inode lidx)])
            (when phys
              (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
                (when pay
                  (let slot-loop ([slot 0])
                    (when (< slot DIRENTS-PER-BLOCK)
                      (let-values ([(iblk nbv) (decode-dirent pay (* slot DIRENT-SIZE))])
                        (if (and (not (= iblk 0))
                                 (string=? (utf8->string nbv) name))
                          ;; Zero this slot
                          (begin
                            (let ([off (* slot DIRENT-SIZE)])
                              (let zero-loop ([i 0])
                                (when (< i DIRENT-SIZE)
                                  (bytevector-u8-set! pay (+ off i) 0)
                                  (zero-loop (+ i 1)))))
                            (blockstore-write-block! (vault-state-bs vault) phys pay)
                            (set! found? #t))
                          (slot-loop (+ slot 1))))))))
              (block-loop (+ lidx 1))))))
      found?))

  (define (dir-list vault dir-inode)
    ;; Returns list of (child-block-num . name-string) for all entries.
    (let ([result '()])
      (let block-loop ([lidx 0])
        (let ([phys (resolve-data-block vault dir-inode lidx)])
          (when phys
            (let ([pay (blockstore-read-block (vault-state-bs vault) phys)])
              (when pay
                (let slot-loop ([slot 0])
                  (when (< slot DIRENTS-PER-BLOCK)
                    (let-values ([(iblk nbv) (decode-dirent pay (* slot DIRENT-SIZE))])
                      (when (not (= iblk 0))
                        (set! result (cons (cons iblk (utf8->string nbv)) result))))
                    (slot-loop (+ slot 1)))))
              (block-loop (+ lidx 1))))))
      (reverse result)))

  (define (dir-empty? vault dir-inode)
    (null? (dir-list vault dir-inode)))

  (define (free-inode-blocks! vault inode)
    ;; Free all data blocks and optionally the indirect block.
    (let loop ([i 0])
      (when (< i DIRECT-BLOCKS)
        (let ([blk (vector-ref (vault-inode-direct inode) i)])
          (unless (= blk VAULT-BLOCK-INVALID)
            (bitmap-free! vault blk)))
        (loop (+ i 1))))
    (let ([ind (vault-inode-indirect inode)])
      (unless (= ind VAULT-BLOCK-INVALID)
        ;; Free each pointer in the indirect block
        (let ([ind-pay (blockstore-read-block (vault-state-bs vault) ind)])
          (when ind-pay
            (let loop ([i 0])
              (when (< i PTRS-PER-BLOCK)
                (let ([blk (bv-u64le ind-pay (* i 8))])
                  (unless (= blk VAULT-BLOCK-INVALID)
                    (bitmap-free! vault blk)))
                (loop (+ i 1))))))
        (bitmap-free! vault ind)))
    ;; Free the inode block itself
    (bitmap-free! vault (vault-inode-ino inode)))

  ;; ======================================================================
  ;; vault-create!
  ;; ======================================================================

  (define (vault-create! path passphrase total-blocks)
    (let* ([pass-bv       (if (string? passphrase) (string->utf8 passphrase) passphrase)]
           [salt          (vault-rand-bytes 32)]
           [master-key    (vault-rand-bytes VAULT-KEY-LEN)]
           ;; Derive passphrase key
           [pk            (vault-pbkdf2 pass-bv salt KDF-ITERATIONS VAULT-KEY-LEN)]
           ;; Encrypt master key
           [mk-enc        (vault-encrypt-small pk master-key)]
           ;; Encrypt superblock block number (always 0)
           [sb-num-bv     (make-bytevector 8 0)]   ;; block 0
           [sb-enc        (vault-encrypt-small pk sb-num-bv)]
           ;; Bitmap layout
           [bitmap-nblks  (max 1 (ceiling (/ total-blocks (* BLOCK-PAYLOAD 8))))]
           ;; Block layout: 0=superblock, 1=root-inode, 2...(1+bitmap-nblks)=bitmap
           [bitmap-start  2]
           [root-block    1]
           ;; Create blockstore
           [bs            (make-blockstore)])
      (blockstore-create! bs path total-blocks)
      ;; Write header
      (let ([hdr (encode-vault-header total-blocks salt KDF-ITERATIONS mk-enc sb-enc)])
        (blockstore-write-header! bs hdr))
      ;; Set master key (moves into secure memory)
      (blockstore-set-key! bs master-key)
      ;; Build in-memory bitmap: mark reserved blocks as used
      (let* ([bm-bytes (* bitmap-nblks BLOCK-PAYLOAD)]
             [bm       (make-bytevector bm-bytes 0)]
             [vault    (make-vault-state
                         bs #f root-block bitmap-start bitmap-nblks 0
                         VAULT-BLOCK-INVALID  ;; policy-block
                         bm #f 1 (make-eq-hashtable)
                         #f       ;; access controller
                         #f       ;; header-bv (not needed for create)
                         (make-mutex))])
        ;; Mark blocks 0 (superblock), 1 (root inode), 2...(1+bitmap-nblks) (bitmap)
        (bitmap-set! vault 0 #t)  ;; superblock
        (bitmap-set! vault 1 #t)  ;; root inode
        (let loop ([i 0])
          (when (< i bitmap-nblks)
            (bitmap-set! vault (+ bitmap-start i) #t)
            (loop (+ i 1))))
        ;; Write root inode at block 1
        (let* ([now  (time-second (current-time))]
               [root (make-vault-inode
                       root-block INODE-TYPE-DIR
                       (bitwise-ior S-IFDIR #o755)
                       0 0 0 now now now 2
                       (string->utf8 "/")
                       (make-vector DIRECT-BLOCKS VAULT-BLOCK-INVALID)
                       VAULT-BLOCK-INVALID)])
          (write-inode! vault root))
        ;; Write superblock at block 0
        (flush-superblock! vault)
        ;; Flush bitmap
        (vault-state-bitmap-dirty?-set! vault #t)
        (flush-bitmap! vault)
        (blockstore-sync! bs)
        ;; Zero passphrase key
        (bytevector-fill! pk 0)
        vault)))

  ;; ======================================================================
  ;; vault-open
  ;; ======================================================================

  (define (vault-open path passphrase)
    (let* ([pass-bv   (if (string? passphrase) (string->utf8 passphrase) passphrase)]
           [bs        (make-blockstore)]
           [_         (blockstore-open! bs path)]
           [hdr-bv    (blockstore-read-header bs)])
      ;; Decode header
      (let-values ([(_magic _ver _blksz total-blocks salt kdf-iter mk-enc sb-enc)
                    (decode-vault-header hdr-bv)])
        ;; Derive passphrase key
        (let ([pk (vault-pbkdf2 pass-bv salt kdf-iter VAULT-KEY-LEN)])
          ;; Decrypt master key
          (let ([master-key (vault-decrypt-small pk mk-enc)])
            (unless master-key
              (bytevector-fill! pk 0)
              (error 'vault-open "wrong passphrase or corrupt vault"))
            ;; Decrypt superblock block number
            (let ([sb-num-bv (vault-decrypt-small pk sb-enc)])
              (unless sb-num-bv
                (bytevector-fill! pk 0)
                (bytevector-fill! master-key 0)
                (error 'vault-open "corrupt vault (superblock locator)"))
              ;; Set master key in blockstore
              (blockstore-set-key! bs master-key)
              ;; Read superblock
              (let ([sb-block (bv-u64le sb-num-bv 0)])
                (let ([sb-pay (blockstore-read-block bs sb-block)])
                  (unless sb-pay
                    (error 'vault-open "cannot read superblock"))
                  (let-values ([(root-block bitmap-start bitmap-nblks generation
                                 policy-block)
                                (decode-superblock sb-pay)])
                    ;; Load bitmap into memory
                    (let* ([bm-bytes (* bitmap-nblks BLOCK-PAYLOAD)]
                           [bm       (make-bytevector bm-bytes 0)])
                      (let loop ([i 0])
                        (when (< i bitmap-nblks)
                          (let ([blk-pay (blockstore-read-block bs (+ bitmap-start i))])
                            (when blk-pay
                              (let ([dst-off (* i BLOCK-PAYLOAD)])
                                (bytevector-copy! blk-pay 0 bm dst-off BLOCK-PAYLOAD))))
                          (loop (+ i 1))))
                      ;; Zero passphrase key
                      (bytevector-fill! pk 0)
                      (make-vault-state
                        bs #f root-block bitmap-start bitmap-nblks generation
                        policy-block
                        bm #f 1 (make-eq-hashtable)
                        #f       ;; access controller
                        hdr-bv   ;; cached header for lock/unlock
                        (make-mutex))))))))))))

  ;; ======================================================================
  ;; vault-close!
  ;; ======================================================================

  (define (vault-close! vault)
    (with-mutex (vault-state-mutex vault)
      (when (blockstore-key-live? (vault-state-bs vault))
        (flush-superblock! vault)
        (flush-bitmap! vault)
        (blockstore-sync! (vault-state-bs vault)))
      (blockstore-clear-key! (vault-state-bs vault))
      (blockstore-close! (vault-state-bs vault))
      (vault-state-master-key-set! vault #f)
      (vault-state-header-bv-set! vault #f)))

  ;; ======================================================================
  ;; vault-lock! / vault-unlock!
  ;; ======================================================================

  ;; Lock: clear the master key from memory without unmounting.
  ;; All I/O operations will fail until vault-unlock! is called.
  ;; The FUSE mount stays alive — unauthorized processes see an empty dir.
  (define (vault-lock! vault)
    (with-mutex (vault-state-mutex vault)
      ;; Flush pending state while we still have the key
      (when (blockstore-key-live? (vault-state-bs vault))
        (flush-superblock! vault)
        (flush-bitmap! vault)
        (blockstore-sync! (vault-state-bs vault)))
      ;; Destroy the master key
      (blockstore-clear-key! (vault-state-bs vault))
      (vault-state-master-key-set! vault #f)
      ;; Lock the access controller
      (let ([ac (vault-state-access vault)])
        (when ac (access-controller-lock! ac)))))

  ;; Unlock: re-derive the master key from passphrase using cached header.
  ;; Returns #t on success, raises on wrong passphrase.
  (define (vault-unlock! vault passphrase)
    (with-mutex (vault-state-mutex vault)
      (let ([hdr-bv (vault-state-header-bv vault)])
        (unless hdr-bv
          (error 'vault-unlock! "no cached header — vault was not opened with vault-open"))
        (let* ([pass-bv (if (string? passphrase) (string->utf8 passphrase) passphrase)])
          (let-values ([(_magic _ver _blksz _total salt kdf-iter mk-enc sb-enc)
                        (decode-vault-header hdr-bv)])
            (let ([pk (vault-pbkdf2 pass-bv salt kdf-iter VAULT-KEY-LEN)])
              (let ([master-key (vault-decrypt-small pk mk-enc)])
                (bytevector-fill! pk 0)
                (unless master-key
                  (error 'vault-unlock! "wrong passphrase"))
                ;; Restore the key in blockstore (moves to secure memory)
                (blockstore-set-key! (vault-state-bs vault) master-key)
                ;; Reload bitmap from disk (may have been modified before lock)
                (let* ([bitmap-nblks (vault-state-bitmap-nblocks vault)]
                       [bm-bytes (* bitmap-nblks BLOCK-PAYLOAD)]
                       [bm (make-bytevector bm-bytes 0)]
                       [bs (vault-state-bs vault)]
                       [bitmap-start (vault-state-bitmap-start vault)])
                  (let loop ([i 0])
                    (when (< i bitmap-nblks)
                      (let ([blk-pay (blockstore-read-block bs (+ bitmap-start i))])
                        (when blk-pay
                          (bytevector-copy! blk-pay 0 bm (* i BLOCK-PAYLOAD) BLOCK-PAYLOAD)))
                      (loop (+ i 1))))
                  (vault-state-bitmap-set! vault bm)
                  (vault-state-bitmap-dirty?-set! vault #f))
                ;; Unlock access controller
                (let ([ac (vault-state-access vault)])
                  (when ac (access-controller-unlock! ac)))
                #t)))))))

  (define (vault-locked? vault)
    (not (blockstore-key-live? (vault-state-bs vault))))

  ;; ======================================================================
  ;; FUSE op implementations
  ;; ======================================================================

  (define (make-vault-getattr vault)
    (lambda (ino ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (and inode (inode->fuse-attr inode))))))

  (define (make-vault-lookup vault)
    (lambda (parent-ino name ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([parent (read-inode vault parent-ino)])
          (and parent
               (= (vault-inode-type parent) INODE-TYPE-DIR)
               (let ([child-blk (dir-lookup vault parent name)])
                 (and child-blk
                      (let ([child (read-inode vault child-blk)])
                        (and child (inode->fuse-entry child))))))))))

  (define (make-vault-readdir vault)
    (lambda (ino fh offset ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (if (and inode (= (vault-inode-type inode) INODE-TYPE-DIR))
            (let* ([entries (dir-list vault inode)]
                   [base (list (make-fuse-dirent ino 1 DT-DIR ".")
                               (make-fuse-dirent ino 2 DT-DIR ".."))]
                   [children
                    (let loop ([es entries] [i 3] [acc '()])
                      (if (null? es) (reverse acc)
                        (let* ([e     (car es)]
                               [cblk  (car e)]
                               [cname (cdr e)]
                               [child (read-inode vault cblk)]
                               [dtype (if child
                                        (cond
                                          [(= (vault-inode-type child) INODE-TYPE-DIR)     DT-DIR]
                                          [(= (vault-inode-type child) INODE-TYPE-SYMLINK) DT-LNK]
                                          [else                                             DT-REG])
                                        DT-UNKNOWN)])
                          (loop (cdr es) (+ i 1)
                                (cons (make-fuse-dirent cblk i dtype cname) acc)))))]
                   [all (append base children)])
              (filter (lambda (d) (> (fuse-dirent-off d) offset)) all))
            '())))))

  (define (make-vault-open vault)
    (lambda (ino flags ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (and inode (alloc-fh! vault ino))))))

  (define (make-vault-release vault)
    (lambda (ino fh ctx)
      (with-mutex (vault-state-mutex vault)
        (release-fh! vault fh))))

  (define (make-vault-read vault)
    (lambda (ino fh size offset ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (and inode
               (= (vault-inode-type inode) INODE-TYPE-FILE)
               (file-read vault inode size offset))))))

  (define (make-vault-write vault)
    (lambda (ino fh data offset ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (and inode
               (= (vault-inode-type inode) INODE-TYPE-FILE)
               (file-write! vault ino inode data offset))))))

  (define (make-vault-create vault)
    (lambda (parent-ino name mode flags ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([parent (read-inode vault parent-ino)])
          (and parent
               (= (vault-inode-type parent) INODE-TYPE-DIR)
               (let ([new-blk (bitmap-alloc! vault)])
                 (and new-blk
                      (let* ([now  (time-second (current-time))]
                             [uid  (fuse-context-uid ctx)]
                             [gid  (fuse-context-gid ctx)]
                             [inode (make-vault-inode
                                      new-blk INODE-TYPE-FILE
                                      (bitwise-ior S-IFREG (bitwise-and mode #o7777))
                                      uid gid 0 now now now 1
                                      (string->utf8 name)
                                      (make-vector DIRECT-BLOCKS VAULT-BLOCK-INVALID)
                                      VAULT-BLOCK-INVALID)])
                        (write-inode! vault inode)
                        (dir-add! vault parent-ino parent new-blk name)
                        (write-inode! vault parent)
                        (let ([fh (alloc-fh! vault new-blk)])
                          (cons (inode->fuse-entry inode) fh))))))))))

  (define (make-vault-mkdir vault)
    (lambda (parent-ino name mode ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([parent (read-inode vault parent-ino)])
          (and parent
               (= (vault-inode-type parent) INODE-TYPE-DIR)
               (let ([new-blk (bitmap-alloc! vault)])
                 (and new-blk
                      (let* ([now  (time-second (current-time))]
                             [uid  (fuse-context-uid ctx)]
                             [gid  (fuse-context-gid ctx)]
                             [inode (make-vault-inode
                                      new-blk INODE-TYPE-DIR
                                      (bitwise-ior S-IFDIR (bitwise-and mode #o7777))
                                      uid gid 0 now now now 2
                                      (string->utf8 name)
                                      (make-vector DIRECT-BLOCKS VAULT-BLOCK-INVALID)
                                      VAULT-BLOCK-INVALID)])
                        (write-inode! vault inode)
                        (dir-add! vault parent-ino parent new-blk name)
                        (vault-inode-nlink-set! parent (+ (vault-inode-nlink parent) 1))
                        (write-inode! vault parent)
                        (inode->fuse-entry inode)))))))))

  (define (make-vault-unlink vault)
    (lambda (parent-ino name ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([parent (read-inode vault parent-ino)])
          (and parent
               (= (vault-inode-type parent) INODE-TYPE-DIR)
               (let ([child-blk (dir-lookup vault parent name)])
                 (and child-blk
                      (let ([child (read-inode vault child-blk)])
                        (and child
                             (not (= (vault-inode-type child) INODE-TYPE-DIR))
                             (begin
                               (dir-remove! vault parent name)
                               (let ([nl (- (vault-inode-nlink child) 1)])
                                 (if (<= nl 0)
                                   (free-inode-blocks! vault child)
                                   (begin
                                     (vault-inode-nlink-set! child nl)
                                     (write-inode! vault child))))
                               (flush-bitmap! vault)
                               #t))))))))))

  (define (make-vault-rmdir vault)
    (lambda (parent-ino name ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([parent (read-inode vault parent-ino)])
          (and parent
               (= (vault-inode-type parent) INODE-TYPE-DIR)
               (let ([child-blk (dir-lookup vault parent name)])
                 (and child-blk
                      (let ([child (read-inode vault child-blk)])
                        (and child
                             (= (vault-inode-type child) INODE-TYPE-DIR)
                             (dir-empty? vault child)
                             (begin
                               (dir-remove! vault parent name)
                               (vault-inode-nlink-set! parent
                                 (max 2 (- (vault-inode-nlink parent) 1)))
                               (write-inode! vault parent)
                               (free-inode-blocks! vault child)
                               (flush-bitmap! vault)
                               #t))))))))))

  (define (make-vault-rename vault)
    (lambda (old-parent-ino old-name new-parent-ino new-name ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([old-parent (read-inode vault old-parent-ino)]
              [new-parent (read-inode vault new-parent-ino)])
          (and old-parent new-parent
               (= (vault-inode-type old-parent) INODE-TYPE-DIR)
               (= (vault-inode-type new-parent) INODE-TYPE-DIR)
               (let ([child-blk (dir-lookup vault old-parent old-name)])
                 (and child-blk
                      (begin
                        ;; Remove from old parent
                        (dir-remove! vault old-parent old-name)
                        ;; If destination exists, remove it
                        (let ([existing (dir-lookup vault new-parent new-name)])
                          (when existing
                            (let ([ex-inode (read-inode vault existing)])
                              (when ex-inode
                                (free-inode-blocks! vault ex-inode)
                                (flush-bitmap! vault)))))
                        ;; Add to new parent
                        (dir-add! vault new-parent-ino new-parent child-blk new-name)
                        (write-inode! vault new-parent)
                        #t))))))))

  (define (make-vault-setattr vault)
    (lambda (ino valid fh size atime mtime ctime atimensec mtimensec ctimensec mode uid gid ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (when inode
            (when (not (zero? (bitwise-and valid FATTR-MODE)))
              (vault-inode-mode-set! inode
                (bitwise-ior (bitwise-and (vault-inode-mode inode) (bitwise-not #o7777))
                             (bitwise-and mode #o7777))))
            (when (not (zero? (bitwise-and valid FATTR-UID)))
              (vault-inode-uid-set! inode uid))
            (when (not (zero? (bitwise-and valid FATTR-GID)))
              (vault-inode-gid-set! inode gid))
            (when (not (zero? (bitwise-and valid FATTR-SIZE)))
              (file-truncate! vault ino inode size))
            (when (not (zero? (bitwise-and valid FATTR-ATIME)))
              (vault-inode-atime-set! inode atime))
            (when (not (zero? (bitwise-and valid FATTR-MTIME)))
              (vault-inode-mtime-set! inode mtime))
            (when (not (zero? (bitwise-and valid FATTR-ATIME-NOW)))
              (vault-inode-atime-set! inode (time-second (current-time))))
            (when (not (zero? (bitwise-and valid FATTR-MTIME-NOW)))
              (vault-inode-mtime-set! inode (time-second (current-time))))
            (vault-inode-ctime-set! inode (time-second (current-time)))
            (write-inode! vault inode)
            (inode->fuse-attr inode))))))

  (define (make-vault-access vault)
    (lambda (ino mask ctx)
      (with-mutex (vault-state-mutex vault)
        (let ([inode (read-inode vault ino)])
          (if inode #t #f)))))

  (define (make-vault-statfs vault)
    (lambda (ctx)
      (with-mutex (vault-state-mutex vault)
        (let* ([total  (blockstore-total-blocks (vault-state-bs vault))]
               [bm     (vault-state-bitmap vault)]
               [used   (let loop ([i 0] [n 0])
                         (if (>= i (bytevector-length bm)) n
                           (let ([byte (bytevector-u8-ref bm i)])
                             (loop (+ i 1)
                                   (+ n (popcount8 byte))))))]
               [free   (- total used)])
          (make-fuse-statfs
            total free free
            total (- total used)
            BLOCK-SIZE 255 BLOCK-SIZE)))))

  (define (popcount8 byte)
    ;; Count set bits in a byte
    (let loop ([b byte] [n 0])
      (if (= b 0) n
        (loop (bitwise-and b (- b 1)) (+ n 1)))))

  ;; ======================================================================
  ;; vault->fuse-ops
  ;; ======================================================================

  (define (vault->fuse-ops vault)
    (let ([ops (make-eq-hashtable)])
      (eq-hashtable-set! ops 'getattr  (make-vault-getattr vault))
      (eq-hashtable-set! ops 'lookup   (make-vault-lookup  vault))
      (eq-hashtable-set! ops 'readdir  (make-vault-readdir vault))
      (eq-hashtable-set! ops 'open     (make-vault-open    vault))
      (eq-hashtable-set! ops 'release  (make-vault-release vault))
      (eq-hashtable-set! ops 'read     (make-vault-read    vault))
      (eq-hashtable-set! ops 'write    (make-vault-write   vault))
      (eq-hashtable-set! ops 'create   (make-vault-create  vault))
      (eq-hashtable-set! ops 'mkdir    (make-vault-mkdir   vault))
      (eq-hashtable-set! ops 'unlink   (make-vault-unlink  vault))
      (eq-hashtable-set! ops 'rmdir    (make-vault-rmdir   vault))
      (eq-hashtable-set! ops 'rename   (make-vault-rename  vault))
      (eq-hashtable-set! ops 'setattr  (make-vault-setattr vault))
      (eq-hashtable-set! ops 'access   (make-vault-access  vault))
      (eq-hashtable-set! ops 'statfs   (make-vault-statfs  vault))
      ops))

  ;; ======================================================================
  ;; Shell integration
  ;; ======================================================================

  (define (vault-mount! path passphrase mountpoint . opts)
    ;; Open vault, mount as FUSE filesystem in background.
    ;; Creates an access controller: only jsh (current PID) and its
    ;; subprocesses can access the vault. Everyone else (including root)
    ;; sees an empty directory.
    ;; Returns (cons vault session) — pass to vault-unmount!
    (let* ([vault   (vault-open path passphrase)]
           [ac      (make-access-controller)]
           [ops     (vault->fuse-ops vault)])
      ;; Store access controller in vault for lock/unlock
      (vault-state-access-set! vault ac)
      (let ([session (apply fuse-start-background! ops mountpoint
                            'fsname "vault"
                            'access-controller ac
                            opts)])
        (cons vault session))))

  (define (vault-unmount! handle)
    ;; handle = (cons vault session)
    (let ([vault   (car handle)]
          [session (cdr handle)])
      (fuse-session-destroy! session)  ;; stop FUSE loop, join thread
      (vault-close! vault)))           ;; flush + close (after FUSE is dead)

) ;; end library
