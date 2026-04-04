(library (chez vault format)
  (export
    ;; Constants
    VAULT-MAGIC VAULT-VERSION BLOCK-SIZE HEADER-SIZE
    BLOCK-NONCE-LEN BLOCK-TAG-LEN BLOCK-PAYLOAD
    INODE-TYPE-FREE INODE-TYPE-FILE INODE-TYPE-DIR INODE-TYPE-SYMLINK
    VAULT-BLOCK-INVALID VAULT-MAX-FILENAME
    DIRECT-BLOCKS PTRS-PER-BLOCK DIRENT-SIZE DIRENTS-PER-BLOCK
    VAULT-MK-ENC-LEN VAULT-SB-ENC-LEN KDF-ITERATIONS VAULT-KEY-LEN
    ;; Header codec
    encode-vault-header decode-vault-header
    ;; Superblock codec
    encode-superblock decode-superblock
    ;; Inode codec
    encode-inode decode-inode
    ;; DirEntry codec
    encode-dirent decode-dirent
    ;; Binary helpers
    bv-u64le bv-set-u64le! bv-u32le bv-set-u32le! bv-u8 bv-sub)

  (import (chezscheme))

  ;; ---- Constants ----

  (define VAULT-MAGIC         #x4D454D48)  ;; "MEMH" LE u32 = bytes 48 4D 45 4D
  (define VAULT-VERSION       1)
  (define BLOCK-SIZE          4096)
  (define HEADER-SIZE         256)
  (define BLOCK-NONCE-LEN     12)
  (define BLOCK-TAG-LEN       16)
  (define BLOCK-PAYLOAD       (- BLOCK-SIZE BLOCK-NONCE-LEN BLOCK-TAG-LEN))  ;; 4068
  (define VAULT-KEY-LEN       32)
  (define VAULT-MAX-FILENAME  255)
  (define DIRECT-BLOCKS       12)
  (define PTRS-PER-BLOCK      (quotient BLOCK-PAYLOAD 8))    ;; 508
  (define DIRENT-SIZE         264)   ;; 8 (inode-block) + 1 (name-len) + 255 (name)
  (define DIRENTS-PER-BLOCK   (quotient BLOCK-PAYLOAD DIRENT-SIZE))  ;; 15
  (define INODE-TYPE-FREE     0)
  (define INODE-TYPE-FILE     1)
  (define INODE-TYPE-DIR      2)
  (define INODE-TYPE-SYMLINK  3)
  (define VAULT-BLOCK-INVALID (- (expt 2 64) 1))  ;; 0xFFFFFFFFFFFFFFFF — bignum!
  ;; Encrypted envelope sizes: nonce + payload + tag
  (define VAULT-MK-ENC-LEN   (+ BLOCK-NONCE-LEN VAULT-KEY-LEN BLOCK-TAG-LEN))  ;; 60
  (define VAULT-SB-ENC-LEN   (+ BLOCK-NONCE-LEN 8 BLOCK-TAG-LEN))              ;; 36
  (define KDF-ITERATIONS      600000)

  ;; ---- Binary helpers ----
  ;; All on-disk multi-byte values are little-endian.
  ;; bv-set-u64le!/bv-u64le use manual byte loops to correctly handle bignum values
  ;; (e.g., VAULT-BLOCK-INVALID = 2^64-1 exceeds fixnum range on most Chez builds).

  (define (bv-u64le bv off)
    (let loop ([i 0] [acc 0])
      (if (= i 8) acc
        (loop (+ i 1)
              (bitwise-ior acc
                (bitwise-arithmetic-shift-left (bytevector-u8-ref bv (+ off i))
                                               (* i 8)))))))

  (define (bv-set-u64le! bv off val)
    (let loop ([i 0] [v val])
      (when (< i 8)
        (bytevector-u8-set! bv (+ off i) (bitwise-and v #xff))
        (loop (+ i 1) (bitwise-arithmetic-shift-right v 8)))))

  (define (bv-u32le bv off)
    (bytevector-u32-ref bv off (endianness little)))

  (define (bv-set-u32le! bv off val)
    (bytevector-u32-set! bv off val (endianness little)))

  (define (bv-u8 bv off)
    (bytevector-u8-ref bv off))

  (define (bv-sub bv start len)
    (let ([out (make-bytevector len 0)])
      (bytevector-copy! bv start out 0 len)
      out))

  ;; ---- VaultHeader ----
  ;; Unencrypted 256-byte header at file offset 0.
  ;;
  ;; Offset  Size  Field
  ;;  0       4    magic          = VAULT-MAGIC (u32 LE)
  ;;  4       2    version        = VAULT-VERSION (u16 LE)
  ;;  6       4    block_size     = BLOCK-SIZE (u32 LE)
  ;; 10       8    total_blocks   (u64 LE)
  ;; 18      32    salt           (KDF salt)
  ;; 50       8    kdf_iterations (u64 LE)
  ;; 58      60    mk_encrypted   = nonce[12] + ciphertext[32] + tag[16]
  ;; 118     36    sb_encrypted   = nonce[12] + ciphertext[8] + tag[16]
  ;; 154    102    padding
  ;; Total: 256 bytes

  (define (encode-vault-header total-blocks salt kdf-iterations mk-enc sb-enc)
    (let ([bv (make-bytevector HEADER-SIZE 0)])
      (bv-set-u32le!  bv 0  VAULT-MAGIC)
      (bytevector-u16-set! bv 4 VAULT-VERSION (endianness little))
      (bv-set-u32le!  bv 6  BLOCK-SIZE)
      (bv-set-u64le!  bv 10 total-blocks)
      (bytevector-copy! salt   0 bv 18  32)
      (bv-set-u64le!  bv 50 kdf-iterations)
      (bytevector-copy! mk-enc 0 bv 58  VAULT-MK-ENC-LEN)
      (bytevector-copy! sb-enc 0 bv 118 VAULT-SB-ENC-LEN)
      bv))

  (define (decode-vault-header bv)
    ;; Returns: (values magic version block-size total-blocks
    ;;                  salt kdf-iterations mk-enc sb-enc)
    (let* ([magic  (bv-u32le bv 0)]
           [ver    (bytevector-u16-ref bv 4 (endianness little))]
           [blksz  (bv-u32le bv 6)])
      (unless (and (= magic VAULT-MAGIC) (= ver VAULT-VERSION) (= blksz BLOCK-SIZE))
        (error 'decode-vault-header "not a valid vault file"))
      (values
        magic ver blksz
        (bv-u64le bv 10)
        (bv-sub   bv 18 32)
        (bv-u64le bv 50)
        (bv-sub   bv 58  VAULT-MK-ENC-LEN)
        (bv-sub   bv 118 VAULT-SB-ENC-LEN))))

  ;; ---- Superblock ----
  ;; Encrypted; occupies one BLOCK-PAYLOAD-byte block (block 0).
  ;;
  ;; Offset  Size  Field
  ;;  0       8    root_inode_block  (u64 LE)
  ;;  8       8    bitmap_start      (u64 LE)
  ;; 16       8    bitmap_blocks     (u64 LE)
  ;; 24       8    generation        (u64 LE)
  ;; 32    4036    padding

  (define (encode-superblock root-inode-block bitmap-start bitmap-blocks generation)
    (let ([bv (make-bytevector BLOCK-PAYLOAD 0)])
      (bv-set-u64le! bv 0  root-inode-block)
      (bv-set-u64le! bv 8  bitmap-start)
      (bv-set-u64le! bv 16 bitmap-blocks)
      (bv-set-u64le! bv 24 generation)
      bv))

  (define (decode-superblock bv)
    ;; Returns: (values root-inode-block bitmap-start bitmap-blocks generation)
    (values
      (bv-u64le bv 0)
      (bv-u64le bv 8)
      (bv-u64le bv 16)
      (bv-u64le bv 24)))

  ;; ---- Inode ----
  ;; Encrypted; occupies one BLOCK-PAYLOAD-byte block.
  ;; inode-num == block-num == FUSE ino (identity mapping).
  ;;
  ;; Offset  Size  Field
  ;;  0       8    inode_num     (u64 LE) = block_num
  ;;  8       1    type          (u8)
  ;;  9       3    pad
  ;; 12       4    mode          (u32 LE)
  ;; 16       4    uid           (u32 LE)
  ;; 20       4    gid           (u32 LE)
  ;; 24       8    size          (u64 LE)
  ;; 32       8    ctime         (u64 LE)
  ;; 40       8    mtime         (u64 LE)
  ;; 48       8    atime         (u64 LE)
  ;; 56       4    nlink         (u32 LE)
  ;; 60       4    name_len      (u32 LE)
  ;; 64     256    name          (bytes, zero-padded)
  ;; 320     96    direct[12]    (u64 LE each; VAULT-BLOCK-INVALID = unused)
  ;; 416      8    indirect      (u64 LE)
  ;; 424   3644    padding

  (define (encode-inode inode-num type mode uid gid size
                        ctime mtime atime nlink name-bv direct-vec indirect)
    (let* ([bv       (make-bytevector BLOCK-PAYLOAD 0)]
           [name-len (min (bytevector-length name-bv) VAULT-MAX-FILENAME)])
      (bv-set-u64le! bv 0  inode-num)
      (bytevector-u8-set! bv 8 type)
      (bv-set-u32le! bv 12 mode)
      (bv-set-u32le! bv 16 uid)
      (bv-set-u32le! bv 20 gid)
      (bv-set-u64le! bv 24 size)
      (bv-set-u64le! bv 32 ctime)
      (bv-set-u64le! bv 40 mtime)
      (bv-set-u64le! bv 48 atime)
      (bv-set-u32le! bv 56 nlink)
      (bv-set-u32le! bv 60 name-len)
      (when (> name-len 0)
        (bytevector-copy! name-bv 0 bv 64 name-len))
      (let loop ([i 0])
        (when (< i DIRECT-BLOCKS)
          (bv-set-u64le! bv (+ 320 (* i 8)) (vector-ref direct-vec i))
          (loop (+ i 1))))
      (bv-set-u64le! bv 416 indirect)
      bv))

  (define (decode-inode bv)
    ;; Returns: (values inode-num type mode uid gid size
    ;;                  ctime mtime atime nlink name-bv direct-vec indirect)
    (let* ([name-len   (bv-u32le bv 60)]
           [name-len*  (min name-len VAULT-MAX-FILENAME)]
           [name-bv    (bv-sub bv 64 name-len*)]
           [direct-vec (make-vector DIRECT-BLOCKS VAULT-BLOCK-INVALID)])
      (let loop ([i 0])
        (when (< i DIRECT-BLOCKS)
          (vector-set! direct-vec i (bv-u64le bv (+ 320 (* i 8))))
          (loop (+ i 1))))
      (values
        (bv-u64le  bv 0)   ;; inode-num
        (bv-u8     bv 8)   ;; type
        (bv-u32le  bv 12)  ;; mode
        (bv-u32le  bv 16)  ;; uid
        (bv-u32le  bv 20)  ;; gid
        (bv-u64le  bv 24)  ;; size
        (bv-u64le  bv 32)  ;; ctime
        (bv-u64le  bv 40)  ;; mtime
        (bv-u64le  bv 48)  ;; atime
        (bv-u32le  bv 56)  ;; nlink
        name-bv
        direct-vec
        (bv-u64le  bv 416) ;; indirect
        )))

  ;; ---- DirEntry ----
  ;; Each entry is DIRENT-SIZE = 264 bytes.
  ;; A block holds DIRENTS-PER-BLOCK = 15 entries.
  ;; Free slot: inode-block == 0.
  ;;
  ;; Offset  Size  Field
  ;;  0       8    inode_block  (u64 LE; 0 = free slot)
  ;;  8       1    name_len     (u8)
  ;;  9     255    name         (bytes)

  (define (encode-dirent inode-block name-bv)
    (let* ([bv       (make-bytevector DIRENT-SIZE 0)]
           [name-len (min (bytevector-length name-bv) VAULT-MAX-FILENAME)])
      (bv-set-u64le! bv 0 inode-block)
      (bytevector-u8-set! bv 8 name-len)
      (when (> name-len 0)
        (bytevector-copy! name-bv 0 bv 9 name-len))
      bv))

  (define (decode-dirent bv slot-offset)
    ;; Reads one dirent from bv at byte offset slot-offset.
    ;; Returns: (values inode-block name-bv)
    ;; inode-block == 0 means free slot.
    (let* ([iblock   (bv-u64le bv slot-offset)]
           [name-len (bv-u8 bv (+ slot-offset 8))]
           [name-bv  (bv-sub bv (+ slot-offset 9) name-len)])
      (values iblock name-bv)))

) ;; end library
