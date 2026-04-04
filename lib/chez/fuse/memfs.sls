(library (chez fuse memfs)
  (export
    make-memfs
    memfs->fuse-ops
    memfs-create-file!
    memfs-create-dir!
    memfs-write-file!
    memfs-read-file
    memfs-remove!
    memfs-list-dir)

  (import
    (chezscheme)
    (chez fuse constants)
    (chez fuse types))

  ;; ======================================================================
  ;; In-memory filesystem — batteries-included FUSE filesystem
  ;;
  ;; Provides a complete read/write filesystem backed by hashtables.
  ;; Usage:
  ;;   (define fs (make-memfs))
  ;;   (fuse-start! (memfs->fuse-ops fs) "/mnt/test")
  ;; ======================================================================

  ;; ---- Node types ----
  (define-record-type memfs-node
    (fields
      (immutable ino)
      (mutable type)           ;; 'file 'dir 'symlink
      (mutable mode)           ;; full st_mode (type + perms)
      (mutable uid)
      (mutable gid)
      (mutable atime)
      (mutable mtime)
      (mutable ctime)
      (mutable nlink)
      (mutable data)           ;; bytevector (file), hashtable (dir), string (symlink)
      (mutable size)))         ;; file size in bytes

  ;; ---- Filesystem state ----
  ;; Named memfs-state to avoid constructor name clash with public make-memfs.
  (define-record-type memfs-state
    (fields
      (mutable next-ino)
      (mutable inodes)         ;; eq-hashtable: ino -> memfs-node
      (mutable next-fh)
      (mutable open-files)     ;; eq-hashtable: fh -> ino
      (mutable mutex)))

  ;; ---- Construction ----

  (define (make-memfs)
    (let* ([now (current-seconds)]
           [root-children (make-hashtable string-hash string=?)]
           [root (make-memfs-node
                   1 'dir (bitwise-ior S-IFDIR #o755)
                   0 0 now now now 2
                   root-children 0)]
           [inodes (make-eq-hashtable)])
      (eq-hashtable-set! inodes 1 root)
      (make-memfs-state 2 inodes 1 (make-eq-hashtable) (make-mutex))))

  (define (current-seconds)
    (time-second (current-time)))

  ;; ---- Programmatic API (for pre-populating the FS) ----

  (define (memfs-create-file! fs path content-string)
    (let* ([data (string->utf8 content-string)]
           [parts (split-path path)]
           [name (car (reverse parts))]
           [dir-parts (reverse (cdr (reverse parts)))]
           [parent-ino (ensure-parents! fs dir-parts)]
           [parent (get-node fs parent-ino)])
      (when parent
        (let ([ino (alloc-ino! fs)])
          (create-file-node! fs ino name
            (bitwise-ior S-IFREG #o644) 0 0 data)
          (hashtable-set! (memfs-node-data parent) name ino)
          ino))))

  (define (memfs-create-dir! fs path)
    (let* ([parts (split-path path)]
           [name (car (reverse parts))]
           [dir-parts (reverse (cdr (reverse parts)))]
           [parent-ino (ensure-parents! fs dir-parts)]
           [parent (get-node fs parent-ino)])
      (when parent
        (let ([ino (alloc-ino! fs)])
          (create-dir-node! fs ino name
            (bitwise-ior S-IFDIR #o755) 0 0)
          (hashtable-set! (memfs-node-data parent) name ino)
          (memfs-node-nlink-set! parent (+ (memfs-node-nlink parent) 1))
          ino))))

  (define (memfs-write-file! fs path content-string)
    (let* ([data (string->utf8 content-string)]
           [parts (split-path path)]
           [ino (resolve-path fs parts)])
      (and ino
        (let ([node (get-node fs ino)])
          (and node (eq? (memfs-node-type node) 'file)
               (begin
                 (memfs-node-data-set! node data)
                 (memfs-node-size-set! node (bytevector-length data))
                 (memfs-node-mtime-set! node (current-seconds))
                 #t))))))

  (define (memfs-read-file fs path)
    (let* ([parts (split-path path)]
           [ino (resolve-path fs parts)])
      (and ino
           (let ([node (get-node fs ino)])
             (and node (eq? (memfs-node-type node) 'file)
                  (utf8->string (memfs-node-data node)))))))

  (define (memfs-remove! fs path)
    (let* ([parts (split-path path)]
           [name (car (reverse parts))]
           [parent-parts (reverse (cdr (reverse parts)))]
           [parent-ino (resolve-path fs parent-parts)]
           [parent (and parent-ino (get-node fs parent-ino))])
      (when (and parent (eq? (memfs-node-type parent) 'dir))
        (let ([children (memfs-node-data parent)])
          (when (hashtable-contains? children name)
            (let* ([ino (hashtable-ref children name #f)]
                   [node (get-node fs ino)])
              (hashtable-delete! children name)
              (when node
                (hashtable-delete! (memfs-state-inodes fs) ino)
                (when (eq? (memfs-node-type node) 'dir)
                  (memfs-node-nlink-set! parent
                    (max 2 (- (memfs-node-nlink parent) 1)))))
              #t))))))

  (define (memfs-list-dir fs path)
    (let* ([parts (split-path path)]
           [ino (resolve-path fs parts)]
           [node (and ino (get-node fs ino))])
      (if (and node (eq? (memfs-node-type node) 'dir))
        (hashtable-keys (memfs-node-data node))
        '())))

  ;; ---- FUSE ops builder ----

  (define (memfs->fuse-ops fs)
    (let ([ops (make-eq-hashtable)])
      (eq-hashtable-set! ops 'getattr (make-memfs-getattr fs))
      (eq-hashtable-set! ops 'lookup  (make-memfs-lookup fs))
      (eq-hashtable-set! ops 'readdir (make-memfs-readdir fs))
      (eq-hashtable-set! ops 'open    (make-memfs-open fs))
      (eq-hashtable-set! ops 'read    (make-memfs-read fs))
      (eq-hashtable-set! ops 'write   (make-memfs-write fs))
      (eq-hashtable-set! ops 'create  (make-memfs-create fs))
      (eq-hashtable-set! ops 'mkdir   (make-memfs-mkdir fs))
      (eq-hashtable-set! ops 'unlink  (make-memfs-unlink fs))
      (eq-hashtable-set! ops 'rmdir   (make-memfs-rmdir fs))
      (eq-hashtable-set! ops 'rename  (make-memfs-rename fs))
      (eq-hashtable-set! ops 'setattr (make-memfs-setattr fs))
      (eq-hashtable-set! ops 'access  (make-memfs-access fs))
      (eq-hashtable-set! ops 'release (make-memfs-release fs))
      (eq-hashtable-set! ops 'symlink (make-memfs-symlink fs))
      (eq-hashtable-set! ops 'readlink (make-memfs-readlink fs))
      (eq-hashtable-set! ops 'link    (make-memfs-link fs))
      (eq-hashtable-set! ops 'statfs  (make-memfs-statfs fs))
      ops))

  ;; ---- Internal helpers ----

  (define (get-node fs ino)
    (eq-hashtable-ref (memfs-state-inodes fs) ino #f))

  (define (alloc-ino! fs)
    (let ([ino (memfs-state-next-ino fs)])
      (memfs-state-next-ino-set! fs (+ ino 1))
      ino))

  (define (alloc-fh! fs ino)
    (let ([fh (memfs-state-next-fh fs)])
      (memfs-state-next-fh-set! fs (+ fh 1))
      (eq-hashtable-set! (memfs-state-open-files fs) fh ino)
      fh))

  (define (node->fuse-attr node)
    (make-fuse-attr
      (memfs-node-ino node)
      (memfs-node-size node)
      (quotient (+ (memfs-node-size node) 511) 512)  ;; blocks
      (memfs-node-atime node)
      (memfs-node-mtime node)
      (memfs-node-ctime node)
      0 0 0   ;; nanoseconds
      (memfs-node-mode node)
      (memfs-node-nlink node)
      (memfs-node-uid node)
      (memfs-node-gid node)
      0        ;; rdev
      4096))   ;; blksize

  (define (node->fuse-entry node)
    (make-fuse-entry
      (memfs-node-ino node) 0  ;; nodeid, generation
      1 0 1 0                  ;; entry_valid, attr_valid (1s each)
      (node->fuse-attr node)))

  (define (create-file-node! fs ino name mode uid gid data)
    (let* ([now (current-seconds)]
           [node (make-memfs-node
                  ino 'file mode uid gid
                  now now now 1
                  data (bytevector-length data))])
      (eq-hashtable-set! (memfs-state-inodes fs) ino node)
      node))

  (define (create-dir-node! fs ino name mode uid gid)
    (let* ([now (current-seconds)]
           [children (make-hashtable string-hash string=?)]
           [node (make-memfs-node
                   ino 'dir mode uid gid
                   now now now 2
                   children 0)])
      (eq-hashtable-set! (memfs-state-inodes fs) ino node)
      node))

  (define (split-path path)
    (let ([parts (filter (lambda (s) (> (string-length s) 0))
                         (string-split path #\/))])
      (if (null? parts) '() parts)))

  ;; Simple string split by char.
  (define (string-split str ch)
    (let ([len (string-length str)])
      (let loop ([i 0] [start 0] [acc '()])
        (cond
          [(= i len)
           (reverse (cons (substring str start len) acc))]
          [(char=? (string-ref str i) ch)
           (loop (+ i 1) (+ i 1) (cons (substring str start i) acc))]
          [else (loop (+ i 1) start acc)]))))

  (define (resolve-path fs parts)
    (let loop ([ino 1] [parts parts])
      (if (null? parts) ino
        (let ([node (get-node fs ino)])
          (if (and node (eq? (memfs-node-type node) 'dir))
            (let ([children (memfs-node-data node)])
              (let ([child-ino (hashtable-ref children (car parts) #f)])
                (if child-ino
                  (loop child-ino (cdr parts))
                  #f)))
            #f)))))

  (define (ensure-parents! fs parts)
    (let loop ([ino 1] [parts parts])
      (if (null? parts) ino
        (let* ([node (get-node fs ino)]
               [children (memfs-node-data node)]
               [name (car parts)]
               [child-ino (hashtable-ref children name #f)])
          (if child-ino
            (loop child-ino (cdr parts))
            (let ([new-ino (alloc-ino! fs)])
              (create-dir-node! fs new-ino name
                (bitwise-ior S-IFDIR #o755) 0 0)
              (hashtable-set! children name new-ino)
              (memfs-node-nlink-set! node (+ (memfs-node-nlink node) 1))
              (loop new-ino (cdr parts))))))))

  ;; ---- FUSE callback implementations ----

  (define (make-memfs-getattr fs)
    (lambda (ino ctx)
      (let ([node (get-node fs ino)])
        (and node (node->fuse-attr node)))))

  (define (make-memfs-lookup fs)
    (lambda (parent-ino name ctx)
      (let ([parent (get-node fs parent-ino)])
        (and parent
             (eq? (memfs-node-type parent) 'dir)
             (let ([child-ino (hashtable-ref (memfs-node-data parent) name #f)])
               (and child-ino
                    (let ([child (get-node fs child-ino)])
                      (and child (node->fuse-entry child)))))))))

  (define (make-memfs-readdir fs)
    (lambda (ino fh offset ctx)
      (let ([node (get-node fs ino)])
        (if (and node (eq? (memfs-node-type node) 'dir))
          (let* ([children (memfs-node-data node)]
                 [keys (vector->list (hashtable-keys children))]
                 ;; Build full entry list: . .. then children
                 [entries
                  (append
                    (list
                      (make-fuse-dirent ino 1 DT-DIR ".")
                      (make-fuse-dirent ino 2 DT-DIR ".."))
                    (let loop ([ks keys] [i 3] [acc '()])
                      (if (null? ks) (reverse acc)
                        (let* ([name (car ks)]
                               [child-ino (hashtable-ref children name #f)]
                               [child (and child-ino (get-node fs child-ino))]
                               [dtype (if child
                                        (case (memfs-node-type child)
                                          [(dir) DT-DIR]
                                          [(symlink) DT-LNK]
                                          [else DT-REG])
                                        DT-UNKNOWN)])
                          (loop (cdr ks) (+ i 1)
                                (cons (make-fuse-dirent
                                        (or child-ino 0) i dtype name)
                                      acc))))))])
            ;; Filter by offset
            (filter (lambda (d) (> (fuse-dirent-off d) offset)) entries))
          '()))))

  (define (make-memfs-open fs)
    (lambda (ino flags ctx)
      (let ([node (get-node fs ino)])
        (and node (alloc-fh! fs ino)))))

  (define (make-memfs-release fs)
    (lambda (ino fh ctx)
      (hashtable-delete! (memfs-state-open-files fs) fh)))

  (define (make-memfs-read fs)
    (lambda (ino fh size offset ctx)
      (let ([node (get-node fs ino)])
        (if (and node (eq? (memfs-node-type node) 'file))
          (let* ([data (memfs-node-data node)]
                 [len (bytevector-length data)]
                 [start (min offset len)]
                 [end (min len (+ offset size))]
                 [count (- end start)])
            (memfs-node-atime-set! node (current-seconds))
            (if (<= count 0)
              (make-bytevector 0)
              (let ([result (make-bytevector count)])
                (bytevector-copy! data start result 0 count)
                result)))
          #f))))

  (define (make-memfs-write fs)
    (lambda (ino fh data offset ctx)
      (let ([node (get-node fs ino)])
        (if (and node (eq? (memfs-node-type node) 'file))
          (let* ([old-data (memfs-node-data node)]
                 [old-len (bytevector-length old-data)]
                 [write-len (bytevector-length data)]
                 [new-end (+ offset write-len)]
                 [new-len (max old-len new-end)]
                 [new-data (make-bytevector new-len 0)])
            ;; Copy old data
            (when (> old-len 0)
              (bytevector-copy! old-data 0 new-data 0 old-len))
            ;; Write new data at offset
            (bytevector-copy! data 0 new-data offset write-len)
            (memfs-node-data-set! node new-data)
            (memfs-node-size-set! node new-len)
            (memfs-node-mtime-set! node (current-seconds))
            write-len)
          #f))))

  (define (make-memfs-create fs)
    (lambda (parent-ino name mode flags ctx)
      (let ([parent (get-node fs parent-ino)])
        (if (and parent (eq? (memfs-node-type parent) 'dir))
          (let* ([ino (alloc-ino! fs)]
                 [fh (alloc-fh! fs ino)]
                 [node (create-file-node! fs ino name
                         (bitwise-ior S-IFREG (bitwise-and mode #o7777))
                         (fuse-context-uid ctx) (fuse-context-gid ctx)
                         (make-bytevector 0))])
            (hashtable-set! (memfs-node-data parent) name ino)
            (cons (node->fuse-entry node) fh))
          #f))))

  (define (make-memfs-mkdir fs)
    (lambda (parent-ino name mode ctx)
      (let ([parent (get-node fs parent-ino)])
        (if (and parent (eq? (memfs-node-type parent) 'dir))
          (let* ([ino (alloc-ino! fs)]
                 [node (create-dir-node! fs ino name
                         (bitwise-ior S-IFDIR (bitwise-and mode #o7777))
                         (fuse-context-uid ctx) (fuse-context-gid ctx))])
            (hashtable-set! (memfs-node-data parent) name ino)
            (memfs-node-nlink-set! parent (+ (memfs-node-nlink parent) 1))
            (node->fuse-entry node))
          #f))))

  (define (make-memfs-unlink fs)
    (lambda (parent-ino name ctx)
      (let ([parent (get-node fs parent-ino)])
        (if (and parent (eq? (memfs-node-type parent) 'dir))
          (let* ([children (memfs-node-data parent)]
                 [child-ino (hashtable-ref children name #f)]
                 [child (and child-ino (get-node fs child-ino))])
            (if (and child (not (eq? (memfs-node-type child) 'dir)))
              (begin
                (hashtable-delete! children name)
                (let ([nl (- (memfs-node-nlink child) 1)])
                  (memfs-node-nlink-set! child nl)
                  (when (<= nl 0)
                    (hashtable-delete! (memfs-state-inodes fs) child-ino)))
                #t)
              #f))
          #f))))

  (define (make-memfs-rmdir fs)
    (lambda (parent-ino name ctx)
      (let ([parent (get-node fs parent-ino)])
        (if (and parent (eq? (memfs-node-type parent) 'dir))
          (let* ([children (memfs-node-data parent)]
                 [child-ino (hashtable-ref children name #f)]
                 [child (and child-ino (get-node fs child-ino))])
            (if (and child (eq? (memfs-node-type child) 'dir))
              (let ([child-children (memfs-node-data child)])
                (if (= (hashtable-size child-children) 0)
                  (begin
                    (hashtable-delete! children name)
                    (hashtable-delete! (memfs-state-inodes fs) child-ino)
                    (memfs-node-nlink-set! parent
                      (max 2 (- (memfs-node-nlink parent) 1)))
                    #t)
                  #f))  ;; ENOTEMPTY handled by caller
              #f))
          #f))))

  (define (make-memfs-rename fs)
    (lambda (old-parent-ino old-name new-parent-ino new-name ctx)
      (let ([old-parent (get-node fs old-parent-ino)]
            [new-parent (get-node fs new-parent-ino)])
        (if (and old-parent new-parent
                 (eq? (memfs-node-type old-parent) 'dir)
                 (eq? (memfs-node-type new-parent) 'dir))
          (let* ([old-children (memfs-node-data old-parent)]
                 [ino (hashtable-ref old-children old-name #f)])
            (if ino
              (let ([new-children (memfs-node-data new-parent)])
                ;; Remove old entry that might exist at destination
                (let ([existing (hashtable-ref new-children new-name #f)])
                  (when existing
                    (hashtable-delete! (memfs-state-inodes fs) existing)))
                (hashtable-delete! old-children old-name)
                (hashtable-set! new-children new-name ino)
                #t)
              #f))
          #f))))

  (define (make-memfs-setattr fs)
    (lambda (ino valid fh size atime mtime ctime
                 atimensec mtimensec ctimensec mode uid gid ctx)
      (let ([node (get-node fs ino)])
        (when node
          (when (not (zero? (bitwise-and valid FATTR-MODE)))
            (memfs-node-mode-set! node
              (bitwise-ior
                (bitwise-and (memfs-node-mode node) S-IFMT)
                (bitwise-and mode #o7777))))
          (when (not (zero? (bitwise-and valid FATTR-UID)))
            (memfs-node-uid-set! node uid))
          (when (not (zero? (bitwise-and valid FATTR-GID)))
            (memfs-node-gid-set! node gid))
          (when (not (zero? (bitwise-and valid FATTR-SIZE)))
            (if (eq? (memfs-node-type node) 'file)
              (let* ([old-data (memfs-node-data node)]
                     [old-len (bytevector-length old-data)])
                (if (< size old-len)
                  (let ([new-data (make-bytevector size)])
                    (bytevector-copy! old-data 0 new-data 0 size)
                    (memfs-node-data-set! node new-data))
                  (let ([new-data (make-bytevector size 0)])
                    (bytevector-copy! old-data 0 new-data 0 old-len)
                    (memfs-node-data-set! node new-data)))
                (memfs-node-size-set! node size))
              (void)))
          (when (not (zero? (bitwise-and valid FATTR-ATIME)))
            (memfs-node-atime-set! node atime))
          (when (not (zero? (bitwise-and valid FATTR-MTIME)))
            (memfs-node-mtime-set! node mtime))
          (when (not (zero? (bitwise-and valid FATTR-ATIME-NOW)))
            (memfs-node-atime-set! node (current-seconds)))
          (when (not (zero? (bitwise-and valid FATTR-MTIME-NOW)))
            (memfs-node-mtime-set! node (current-seconds)))
          (memfs-node-ctime-set! node (current-seconds))
          (node->fuse-attr node)))))

  (define (make-memfs-access fs)
    (lambda (ino mask ctx)
      (let ([node (get-node fs ino)])
        (if node #t #f))))

  (define (make-memfs-symlink fs)
    (lambda (parent-ino name target ctx)
      (let ([parent (get-node fs parent-ino)])
        (if (and parent (eq? (memfs-node-type parent) 'dir))
          (let* ([ino (alloc-ino! fs)]
                 [now (current-seconds)]
                 [node (make-memfs-node
                         ino 'symlink
                         (bitwise-ior S-IFLNK #o777)
                         (fuse-context-uid ctx) (fuse-context-gid ctx)
                         now now now 1
                         target (string-length target))])
            (eq-hashtable-set! (memfs-state-inodes fs) ino node)
            (hashtable-set! (memfs-node-data parent) name ino)
            (node->fuse-entry node))
          #f))))

  (define (make-memfs-readlink fs)
    (lambda (ino ctx)
      (let ([node (get-node fs ino)])
        (and node (eq? (memfs-node-type node) 'symlink)
             (memfs-node-data node)))))

  (define (make-memfs-link fs)
    (lambda (new-parent-ino new-name old-ino ctx)
      (let ([parent (get-node fs new-parent-ino)]
            [target (get-node fs old-ino)])
        (if (and parent target (eq? (memfs-node-type parent) 'dir))
          (begin
            (hashtable-set! (memfs-node-data parent) new-name old-ino)
            (memfs-node-nlink-set! target (+ (memfs-node-nlink target) 1))
            (node->fuse-entry target))
          #f))))

  (define (make-memfs-statfs fs)
    (lambda (ctx)
      (let ([count (eq-hashtable-size (memfs-state-inodes fs))])
        (make-fuse-statfs
          1048576              ;; blocks (4GB at 4K blocks)
          (- 1048576 count)    ;; bfree
          (- 1048576 count)    ;; bavail
          1000000              ;; files (max inodes)
          (- 1000000 count)    ;; ffree
          4096                 ;; bsize
          255                  ;; namelen
          4096))))             ;; frsize

  ;; ---- Utilities ----

  ;; eq-hashtable-keys: extract key vector from an eq-hashtable.
  (define (eq-hashtable-keys ht)
    (let-values ([(keys vals) (hashtable-entries ht)])
      keys))

  ;; eq-hashtable-size: number of entries in an eq-hashtable.
  (define (eq-hashtable-size ht)
    (vector-length (eq-hashtable-keys ht)))

) ;; end library
