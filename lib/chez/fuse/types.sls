(library (chez fuse types)
  (export
    ;; fuse-attr
    make-fuse-attr fuse-attr?
    fuse-attr-ino fuse-attr-size fuse-attr-blocks
    fuse-attr-atime fuse-attr-mtime fuse-attr-ctime
    fuse-attr-atimensec fuse-attr-mtimensec fuse-attr-ctimensec
    fuse-attr-mode fuse-attr-nlink fuse-attr-uid fuse-attr-gid
    fuse-attr-rdev fuse-attr-blksize

    ;; fuse-entry
    make-fuse-entry fuse-entry?
    fuse-entry-nodeid fuse-entry-generation
    fuse-entry-entry-valid fuse-entry-entry-valid-nsec
    fuse-entry-attr-valid fuse-entry-attr-valid-nsec
    fuse-entry-attr

    ;; fuse-request (decoded incoming request)
    make-fuse-request fuse-request?
    fuse-request-len fuse-request-opcode fuse-request-unique
    fuse-request-nodeid fuse-request-uid fuse-request-gid
    fuse-request-pid

    ;; fuse-dirent
    make-fuse-dirent fuse-dirent?
    fuse-dirent-ino fuse-dirent-off fuse-dirent-type fuse-dirent-name

    ;; fuse-statfs
    make-fuse-statfs fuse-statfs?
    fuse-statfs-blocks fuse-statfs-bfree fuse-statfs-bavail
    fuse-statfs-files fuse-statfs-ffree
    fuse-statfs-bsize fuse-statfs-namelen fuse-statfs-frsize

    ;; fuse-context (per-request caller info)
    make-fuse-context fuse-context?
    fuse-context-uid fuse-context-gid fuse-context-pid

    ;; fuse-session (runtime state)
    make-fuse-session fuse-session?
    fuse-session-fd fuse-session-fd-set!
    fuse-session-mountpoint fuse-session-mountpoint-set!
    fuse-session-mounted? fuse-session-mounted?-set!
    fuse-session-running? fuse-session-running?-set!
    fuse-session-proto-major fuse-session-proto-major-set!
    fuse-session-proto-minor fuse-session-proto-minor-set!
    fuse-session-max-write fuse-session-max-write-set!
    fuse-session-max-readahead fuse-session-max-readahead-set!
    fuse-session-ops fuse-session-ops-set!
    fuse-session-mutex fuse-session-mutex-set!
    fuse-session-thread fuse-session-thread-set!
    fuse-session-done fuse-session-done-set!)

  (import (chezscheme))

  ;; ---- fuse-attr ----
  ;; Mirrors the 88-byte fuse_attr struct.
  (define-record-type fuse-attr
    (fields
      (immutable ino)
      (immutable size)
      (immutable blocks)
      (immutable atime)
      (immutable mtime)
      (immutable ctime)
      (immutable atimensec)
      (immutable mtimensec)
      (immutable ctimensec)
      (immutable mode)
      (immutable nlink)
      (immutable uid)
      (immutable gid)
      (immutable rdev)
      (immutable blksize)))

  ;; ---- fuse-entry ----
  ;; Response for LOOKUP, CREATE, MKDIR, MKNOD, SYMLINK, LINK.
  (define-record-type fuse-entry
    (fields
      (immutable nodeid)
      (immutable generation)
      (immutable entry-valid)       ;; seconds
      (immutable entry-valid-nsec)
      (immutable attr-valid)        ;; seconds
      (immutable attr-valid-nsec)
      (immutable attr)))            ;; fuse-attr record

  ;; ---- fuse-request ----
  ;; Decoded fuse_in_header (40 bytes).
  (define-record-type fuse-request
    (fields
      (immutable len)
      (immutable opcode)
      (immutable unique)
      (immutable nodeid)
      (immutable uid)
      (immutable gid)
      (immutable pid)))

  ;; ---- fuse-dirent ----
  ;; A directory entry for READDIR response packing.
  (define-record-type fuse-dirent
    (fields
      (immutable ino)
      (immutable off)        ;; offset cookie for next entry
      (immutable type)       ;; DT_* constant
      (immutable name)))     ;; string

  ;; ---- fuse-statfs ----
  ;; Filesystem statistics for STATFS response.
  (define-record-type fuse-statfs
    (fields
      (immutable blocks)
      (immutable bfree)
      (immutable bavail)
      (immutable files)
      (immutable ffree)
      (immutable bsize)
      (immutable namelen)
      (immutable frsize)))

  ;; ---- fuse-context ----
  ;; Per-request caller identity (extracted from in-header).
  (define-record-type fuse-context
    (fields
      (immutable uid)
      (immutable gid)
      (immutable pid)))

  ;; ---- fuse-session ----
  ;; Mutable runtime state for a mounted FUSE session.
  (define-record-type fuse-session
    (fields
      (mutable fd)
      (mutable mountpoint)
      (mutable mounted?)
      (mutable running?)
      (mutable proto-major)
      (mutable proto-minor)
      (mutable max-write)
      (mutable max-readahead)
      (mutable ops)           ;; hashtable of symbol -> procedure
      (mutable mutex)         ;; dispatch mutex for thread safety
      (mutable thread)        ;; background thread handle (or #f)
      (mutable done)))        ;; completion flag

) ;; end library
