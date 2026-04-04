#!/usr/bin/env scheme --libdirs lib --script
;;
;; hello.ss — minimal read-only FUSE filesystem
;;
;; Mounts a filesystem with a single file /hello.txt.
;; Demonstrates manual ops callbacks and signal-safe cleanup.
;;
;; Usage:
;;   mkdir -p /tmp/hello
;;   scheme --libdirs lib --script examples/hello.ss /tmp/hello
;;
;; Then in another terminal:
;;   ls /tmp/hello
;;   cat /tmp/hello/hello.txt
;;

(import (jerboa prelude))
(import (chez fuse))

(def file-content (string->utf8 "Hello from Chez FUSE!\n"))
(def file-ino 2)

(def (now) (time-second (current-time)))

(def (root-attr)
  (make-fuse-attr FUSE-ROOT-ID 0 0 (now) (now) (now) 0 0 0
    (bitwise-ior S-IFDIR #o755) 2 0 0 0 4096))

(def (file-attr)
  (make-fuse-attr file-ino (bytevector-length file-content) 1
    (now) (now) (now) 0 0 0
    (bitwise-ior S-IFREG #o444) 1 0 0 0 4096))

(def (make-entry ino attr)
  (make-fuse-entry ino 0 1 0 1 0 attr))

(def (my-lookup parent name ctx)
  (if (and (= parent FUSE-ROOT-ID) (string=? name "hello.txt"))
    (make-entry file-ino (file-attr))
    #f))

(def (my-getattr ino ctx)
  (cond [(= ino FUSE-ROOT-ID) (root-attr)]
        [(= ino file-ino)     (file-attr)]
        [else #f]))

(def (my-readdir ino fh offset ctx)
  (def entries
    (list (make-fuse-dirent FUSE-ROOT-ID 1 DT-DIR ".")
          (make-fuse-dirent FUSE-ROOT-ID 2 DT-DIR "..")
          (make-fuse-dirent file-ino     3 DT-REG "hello.txt")))
  (filter (lambda (d) (> (fuse-dirent-off d) offset)) entries))

(def (my-open ino flags ctx)
  (if (= ino file-ino) 0 #f))

(def (my-read ino fh size offset ctx)
  (if (= ino file-ino)
    (let* ([len (bytevector-length file-content)]
           [start (min offset len)]
           [count (- (min len (+ offset size)) start)])
      (if (<= count 0)
        (make-bytevector 0)
        (let ([result (make-bytevector count)])
          (bytevector-copy! file-content start result 0 count)
          result)))
    #f))

(def (my-access ino mask ctx) #t)

(def (main args)
  (when (< (length args) 2)
    (displayln "Usage: hello.ss <mountpoint>")
    (exit 1))
  (def mountpoint (cadr args))
  (displayln "Mounting hello filesystem at " mountpoint)
  (displayln "Press Ctrl-C to unmount and exit.")
  (fuse-start!
    (make-fuse-filesystem
      'lookup  my-lookup
      'getattr my-getattr
      'readdir my-readdir
      'open    my-open
      'read    my-read
      'access  my-access)
    mountpoint
    'fsname "hello-fs"
    'debug #f))

(main (command-line))
