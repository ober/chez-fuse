#!/usr/bin/env scheme --libdirs lib --script
;;
;; memfs.ss — in-memory read/write FUSE filesystem
;;
;; Mounts a fully writable in-memory filesystem.
;; Demonstrates fuse-start-background! for non-blocking mount,
;; programmatic file creation, and clean shutdown.
;;
;; Usage (needs root or fusefs loaded):
;;   mkdir -p /tmp/memfs
;;   scheme --libdirs lib --script examples/memfs.ss /tmp/memfs
;;
;; Then in another terminal:
;;   ls /tmp/memfs            → docs/ readme.txt
;;   cat /tmp/memfs/readme.txt
;;   echo "hello" > /tmp/memfs/new.txt
;;   mkdir /tmp/memfs/mydir
;;   ls /tmp/memfs/docs/
;;

(import (jerboa prelude))
(import (chez fuse))
(import (chez fuse memfs))

(def (main args)
  (when (< (length args) 2)
    (displayln "Usage: memfs.ss <mountpoint>")
    (exit 1))

  (def mountpoint (cadr args))

  ;; Create the in-memory filesystem
  (def fs (make-memfs))

  ;; Pre-populate with some content
  (memfs-create-file! fs "/readme.txt"
    "Welcome to chez-fuse memfs!\n\nThis is a fully in-memory filesystem.\nAnything you write here lives in Scheme memory.\n")

  (memfs-create-dir! fs "/docs")
  (memfs-create-file! fs "/docs/api.txt"
    "chez-fuse API\n=============\n\n(make-fuse-filesystem 'op handler ...)\n(fuse-start! ops mountpoint options ...)\n(fuse-start-background! ops mountpoint options ...)\n(fuse-session-destroy! session)\n")

  (memfs-create-dir! fs "/tmp")
  (memfs-create-file! fs "/tmp/scratch.txt" "")

  ;; Mount in background so we can keep running
  (def session
    (fuse-start-background!
      (memfs->fuse-ops fs)
      mountpoint
      'fsname "memfs"
      'debug #f))

  (displayln "memfs mounted at " mountpoint)
  (displayln "Files pre-populated: /readme.txt  /docs/api.txt  /tmp/scratch.txt")
  (displayln "Press Enter or Ctrl-C to unmount and exit.")

  ;; Install Ctrl-C handler for clean shutdown
  (keyboard-interrupt-handler
    (lambda ()
      (displayln "\nUnmounting...")
      (fuse-session-destroy! session)
      (exit 0)))

  ;; Block waiting for input so the mount stays alive
  (read-char)

  ;; Clean shutdown
  (displayln "Unmounting " mountpoint "...")
  (fuse-session-destroy! session)
  (displayln "Done."))

(main (command-line))
