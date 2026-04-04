;;
;; jsh-builtin.ss — example of integrating chez-fuse into jerboa-shell
;;
;; This shows how a jerboa-shell builtin could mount a virtual filesystem.
;; The FUSE loop runs in a background thread (fork-thread) so the shell
;; remains interactive. Cleanup happens via the EXIT trap.
;;
;; In a real jsh builtin file you would:
;;   (import (chez fuse))
;;   (import (chez fuse memfs))
;; and use defbuiltin to register the commands.
;;
;; This file can be loaded from a jsh init file:
;;   scheme --libdirs /path/to/chez-fuse/lib --script jsh-builtin.ss

(import (jerboa prelude))
(import (chez fuse))
(import (chez fuse memfs))

;; ---- Global session registry ----
;; Tracks active FUSE mounts so we can clean up on shell exit.

(def *fuse-sessions* (make-hash-table))

(def (register-mount! mountpoint session)
  (hash-put! *fuse-sessions* mountpoint session))

(def (unregister-mount! mountpoint)
  (hash-remove! *fuse-sessions* mountpoint))

(def (unmount-all!)
  (for ((mp (hash-keys *fuse-sessions*)))
    (def session (hash-get *fuse-sessions* mp))
    (when session
      (displayln "chez-fuse: unmounting " mp)
      (guard (exn [else (void)])
        (fuse-session-destroy! session)))
    (unregister-mount! mp)))

;; ---- Builtin: mount-memfs <mountpoint> ----
;;
;; Usage in jsh:  mount-memfs /tmp/scratch
;;
;; Mounts a fresh in-memory filesystem at <mountpoint>.
;; Stays alive until unmount-fuse or shell exit.

(def (builtin-mount-memfs args env)
  (when (< (length args) 2)
    (displayln "Usage: mount-memfs <mountpoint>")
    (return 1))
  (def mountpoint (cadr args))
  (def fs (make-memfs))
  (def session
    (fuse-start-background!
      (memfs->fuse-ops fs)
      mountpoint
      'fsname "jsh-memfs"))
  (register-mount! mountpoint session)
  (displayln "mounted memfs at " mountpoint)
  0)

;; ---- Builtin: unmount-fuse <mountpoint> ----

(def (builtin-unmount-fuse args env)
  (when (< (length args) 2)
    (displayln "Usage: unmount-fuse <mountpoint>")
    (return 1))
  (def mountpoint (cadr args))
  (def session (hash-get *fuse-sessions* mountpoint))
  (if session
    (begin
      (fuse-session-destroy! session)
      (unregister-mount! mountpoint)
      (displayln "unmounted " mountpoint)
      0)
    (begin
      (displayln "unmount-fuse: not mounted: " mountpoint)
      1)))

;; ---- Builtin: list-fuse-mounts ----

(def (builtin-list-fuse-mounts args env)
  (def mounts (hash-keys *fuse-sessions*))
  (if (null? mounts)
    (displayln "(no fuse mounts)")
    (for ((mp mounts))
      (displayln "  " mp)))
  0)

;; ---- How it would register in jsh ----
;;
;; (builtin-register! "mount-memfs"  builtin-mount-memfs)
;; (builtin-register! "unmount-fuse" builtin-unmount-fuse)
;; (builtin-register! "fuse-mounts"  builtin-list-fuse-mounts)
;;
;; And in the shell's exit hook:
;; (register-exit-hook! unmount-all!)
;;
;; Then in jsh you'd be able to:
;;   $ mount-memfs /tmp/scratch
;;   mounted memfs at /tmp/scratch
;;   $ echo "hello" > /tmp/scratch/test.txt
;;   $ cat /tmp/scratch/test.txt
;;   hello
;;   $ fuse-mounts
;;     /tmp/scratch
;;   $ unmount-fuse /tmp/scratch
;;   unmounted /tmp/scratch

;; Demo: run standalone to verify the integration code loads
(displayln "jsh-builtin.ss loaded OK")
(displayln "builtins defined: mount-memfs, unmount-fuse, fuse-mounts")
