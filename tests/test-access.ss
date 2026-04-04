;;; test-access.ss — tests for the process-tree access controller
;;; Run with: scheme --libdirs lib --script tests/test-access.ss

(import (chezscheme))
(import (chez fuse access))

(define pass 0)
(define fail 0)

(define (test-assert name expr)
  (if expr
    (begin (set! pass (+ pass 1))
           (display "  PASS: ") (display name) (newline))
    (begin (set! fail (+ fail 1))
           (display "  FAIL: ") (display name) (newline))))

(display "=== access controller ===") (newline)

;; Our own PID should always be trusted
(define ac (make-access-controller))
(define my-pid
  ((foreign-procedure "chez_fuse_getpid" () int)))

(test-assert "own PID is trusted"
  (access-check ac my-pid))

;; PID 1 (init/launchd) should NOT be trusted (not our descendant)
(test-assert "PID 1 is not trusted"
  (not (access-check ac 1)))

;; A bogus PID that almost certainly doesn't exist
(test-assert "nonexistent PID is not trusted"
  (not (access-check ac 999999999)))

;; Lock should deny everything
(access-controller-lock! ac)
(test-assert "locked: own PID denied"
  (not (access-check ac my-pid)))
(test-assert "locked: controller reports locked"
  (access-controller-locked? ac))

;; Unlock should restore
(access-controller-unlock! ac)
(test-assert "unlocked: own PID trusted again"
  (access-check ac my-pid))
(test-assert "unlocked: not locked"
  (not (access-controller-locked? ac)))

;; Test pid-is-descendant? directly
(test-assert "own PID is descendant of own PID"
  (pid-is-descendant? my-pid my-pid))
(test-assert "PID 1 is not descendant of own PID"
  (not (pid-is-descendant? 1 my-pid)))

;; === Stealth deny helpers ===
(display "=== stealth deny ===") (newline)

(define sattr (stealth-deny-attr))
(test-assert "stealth attr is not #f" (not (eq? sattr #f)))

(define sdirents (stealth-deny-readdir 1))
(test-assert "stealth readdir has 2 entries" (= (length sdirents) 2))

;; Summary
(newline)
(display "PASS: ") (display pass) (newline)
(display "FAIL: ") (display fail) (newline)
(when (> fail 0) (exit 1))
(display "All tests passed!") (newline)
