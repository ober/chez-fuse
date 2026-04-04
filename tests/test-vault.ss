;;; test-vault.ss — functional tests for the vault library
;;; Run with: scheme --libdirs lib --script tests/test-vault.ss

(import (chezscheme))
(import (chez vault))

(define pass 0)
(define fail 0)

(define (test-assert name expr)
  (if expr
    (begin (set! pass (+ pass 1))
           (display "  PASS: ") (display name) (newline))
    (begin (set! fail (+ fail 1))
           (display "  FAIL: ") (display name) (newline))))

(define test-path "/tmp/chez-vault-test.bin")

(define (cleanup)
  (when (file-exists? test-path) (delete-file test-path)))

(display "=== vault create / open / close ===") (newline)

;; Test 1: Create a vault
(cleanup)
(define v1 (vault-create! test-path "secret123" 256))
(test-assert "vault-create! returns a handle" (not (eq? v1 #f)))

;; Test 2: vault->fuse-ops returns a hashtable
(define ops (vault->fuse-ops v1))
(test-assert "vault->fuse-ops returns hashtable" (eq-hashtable? ops))
(test-assert "fuse ops has getattr"  (procedure? (eq-hashtable-ref ops 'getattr  #f)))
(test-assert "fuse ops has lookup"   (procedure? (eq-hashtable-ref ops 'lookup   #f)))
(test-assert "fuse ops has readdir"  (procedure? (eq-hashtable-ref ops 'readdir  #f)))
(test-assert "fuse ops has read"     (procedure? (eq-hashtable-ref ops 'read     #f)))
(test-assert "fuse ops has write"    (procedure? (eq-hashtable-ref ops 'write    #f)))
(test-assert "fuse ops has create"   (procedure? (eq-hashtable-ref ops 'create   #f)))
(test-assert "fuse ops has mkdir"    (procedure? (eq-hashtable-ref ops 'mkdir    #f)))
(test-assert "fuse ops has unlink"   (procedure? (eq-hashtable-ref ops 'unlink   #f)))
(test-assert "fuse ops has rmdir"    (procedure? (eq-hashtable-ref ops 'rmdir    #f)))

;; Test 3: Close the vault
(vault-close! v1)
(test-assert "vault-close! completes" #t)

;; Test 4: Open the vault with correct passphrase
(define v2 (vault-open test-path "secret123"))
(test-assert "vault-open returns a handle" (not (eq? v2 #f)))
(vault-close! v2)

;; Test 5: Wrong passphrase is rejected
(define wrong-pass-rejected
  (guard (exn [#t #t])
    (vault-open test-path "wrongpassphrase")
    #f))
(test-assert "wrong passphrase rejected" wrong-pass-rejected)

;; Test 6: Open/close cycle multiple times
(let loop ([i 0])
  (when (< i 3)
    (let ([v (vault-open test-path "secret123")])
      (vault-close! v))
    (loop (+ i 1))))
(test-assert "repeated open/close OK" #t)

(display "=== vault file size ===") (newline)

;; Check file was created and has correct size
;; Size = HEADER-SIZE + total-blocks * BLOCK-SIZE = 256 + 256 * 4096
(define expected-size (+ 256 (* 256 4096)))
(define actual-size
  (call-with-port (open-file-input-port test-path)
    (lambda (p)
      (let loop ([n 0])
        (if (eof-object? (get-u8 p)) n (loop (+ n 1)))))))
(test-assert "vault file has correct size" (= actual-size expected-size))

(cleanup)

(display "=== Summary ===") (newline)
(display "PASS: ") (display pass) (newline)
(display "FAIL: ") (display fail) (newline)
(when (> fail 0) (exit 1))
(display "All tests passed!") (newline)
