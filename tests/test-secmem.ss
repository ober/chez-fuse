;;; test-secmem.ss — tests for secure memory (mlock'd key storage)
;;; Run with: scheme --libdirs lib --script tests/test-secmem.ss

(import (chezscheme))
(import (chez fuse secmem))

(define pass 0)
(define fail 0)

(define (test-assert name expr)
  (if expr
    (begin (set! pass (+ pass 1))
           (display "  PASS: ") (display name) (newline))
    (begin (set! fail (+ fail 1))
           (display "  FAIL: ") (display name) (newline))))

(display "=== secure memory ===") (newline)

;; Basic alloc/free
(let ([p (secmem-alloc 32)])
  (test-assert "secmem-alloc returns non-#f" (not (eq? p #f)))
  (test-assert "secmem-alloc returns non-zero" (not (= p 0)))
  (secmem-free! p 32)
  (test-assert "secmem-free completes" #t))

;; Secure key lifecycle
(display "=== secure key ===") (newline)

(let* ([bv (make-bytevector 32 0)])
  ;; Fill with known data
  (do ([i 0 (+ i 1)]) ((= i 32))
    (bytevector-u8-set! bv i (+ i 42)))

  (let ([sk (make-secure-key bv)])
    ;; Source bytevector should be zeroed
    (test-assert "source bv zeroed after make-secure-key"
      (= (bytevector-u8-ref bv 0) 0))

    (test-assert "secure-key? returns #t" (secure-key? sk))
    (test-assert "secure-key-live? returns #t" (secure-key-live? sk))
    (test-assert "secure-key-size is 32" (= (secure-key-size sk) 32))

    ;; Borrow and verify content
    (let ([borrowed (secure-key-borrow sk)])
      (test-assert "borrowed key has correct first byte"
        (= (bytevector-u8-ref borrowed 0) 42))
      (test-assert "borrowed key has correct last byte"
        (= (bytevector-u8-ref borrowed 31) 73))
      (bytevector-fill! borrowed 0))  ;; clean up

    ;; call-with-secure-key
    (let ([result
           (call-with-secure-key sk
             (lambda (key-bv)
               ;; Key should be valid inside the callback
               (bytevector-u8-ref key-bv 0)))])
      (test-assert "call-with-secure-key returns value" (= result 42)))

    ;; Destroy
    (secure-key-destroy! sk)
    (test-assert "after destroy: not live" (not (secure-key-live? sk)))

    ;; Borrow after destroy should error
    (let ([got-error
           (guard (exn [#t #t])
             (secure-key-borrow sk)
             #f)])
      (test-assert "borrow after destroy raises error" got-error))))

;; Summary
(newline)
(display "PASS: ") (display pass) (newline)
(display "FAIL: ") (display fail) (newline)
(when (> fail 0) (exit 1))
(display "All tests passed!") (newline)
