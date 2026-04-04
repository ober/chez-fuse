(library (chez vault crypto)
  (export
    vault-rand-bytes
    vault-pbkdf2
    vault-block-key
    vault-encrypt-block    ;; BLOCK-PAYLOAD bytes → BLOCK-SIZE bytes
    vault-decrypt-block    ;; BLOCK-SIZE bytes → BLOCK-PAYLOAD bytes or #f
    vault-encrypt-small    ;; N bytes → (12+N+16) bytes
    vault-decrypt-small)   ;; (12+N+16) bytes → N bytes or #f

  (import (chezscheme)
          (chez vault format))

  ;; ---- Load libcrypto ----
  ;; Same load pattern as (std crypto aead) and (std crypto password).

  (define _loaded
    (or (guard (e [#t #f]) (load-shared-object "libcrypto.so") #t)
        (guard (e [#t #f]) (load-shared-object "libcrypto.so.3") #t)
        (guard (e [#t #f]) (load-shared-object "libcrypto.so.35") #t)
        #f))

  ;; ---- FFI bindings ----

  (define c-rand-bytes
    (if _loaded
      (foreign-procedure "RAND_bytes" (u8* int) int)
      (lambda (bv n) (error 'vault-crypto "libcrypto not available"))))

  (define c-evp-sha256
    (if _loaded
      (foreign-procedure "EVP_sha256" () uptr)
      (lambda () 0)))

  (define c-pbkdf2
    (if _loaded
      (foreign-procedure "PKCS5_PBKDF2_HMAC" (u8* int u8* int int uptr int u8*) int)
      (lambda args (error 'vault-crypto "libcrypto not available"))))

  (define c-ctx-new
    (if _loaded
      (foreign-procedure "EVP_CIPHER_CTX_new" () uptr)
      (lambda () 0)))

  (define c-ctx-free
    (if _loaded
      (foreign-procedure "EVP_CIPHER_CTX_free" (uptr) void)
      (lambda (x) (void))))

  (define c-aes-256-gcm
    (if _loaded
      (foreign-procedure "EVP_aes_256_gcm" () uptr)
      (lambda () 0)))

  (define c-enc-init
    (if _loaded
      (foreign-procedure "EVP_EncryptInit_ex" (uptr uptr uptr u8* u8*) int)
      (lambda args 0)))

  (define c-enc-update
    (if _loaded
      (foreign-procedure "EVP_EncryptUpdate" (uptr u8* u8* u8* int) int)
      (lambda args 0)))

  (define c-enc-final
    (if _loaded
      (foreign-procedure "EVP_EncryptFinal_ex" (uptr u8* u8*) int)
      (lambda args 0)))

  (define c-ctx-ctrl
    (if _loaded
      (foreign-procedure "EVP_CIPHER_CTX_ctrl" (uptr int int u8*) int)
      (lambda args 0)))

  (define c-dec-init
    (if _loaded
      (foreign-procedure "EVP_DecryptInit_ex" (uptr uptr uptr u8* u8*) int)
      (lambda args 0)))

  (define c-dec-update
    (if _loaded
      (foreign-procedure "EVP_DecryptUpdate" (uptr u8* u8* u8* int) int)
      (lambda args 0)))

  (define c-dec-final
    (if _loaded
      (foreign-procedure "EVP_DecryptFinal_ex" (uptr u8* u8*) int)
      (lambda args 0)))

  (define GCM-GET-TAG #x10)
  (define GCM-SET-TAG #x11)

  ;; ---- vault-rand-bytes ----

  (define (vault-rand-bytes n)
    (let ([bv (make-bytevector n 0)])
      (let ([r (c-rand-bytes bv n)])
        (unless (= r 1) (error 'vault-rand-bytes "RAND_bytes failed"))
        bv)))

  ;; ---- vault-pbkdf2 ----
  ;; PBKDF2-HMAC-SHA256(password, salt, iterations, key-len)
  ;; Used for:
  ;;   (vault-pbkdf2 passphrase salt KDF-ITERATIONS 32) → passphrase-key
  ;;   (vault-pbkdf2 master-key block-num-bv 1 32)      → per-block-key

  (define (vault-pbkdf2 password-bv salt-bv iterations key-len)
    (let ([out (make-bytevector key-len 0)])
      (let ([r (c-pbkdf2
                 password-bv (bytevector-length password-bv)
                 salt-bv     (bytevector-length salt-bv)
                 iterations
                 (c-evp-sha256)
                 key-len out)])
        (unless (= r 1) (error 'vault-pbkdf2 "PKCS5_PBKDF2_HMAC failed"))
        out)))

  ;; ---- vault-block-key ----
  ;; Derive a unique per-block encryption key from the master key.
  ;; Uses PBKDF2 with 1 iteration (= single HMAC-SHA256 call) — fast.

  (define (vault-block-key master-key block-num)
    (let ([salt (make-bytevector 8 0)])
      (bv-set-u64le! salt 0 block-num)
      (vault-pbkdf2 master-key salt 1 VAULT-KEY-LEN)))

  ;; ---- AES-256-GCM core ----
  ;; Output format: nonce[12] || ciphertext[N] || tag[16]

  (define (gcm-encrypt key plaintext-bv)
    (let* ([pt-len  (bytevector-length plaintext-bv)]
           [nonce   (vault-rand-bytes BLOCK-NONCE-LEN)]
           [ct      (make-bytevector pt-len 0)]
           [tag     (make-bytevector BLOCK-TAG-LEN 0)]
           [outlen  (make-bytevector 4 0)]
           [ctx     (c-ctx-new)])
      (when (= ctx 0) (error 'vault-encrypt "EVP_CIPHER_CTX_new failed"))
      (dynamic-wind
        (lambda () (void))
        (lambda ()
          (c-enc-init   ctx (c-aes-256-gcm) 0 key nonce)
          (c-enc-update ctx ct outlen plaintext-bv pt-len)
          (c-enc-final  ctx (make-bytevector BLOCK-TAG-LEN) outlen)
          (c-ctx-ctrl   ctx GCM-GET-TAG BLOCK-TAG-LEN tag)
          (let ([result (make-bytevector (+ BLOCK-NONCE-LEN pt-len BLOCK-TAG-LEN))])
            (bytevector-copy! nonce 0 result 0                           BLOCK-NONCE-LEN)
            (bytevector-copy! ct    0 result BLOCK-NONCE-LEN             pt-len)
            (bytevector-copy! tag   0 result (+ BLOCK-NONCE-LEN pt-len)  BLOCK-TAG-LEN)
            result))
        (lambda () (c-ctx-free ctx)))))

  (define (gcm-decrypt key ciphertext-bv)
    ;; Returns plaintext bytevector or #f on authentication failure
    (let* ([total  (bytevector-length ciphertext-bv)]
           [ct-len (- total BLOCK-NONCE-LEN BLOCK-TAG-LEN)])
      (if (< ct-len 0) #f
        (let* ([nonce  (bv-sub ciphertext-bv 0 BLOCK-NONCE-LEN)]
               [ct     (bv-sub ciphertext-bv BLOCK-NONCE-LEN ct-len)]
               [tag    (bv-sub ciphertext-bv (+ BLOCK-NONCE-LEN ct-len) BLOCK-TAG-LEN)]
               [pt     (make-bytevector ct-len 0)]
               [outlen (make-bytevector 4 0)]
               [ctx    (c-ctx-new)])
          (when (= ctx 0) (error 'vault-decrypt "EVP_CIPHER_CTX_new failed"))
          (dynamic-wind
            (lambda () (void))
            (lambda ()
              (c-dec-init   ctx (c-aes-256-gcm) 0 key nonce)
              (c-ctx-ctrl   ctx GCM-SET-TAG BLOCK-TAG-LEN tag)
              (c-dec-update ctx pt outlen ct ct-len)
              (let ([final-r (c-dec-final ctx (make-bytevector BLOCK-TAG-LEN) outlen)])
                (if (= final-r 1) pt #f)))
            (lambda () (c-ctx-free ctx)))))))

  ;; ---- Public API ----

  (define (vault-encrypt-block key payload)
    ;; payload: BLOCK-PAYLOAD (4068) bytes → BLOCK-SIZE (4096) bytes
    (gcm-encrypt key payload))

  (define (vault-decrypt-block key block-bv)
    ;; block-bv: BLOCK-SIZE (4096) bytes → BLOCK-PAYLOAD (4068) bytes or #f
    (gcm-decrypt key block-bv))

  (define (vault-encrypt-small key plaintext-bv)
    ;; For encrypting small fields (master key, superblock block num)
    (gcm-encrypt key plaintext-bv))

  (define (vault-decrypt-small key ciphertext-bv)
    ;; Returns plaintext or #f on failure
    (gcm-decrypt key ciphertext-bv))

) ;; end library
