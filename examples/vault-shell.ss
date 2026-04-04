;;; vault-shell.ss — Mount an encrypted vault as a FUSE filesystem
;;;
;;; Usage:
;;;   scheme --libdirs lib --script examples/vault-shell.ss <vault-file> <mountpoint>
;;;
;;; Creates the vault if it doesn't exist, then mounts it.
;;; The vault stays mounted until you press Enter.
;;;
;;; Example:
;;;   make all
;;;   scheme --libdirs lib --script examples/vault-shell.ss /tmp/my.vault /mnt/vault

(import (chezscheme))
(import (chez vault))

(define (usage)
  (display "Usage: vault-shell.ss <vault-file> <mountpoint>") (newline)
  (exit 1))

(define args (command-line))
(when (< (length args) 3) (usage))

(define vault-path  (cadr args))
(define mountpoint  (caddr args))
(define passphrase
  (begin
    (display "Passphrase: ")
    (flush-output-port (current-output-port))
    (get-line (current-input-port))))

(define handle
  (if (file-exists? vault-path)
    (begin
      (display "Opening existing vault...") (newline)
      (vault-mount! vault-path passphrase mountpoint))
    (begin
      (display "Creating new vault (1 GiB)...") (newline)
      (let ([v (vault-create! vault-path passphrase (quotient (* 1024 1024 1024) 4096))])
        (vault-close! v))
      (display "Mounting...") (newline)
      (vault-mount! vault-path passphrase mountpoint))))

(display "Vault mounted at ") (display mountpoint) (newline)
(display "Press Enter to unmount and exit.") (newline)
(get-line (current-input-port))

(display "Unmounting...") (newline)
(vault-unmount! handle)
(display "Done.") (newline)
