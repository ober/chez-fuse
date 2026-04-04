#!/usr/bin/env scheme --libdirs lib --script
;;
;; test-memfs.ss — unit tests for the in-memory filesystem
;;

(import (jerboa prelude))
(import (chez fuse memfs))

(def pass-count 0)
(def fail-count 0)

(def (check label got expected)
  (if (equal? got expected)
    (begin
      (set! pass-count (+ pass-count 1))
      (displayln "  PASS: " label))
    (begin
      (set! fail-count (+ fail-count 1))
      (displayln "  FAIL: " label " — got " got " expected " expected))))

(def (check-true label val)
  (check label (if val #t #f) #t))

(def (check-false label val)
  (check label (if val #t #f) #f))

(displayln "=== test-memfs ===")
(newline)

;; ---- Construction ----
(displayln "-- Construction --")
(def fs (make-memfs))
(check-true  "make-memfs returns a value" fs)
(check       "root dir exists"
  (if (memfs-list-dir fs "/") #t #f) #t)

;; ---- File creation and read ----
(displayln "-- File I/O --")
(memfs-create-file! fs "/readme.txt" "Hello world!")
(check       "read after create"
  (memfs-read-file fs "/readme.txt") "Hello world!")
(check-false "read nonexistent"
  (memfs-read-file fs "/no-such-file.txt"))

;; ---- Directory creation and listing ----
(displayln "-- Directories --")
(memfs-create-dir! fs "/docs")
(def root-entries (vector->list (memfs-list-dir fs "/")))
(check-true  "root has 2 entries (readme.txt, docs)"
  (= (length root-entries) 2))

;; ---- Nested path ----
(displayln "-- Nested paths --")
(memfs-create-file! fs "/docs/api.txt" "API docs here")
(check       "read nested file"
  (memfs-read-file fs "/docs/api.txt") "API docs here")
(def docs-entries (vector->list (memfs-list-dir fs "/docs")))
(check       "docs has 1 entry" (length docs-entries) 1)

;; ---- Write (overwrite) ----
(displayln "-- Write --")
(memfs-write-file! fs "/readme.txt" "Updated content!")
(check       "read after write"
  (memfs-read-file fs "/readme.txt") "Updated content!")

;; ---- Remove file ----
(displayln "-- Remove --")
(memfs-create-file! fs "/docs/temp.txt" "temporary")
(check-true  "file exists before remove"
  (memfs-read-file fs "/docs/temp.txt"))
(memfs-remove! fs "/docs/temp.txt")
(check-false "file gone after remove"
  (memfs-read-file fs "/docs/temp.txt"))

;; ---- Remove directory ----
(memfs-create-dir! fs "/scratch")
(memfs-remove! fs "/scratch")
(check-false "dir gone after remove"
  (and (for/or ((e (in-list (vector->list (memfs-list-dir fs "/")))))
         (string=? e "scratch"))
       #t))

;; ---- Deep nesting (auto-create parents) ----
(displayln "-- Deep nesting --")
(memfs-create-file! fs "/a/b/c/deep.txt" "deep content")
(check       "read deeply nested"
  (memfs-read-file fs "/a/b/c/deep.txt") "deep content")

;; ---- Summary ----
(newline)
(displayln "Passed: " pass-count "  Failed: " fail-count)
(when (> fail-count 0)
  (exit 1))
(displayln "=== ALL TESTS PASSED ===")
