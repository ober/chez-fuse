SCHEME = scheme
LIBDIRS = lib

CC ?= cc
CFLAGS = -Wall -Wextra -fPIC -O2

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),FreeBSD)
  MOUNT_FLAGS = -DFREEBSD
  SHARED_FLAG = -shared
  SOEXT = .so
else ifeq ($(UNAME_S),Linux)
  MOUNT_FLAGS = -DLINUX
  SHARED_FLAG = -shared
  SOEXT = .so
else ifeq ($(UNAME_S),Darwin)
  MOUNT_FLAGS = -DDARWIN
  SHARED_FLAG = -dynamiclib
  SOEXT = .dylib
else
  MOUNT_FLAGS =
  SHARED_FLAG = -shared
  SOEXT = .so
endif

MOUNT_HELPER = src/libchez_fuse_mount$(SOEXT)

.PHONY: all clean test vault-test mount umount

all: $(MOUNT_HELPER)

$(MOUNT_HELPER): src/mount_helper.c
	$(CC) $(CFLAGS) $(MOUNT_FLAGS) $(SHARED_FLAG) -o $@ $<

clean:
	rm -f src/libchez_fuse_mount.so src/libchez_fuse_mount.dylib
	find lib -name "*.so" -delete
	find lib -name "*.wpo" -delete

test: all
	$(SCHEME) --libdirs $(LIBDIRS) --script tests/test-memfs.ss

vault-test: all
	$(SCHEME) --libdirs $(LIBDIRS) --script tests/test-vault.ss

mount: all
	@test -n "$(MOUNTPOINT)" || (echo "MOUNTPOINT required: make mount MOUNTPOINT=/tmp/hello" && exit 1)
	@mkdir -p $(MOUNTPOINT)
	$(SCHEME) --libdirs $(LIBDIRS) --script examples/hello.ss $(MOUNTPOINT)

umount:
	@test -n "$(MOUNTPOINT)" || (echo "MOUNTPOINT required" && exit 1)
	umount $(MOUNTPOINT) 2>/dev/null || true
