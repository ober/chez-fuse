SCHEME = scheme
LIBDIRS = lib

CC ?= cc
CFLAGS = -Wall -Wextra -fPIC -O2

UNAME != uname -s
SOEXT = .so

.if ${UNAME} == "FreeBSD"
MOUNT_FLAGS = -DFREEBSD
.elif ${UNAME} == "Linux"
MOUNT_FLAGS = -DLINUX
.elif ${UNAME} == "Darwin"
MOUNT_FLAGS = -DDARWIN
SOEXT = .dylib
.else
MOUNT_FLAGS =
.endif

MOUNT_HELPER = src/libchez_fuse_mount${SOEXT}

.PHONY: all clean test vault-test mount umount

all: ${MOUNT_HELPER}

${MOUNT_HELPER}: src/mount_helper.c
	${CC} ${CFLAGS} ${MOUNT_FLAGS} -shared -o ${.TARGET} ${.ALLSRC}

clean:
	rm -f src/libchez_fuse_mount${SOEXT}
	find lib -name "*.so" -delete
	find lib -name "*.wpo" -delete

test: all
	${SCHEME} --libdirs ${LIBDIRS} --script tests/test-memfs.ss

vault-test: all
	${SCHEME} --libdirs ${LIBDIRS} --script tests/test-vault.ss

mount: all
	@test -n "${MOUNTPOINT}" || (echo "MOUNTPOINT required: make mount MOUNTPOINT=/tmp/hello" && exit 1)
	@mkdir -p ${MOUNTPOINT}
	${SCHEME} --libdirs ${LIBDIRS} --script examples/hello.ss ${MOUNTPOINT}

umount:
	@test -n "${MOUNTPOINT}" || (echo "MOUNTPOINT required" && exit 1)
	umount ${MOUNTPOINT} 2>/dev/null || true
