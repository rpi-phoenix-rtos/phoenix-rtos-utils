#
# Makefile for Phoenix-RTOS nfs-smoke (libnfs port T1 feasibility gate, #153)
#
# Copyright 2026 Phoenix Systems
#
# %LICENSE%
#

NAME := nfs-smoke
LOCAL_PATH = $(call my-dir)
SRCS := $(wildcard $(LOCAL_PATH)*.c)
LOCAL_INSTALL_PATH := /bin

# Link against the libnfs port. libnfs declares no `conflicts`, so its port
# harness installs it as a "normal lib" into the flat sysroot PREFIX_A/PREFIX_H
# (not the versioned-ports tree). Those dirs are already on the global
# -L$(PREFIX_A) / -I$(PREFIX_H), so a plain -lnfs resolves the staged libnfs.a
# and <nfsc/libnfs.h>. The libnfs port (ports.yaml) must be built first.
LOCAL_LDLIBS := -lnfs

# The ifstatus parser copies fixed-width interface/IP fields with strncpy and
# explicitly NUL-terminates afterwards; -Wstringop-truncation flags the
# intentional no-trailing-NUL strncpy under the util build's -Werror. Downgrade
# just this one diagnostic (keep -Werror for everything else).
LOCAL_CFLAGS := -Wno-error=stringop-truncation

include $(binary.mk)
