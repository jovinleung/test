############################################################################
#
# Makefile -- Top level uClinux makefile.
#
# Copyright (c) 2001-2004, SnapGear (www.snapgear.com)
# Copyright (c) 2001, Lineo
#

VERSIONPKG = 1.1

############################################################################
#
# User configuration check
#

include .config
include versions.inc

ifeq ($(CONFIG_WITHOUT_KERNEL),y)
all: dep tools unpack_trx libc_only libs_only user_only romfs image
else
all: dep tools linux libc_only libs_only user_only romfs image
endif

############################################################################
#
# Core configuration
#

ROOTDIR        = $(shell pwd)
HOSTCC         = gcc
ROMFSINST      = $(ROOTDIR)/tools/romfs-inst.sh
TFTPDIR        = /tftpboot
PATH          := $(if $(filter y,$(CONFIG_CCACHE)),$(CONFIG_CROSS_COMPILER_ROOT)/lib/ccache:,)$(CONFIG_CROSS_COMPILER_ROOT)/bin:$(PATH):$(ROOTDIR)/tools

VERSIONSTR     = $(CONFIG_VENDOR)/$(CONFIG_PRODUCT) Version $(VERSIONPKG)

LINUXDIR       = $(CONFIG_LINUXDIR)
LINUXINCDIR    = $(ROOTDIR)/$(LINUXDIR)/include
IMAGEDIR       = $(ROOTDIR)/images
ROMFSDIR       = $(ROOTDIR)/romfs
STAGEDIR       = $(ROOTDIR)/stage
SCRIPTSDIR     = $(ROOTDIR)/config/scripts
LINUX_CONFIG   = $(ROOTDIR)/$(LINUXDIR)/.config
PROJECT_CONFIG = $(ROOTDIR)/.config
SSTRIP_TOOL    = $(if $(CONFIG_FIRMWARE_PERFORM_SSTRIP),$(ROOTDIR)/tools/sstrip/sstrip)
LZMA_TOOL      = $(ROOTDIR)/tools/lzma/lzma
MKIMAGE_TOOL   = $(ROOTDIR)/tools/mkimage/mkimage
MKSQUASHFS_TOOL= $(ROOTDIR)/tools/mksquashfs_xz/mksquashfs
UNSQSHFS_TOOL  = $(ROOTDIR)/tools/mksquashfs_xz/unsquashfs
MERGE_DIR      = $(ROOTDIR)/merge
MERGE_ROOTFS   = $(MERGE_DIR)/$(CONFIG_FIRMWARE_PRODUCT_ID)/rootfs

# Parallel build configuration
CPU_OVERLOAD   = 1
HOST_NCPU      = $(shell if [ -f /proc/cpuinfo ]; then n=`grep -c processor /proc/cpuinfo`; if [ $$n -gt 1 ];then expr $$n \* ${CPU_OVERLOAD}; else echo $$n; fi; else echo 1; fi)

CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	  else if [ -x /bin/bash ]; then echo /bin/bash; \
	  else echo sh; fi ; fi)

FIRMWARE_KERNEL_VER="4.4"
CONFIG_CROSS_COMPILER_PATH = $(CONFIG_CROSS_COMPILER_ROOT)/bin
CONFIG_CMAKE_TOOLCHAIN_FILE = $(ROOTDIR)/vendors/cmake/cross-mipsel-linux.cmake
KERNEL_HEADERS_PATH = $(realpath $(shell $(CONFIG_CROSS_COMPILER_ROOT)/bin/$(CC) -print-sysroot)/usr/include)

ifeq (config.arch,$(wildcard config.arch))
ifeq ($(filter %_default, $(MAKECMDGOALS)),)
include config.arch
ARCH_CONFIG = $(ROOTDIR)/config.arch
export ARCH_CONFIG
endif
endif

# Cross-compilation setup
KERNEL_CROSS_COMPILE ?= $(CROSS_COMPILE)
ifneq ($(SUBARCH),)
MAKEARCH = $(MAKE) ARCH=$(SUBARCH) CROSS_COMPILE=$(CROSS_COMPILE)
MAKEARCH_KERNEL = $(MAKE) ARCH=$(ARCH) SUBARCH=$(SUBARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE)
else
MAKEARCH = $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)
MAKEARCH_KERNEL = $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE)
endif

DIRS = libc libs user

export VENDOR PRODUCT HOSTCC CONFIG_SHELL HOST_NCPU SSTRIP_TOOL LZMA_TOOL MKIMAGE_TOOL
export PROJECT_CONFIG LINUX_CONFIG ROOTDIR LINUXDIR ROMFSDIR SCRIPTSDIR
export FIRMWARE_KERNEL_VER FIRMWARE_ROOTFS_VER FIRMWARE_BUILDS_VER FIRMWARE_BUILDS_REV
export VERSIONPKG VERSIONSTR ROMFSINST PATH IMAGEDIR RELFILES TFTPDIR
export KERNEL_HEADERS_PATH CONFIG_CROSS_COMPILER_ROOT CONFIG_CROSS_COMPILER_PATH
export CONFIG_CMAKE_TOOLCHAIN_FILE MKSQUASHFS_TOOL UNSQSHFS_TOOL CONFIG_WITHOUT_KERNEL

############################################################################
# Build Targets
############################################################################

.PHONY: modules
modules:
	@echo "\033[1;34m==> Building kernel modules...\033[0m"
	@. $(LINUXDIR)/.config; if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(LINUXDIR)/modules ] || mkdir -p $(LINUXDIR)/modules; \
		if ! $(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) modules; then \
			echo "\033[1;31mERROR: Module build failed!\033[0m"; exit 1; \
		fi; \
	else \
		echo "\033[1;33mWARNING: Module support disabled in kernel config\033[0m"; \
	fi

.PHONY: modules_install
modules_install:
	@echo "\033[1;34m==> Installing kernel modules...\033[0m"
	@. $(LINUXDIR)/.config; if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(ROMFSDIR)/lib/modules ] || mkdir -p $(ROMFSDIR)/lib/modules; \
		if ! $(MAKEARCH_KERNEL) -C $(LINUXDIR) INSTALL_MOD_PATH=$(ROMFSDIR) DEPMOD=$(ROOTDIR)/tools/depmod.sh modules_install; then \
			echo "\033[1;31mERROR: Module install failed!\033[0m"; exit 1; \
		fi; \
	fi

.PHONY: modules_copy
modules_copy:
	@echo "\033[1;34m==> Copying merged modules...\033[0m"
	[ -d $(ROMFSDIR)/lib/modules ] || mkdir -p $(ROMFSDIR)/lib/modules
	@if ! cp -rfa $(MERGE_ROOTFS)/lib/modules $(ROMFSDIR)/lib; then \
		echo "\033[1;31mERROR: Module copy failed!\033[0m"; exit 1; \
	fi

.PHONY: bin_copy
bin_copy:
	@echo "\033[1;34m==> Copying merged binaries...\033[0m"
	@for f in `grep -v "^#" $(MERGE_DIR)/file_list`; do \
		if ! cp -fP $(MERGE_ROOTFS)/$$f $(ROMFSDIR)/$$f; then \
			echo "\033[1;31mERROR: Failed to copy $$f\033[0m"; exit 1; \
		fi; \
	done

############################################################################
# Main Build Process
############################################################################

.PHONY: romfs
ifeq ($(CONFIG_WITHOUT_KERNEL),y)
romfs: romfs.subdirs modules_copy bin_copy romfs.post
else
romfs: romfs.subdirs modules_install romfs.post
endif

.PHONY: romfs.subdirs
romfs.subdirs: $(patsubst %,%_romfs,vendors $(DIRS))
	@echo "\033[1;32m==> ROMFS subdirs completed\033[0m"

.PHONY: romfs.post
romfs.post:
	@echo "\033[1;34m==> Post-processing ROMFS...\033[0m"
	@-find $(ROMFSDIR) -name CVS -exec rm -rf {} +
	@$(ROOTDIR)/tools/strip-romfs.sh || (echo "\033[1;31mERROR: ROMFS stripping failed!\033[0m"; exit 1)
	@$(MAKEARCH) -C vendors romfs.post

.PHONY: image
image:
	@echo "\033[1;34m==> Generating firmware image...\033[0m"
	@mkdir -p $(IMAGEDIR)
	@$(MAKEARCH) -C vendors image || (echo "\033[1;31mERROR: Image generation failed!\033[0m"; exit 1)

.PHONY: linux
linux:
	@echo "\033[1;34m==> Building Linux kernel...\033[0m"
	@$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) $(LINUXTARGET) || (echo "\033[1;31mERROR: Kernel build failed!\033[0m"; exit 1)
	@if [ -f $(LINUXDIR)/vmlinux ]; then \
		ln -f $(LINUXDIR)/vmlinux $(LINUXDIR)/linux; \
	fi

.PHONY: sparse
sparse:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=1 $(LINUXTARGET) || exit 1

.PHONY: sparseall
sparseall:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=2 $(LINUXTARGET) || exit 1

.PHONY: subdirs
subdirs: $(patsubst %,%_only,$(DIRS))

############################################################################
# Configuration & Clean
############################################################################

.PHONY: config dep
config:
	@echo "\033[1;34m==> Configuring build...\033[0m"
	@./configure || (echo "\033[1;31mERROR: Configuration failed!\033[0m"; exit 1)
ifeq ($(CONFIG_CCACHE),y)
	@mkdir -p $(CONFIG_CROSS_COMPILER_ROOT)/lib/ccache
	@for bin in gcc g++ cc c++; do \
		ln -sf /usr/bin/ccache $(CONFIG_CROSS_COMPILER_ROOT)/lib/ccache/$$bin; \
		ln -sf /usr/bin/ccache $(CONFIG_CROSS_COMPILER_ROOT)/lib/ccache/$(CROSS_COMPILE)$$bin; \
	done
endif

dep: config
	@$(MAKEARCH_KERNEL) -C $(LINUXDIR) olddefconfig
	@$(MAKEARCH_KERNEL) -C $(LINUXDIR) modules_prepare

.PHONY: tools
tools:
	@echo "\033[1;34m==> Building tools...\033[0m"
	@make -C tools || (echo "\033[1;31mERROR: Tools build failed!\033[0m"; exit 1)

.PHONY: unpack_trx
unpack_trx:
	@echo "\033[1;34m==> Unpacking TRX image...\033[0m"
	@unpack-trx.sh || (echo "\033[1;31mERROR: TRX unpack failed!\033[0m"; exit 1)

clean: $(patsubst %,%_clean,tools kernel $(DIRS))
	@echo "\033[1;33m==> Cleaning all artifacts...\033[0m"
	@rm -rf $(STAGEDIR) $(ROMFSDIR) $(IMAGEDIR) $(MERGE_DIR)
	@rm -rf $(LINUXDIR)/net/ipsec/alg/libaes $(LINUXDIR)/net/ipsec/alg/perlasm
	@rm -f $(LINUXDIR)/arch/mips/ramdisk/*.gz
	@echo "\033[1;32m==> Clean completed!\033[0m"

.PHONY: tools_clean
tools_clean:
	@echo "\033[1;33m==> Cleaning tools...\033[0m"
	@$(MAKE) -C tools clean

.PHONY: kernel_clean
kernel_clean:
	@echo "\033[1;33m==> Cleaning kernel...\033[0m"
	@$(MAKEARCH_KERNEL) -C $(LINUXDIR) distclean

############################################################################
# Pattern Rules
############################################################################

%_romfs:
	@case "$(@)" in \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(@:_romfs=) romfs;; \
	esac

%_only:
	@case "$(@)" in \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(@:_only=);; \
	esac

%_clean:
	@case "$(@)" in \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(@:_clean=) clean;; \
	esac

############################################################################
