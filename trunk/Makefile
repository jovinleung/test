############################################################################
# Top-Level Makefile for Padavan-based Firmware
#
# Copyright (c) 2001-2004, SnapGear (www.snapgear.com)
# Copyright (c) 2001, Lineo
# Copyright (c) 2025, TurBoTse
############################################################################

# === Load Build Configuration ===
include .config
include versions.inc

# === Host Environment Detection ===(override with make JOBS=N)
HOST_NCPU       := $(shell nproc 2>/dev/null || echo 1)
JOBS            ?= $(HOST_NCPU)
CONFIG_SHELL    := $(shell which bash 2>/dev/null || echo /bin/sh)

# === Directory Layout ===
ROOTDIR         := $(CURDIR)
LINUXDIR        := $(CONFIG_LINUXDIR)
LINUXINCDIR     := $(ROOTDIR)/$(LINUXDIR)/include
SCRIPTSDIR      := $(ROOTDIR)/config/scripts
ROMFSDIR        := $(ROOTDIR)/romfs
STAGEDIR        := $(ROOTDIR)/stage
IMAGEDIR        := $(ROOTDIR)/images
MERGE_DIR       := $(ROOTDIR)/merge
MERGE_ROOTFS    := $(MERGE_DIR)/$(CONFIG_FIRMWARE_PRODUCT_ID)/rootfs
LINUX_CONFIG    := $(ROOTDIR)/$(LINUXDIR)/.config
PROJECT_CONFIG  := $(ROOTDIR)/.config
TFTPDIR         := /tftpboot

# === Tool Definitions ===
DEPMOD          := $(ROOTDIR)/tools/depmod.sh
ROMFSINST       := $(ROOTDIR)/tools/romfs-inst.sh
UNPACKTRX       := $(ROOTDIR)/tools/unpack-trx.sh
STRIPROMFS      := $(ROOTDIR)/tools/strip-romfs.sh
SSTRIP_TOOL     := $(if $(filter y,$(CONFIG_FIRMWARE_PERFORM_SSTRIP)),$(ROOTDIR)/tools/sstrip/sstrip)
LZMA_TOOL       := $(ROOTDIR)/tools/lzma/lzma
MKIMAGE_TOOL    := $(ROOTDIR)/tools/mkimage/mkimage
MKSQUASHFS_TOOL := $(ROOTDIR)/tools/mksquashfs_xz/mksquashfs
UNSQSHFS_TOOL   := $(ROOTDIR)/tools/mksquashfs_xz/unsquashfs

# === Toolchain & Headers ===
CONFIG_CROSS_COMPILER_PATH  = $(CONFIG_CROSS_COMPILER_ROOT)/bin
CONFIG_CMAKE_TOOLCHAIN_FILE = $(ROOTDIR)/vendors/cmake/cross-mipsel-linux.cmake
KERNEL_HEADERS_PATH         = $(realpath $(shell $(CONFIG_CROSS_COMPILER_PATH)/$(CC) -print-sysroot)/usr/include)

ifeq ($(CONFIG_CCACHE),y)
  CCACHE_WRAPPER_DIR := $(CONFIG_CROSS_COMPILER_ROOT)/ccache-wrappers
  CCACHE_BIN := $(shell command -v ccache)
  WRAPPERS := $(addprefix $(CROSS_COMPILE), gcc g++ cc c++)
  $(shell \
    mkdir -p $(CCACHE_WRAPPER_DIR); \
    for bin in $(WRAPPERS); do \
      target="$(CCACHE_WRAPPER_DIR)/$$bin"; \
      [ -e "$$target" ] || ln -sf $(CCACHE_BIN) "$$target"; \
    done)

  PATH := $(CCACHE_WRAPPER_DIR):$(CONFIG_CROSS_COMPILER_PATH):$(PATH):$(ROOTDIR)/tools
else
  PATH := $(CONFIG_CROSS_COMPILER_PATH):$(PATH):$(ROOTDIR)/tools
endif
export PATH

# === Exported Environment ===
export \
  VENDOR PRODUCT CONFIG_SHELL HOST_NCPU JOBS \
  CONFIG_CROSS_COMPILER_ROOT CONFIG_CROSS_COMPILER_PATH CONFIG_CMAKE_TOOLCHAIN_FILE CONFIG_WITHOUT_KERNEL \
  SSTRIP_TOOL LZMA_TOOL MKIMAGE_TOOL MKSQUASHFS_TOOL UNSQSHFS_TOOL \
  PROJECT_CONFIG LINUX_CONFIG ROOTDIR LINUXDIR ROMFSDIR SCRIPTSDIR IMAGEDIR RELFILES TFTPDIR KERNEL_HEADERS_PATH \
  FIRMWARE_KERNEL_VER FIRMWARE_ROOTFS_VER FIRMWARE_BUILDS_VER FIRMWARE_BUILDS_REV VERSIONPKG VERSIONSTR \
  ROMFSINST UNPACKTRX

# === Build Targets ===
DIRS := libc libs user

.PHONY: all clean config dep tools unpack_trx linux romfs image \
        modules modules_install modules_copy bin_copy \
        sparse sparseall subdirs romfs.subdirs romfs.post tools_clean kernel_clean \
        %_romfs %_only %_clean

# === Architecture Configuration ===
ifeq ($(wildcard config.arch),config.arch)
  ifeq ($(filter %_default,$(MAKECMDGOALS)),)
    include config.arch
    export ARCH_CONFIG := $(ROOTDIR)/config.arch
  endif
endif

# === Kernel Build Commands ===
KERNEL_CROSS_COMPILE ?= $(CROSS_COMPILE)
ifeq ($(SUBARCH),)
  MAKEARCH        := $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)
  MAKEARCH_KERNEL := $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE)
else
  MAKEARCH        := $(MAKE) ARCH=$(SUBARCH) CROSS_COMPILE=$(CROSS_COMPILE)
  MAKEARCH_KERNEL := $(MAKE) ARCH=$(SUBARCH) SUBARCH=$(SUBARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE)
endif

# === Default Build Flow ===
# make [all] => config → dep → tools → (linux) → libc → libs → user → romfs → image
ifeq ($(CONFIG_WITHOUT_KERNEL),y)
all: dep tools unpack_trx libc_only libs_only user_only romfs image
else
all: dep tools linux libc_only libs_only user_only romfs image
endif

modules:
	@echo "\033[1;34m===> 📦 Building kernel modules...\033[0m"
	@if grep -q 'CONFIG_MODULES=y' $(LINUX_CONFIG); then \
		mkdir -p $(LINUXDIR)/modules; \
		$(MAKEARCH_KERNEL) -j$(JOBS) -C $(LINUXDIR) modules || { echo "\033[1;31m===> ❌ Module build failed\033[0m"; exit 1; }; \
	else \
		echo "\033[1;33m===> ⚠️  Module support disabled\033[0m"; \
	fi

modules_install:
	@echo "\033[1;34m===> 📦 Installing kernel modules into ROMFS...\033[0m"
	@if grep -q 'CONFIG_MODULES=y' $(LINUX_CONFIG); then \
		mkdir -p $(ROMFSDIR)/lib/modules; \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) INSTALL_MOD_PATH=$(ROMFSDIR) \
		  $(DEPMOD) modules_install || { echo "\033[1;31m===> ❌ Module installation failed\033[0m"; exit 1; }; \
	else \
		echo "\033[1;33m===> ⚠️  Module support disabled\033[0m"; \
	fi

modules_copy:
	@echo "\033[1;34m===> 📦 Copying merged modules...\033[0m"
	@if [ -d "$(MERGE_ROOTFS)/lib/modules" ]; then \
		mkdir -p $(ROMFSDIR)/lib/modules; \
		cp -rfa $(MERGE_ROOTFS)/lib/modules/. $(ROMFSDIR)/lib/modules/; \
	else \
		echo "\033[1;33m===> ⚠️  No modules to copy\033[0m"; \
	fi

bin_copy:
	@echo "\033[1;34m===> 📦 Copying merged binaries...\033[0m"
	@if [ -f "$(MERGE_DIR)/file_list" ]; then \
		grep -v '^#' $(MERGE_DIR)/file_list | while read -r f; do \
			if [ -f "$(MERGE_ROOTFS)/$$f" ]; then \
				mkdir -p $(dir $(ROMFSDIR)/$$f); \
				cp -fP $(MERGE_ROOTFS)/$$f $(ROMFSDIR)/$$f; \
			else \
				echo "\033[1;33m===> ⚠️  Skipping missing file: $$f\033[0m"; \
			fi; \
		done; \
	else \
		echo "\033[1;33m===> ⚠️  No binary file list found\033[0m"; \
	fi

ifeq ($(CONFIG_WITHOUT_KERNEL),y)
romfs: romfs.subdirs modules_copy bin_copy romfs.post
else
romfs: romfs.subdirs modules_install romfs.post
endif

romfs.subdirs: $(patsubst %,%_romfs,vendors $(DIRS))
	@echo "\033[1;32m===> ✅ ROMFS subdirectories completed\033[0m"

romfs.post:
	@echo "\033[1;34m===> 🧩 Post-processing ROMFS...\033[0m"
	@-find $(ROMFSDIR) -name CVS -exec rm -rf {} +
	@$(STRIPROMFS) || { echo "\033[1;31m===> ❌ ROMFS stripping failed!\033[0m"; exit 1; }
	@$(MAKEARCH) -C vendors romfs.post

image:
	@echo "\033[1;34m===> 🧱 Generating firmware image...\033[0m"
	@mkdir -p $(IMAGEDIR)
	@$(MAKEARCH) -C vendors image || { echo "\033[1;31m===> ❌ Image generation failed\033[0m"; exit 1; }

linux:
	@echo "\033[1;34m===> 🧠 Building the Linux kernel...\033[0m"
	@$(MAKEARCH_KERNEL) -j$(JOBS) -C $(LINUXDIR) $(LINUXTARGET) -s || { echo "\033[1;31m===> ❌ Kernel build failed\033[0m"; exit 1; }
	@if [ -f $(LINUXDIR)/vmlinux ]; then \
		ln -f $(LINUXDIR)/vmlinux $(LINUXDIR)/linux; \
	fi

sparse:
	@echo "\033[1;34m===> 🔍 Performing sparse check...\033[0m"
	@$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=1 $(LINUXTARGET) || exit 1

sparseall:
	@echo "\033[1;34m===> 🔍 Performing full sparse check...\033[0m"
	@$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=2 $(LINUXTARGET) || exit 1

subdirs: $(patsubst %,%_only,$(DIRS))

config:
	@echo "\033[1;34m===> 🛠️ Configuring build environment...\033[0m"
	@./configure || { echo "\033[1;31m===> ❌ Configuration failed\033[0m"; exit 1; }

ifeq ($(CONFIG_CCACHE),y)
	@echo "\033[1;32m===> ✅ ccache enabled: Checking ccache wrappers...\033[0m"
	@mkdir -p "$(CCACHE_WRAPPER_DIR)"
	@ccache_path="$(CCACHE_BIN)"; \
	for bin in $(WRAPPERS); do \
		target="$(CCACHE_WRAPPER_DIR)/$$bin"; \
		if [ -e "$$target" ]; then \
			echo "\033[1;36m→ Wrapper $$target is correct, skipping.\033[0m"; \
		else \
			echo "\033[1;36m→ Creating wrapper $$target → $$ccache_path\033[0m"; \
			ln -sf "$$ccache_path" "$$target"; \
		fi; \
	done
endif

dep: config
	@echo "\033[1;34m===> 🔍 Preparing kernel configuration...\033[0m"
	@if [ -f $(LINUX_CONFIG) ] && cmp -s $(PROJECT_CONFIG) $(LINUX_CONFIG); then \
		echo "\033[1;32m===> ✅ Kernel config unchanged, skipping olddefconfig\033[0m"; \
	else \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) olddefconfig; \
	fi

tools:
	@echo "\033[1;34m===> 📦 Building tools utilities...\033[0m"
	@$(MAKE) -C tools -s || { echo "\033[1;31m===> ❌ Tools build failed\033[0m"; exit 1; }

unpack_trx:
	@echo "\033[1;36m===> 📦 Extracting TRX firmware to merge/ directory...\033[0m"
	@$(UNPACKTRX)
	@echo "\033[1;32m===> ✅ TRX firmware unpacked.\033[0m"

clean: $(patsubst %,%_clean,tools kernel $(DIRS))
	@echo "\033[1;33m===> 🧹 Cleaning build artifacts...\033[0m"
	@rm -rf $(STAGEDIR) $(ROMFSDIR) $(IMAGEDIR) $(MERGE_DIR)
	@rm -rf $(LINUXDIR)/net/ipsec/alg/libaes $(LINUXDIR)/net/ipsec/alg/perlasm
	@rm -f $(LINUXDIR)/arch/mips/ramdisk/*.gz
	@echo "\033[1;32m===> ✅ Clean completed!\033[0m"

tools_clean:
	@echo "\033[1;33m===> 🧹 Cleaning tools...\033[0m"
	@$(MAKE) -C tools clean

kernel_clean:
	@echo "\033[1;33m===> 🧹 Cleaning kernel source: $(LINUXDIR)...\033[0m"
	@$(MAKEARCH_KERNEL) -C $(LINUXDIR) distclean

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
