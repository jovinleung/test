# =====================================================
#  Padavan Firmware Build System - Top-Level Makefile
#  Author: TurBoTse (Optimized for clarity and scalability)
#  Description: Professional, modular, and scalable firmware pipeline
# =====================================================

TOPDIR          := $(CURDIR)
SOURCE_DIR      := $(TOPDIR)/trunk
TEMPLATE_DIR    := $(SOURCE_DIR)/configs/templates
CONFIG_FILE     := $(SOURCE_DIR)/.config

# Toolchain Settings
TOOLCHAIN       ?= mipsel-linux-musl
TOOLCHAIN_ROOT  := $(TOPDIR)/toolchain
TOOLCHAIN_PATH  := $(TOOLCHAIN_ROOT)/$(TOOLCHAIN)
TOOLCHAIN_URL   := https://github.com/jovinleung/test/releases/download/toolchain/$(TOOLCHAIN).tar.xz

# Auto-discovered target products
PRODUCTS        := $(notdir $(basename $(wildcard $(TEMPLATE_DIR)/*.config)))

.PHONY: all build clean prepare-headers $(PRODUCTS)

all: build
build:
	@echo "\033[1;36m===> 🔎 Verifying toolchain availability...\033[0m"
	@if [ ! -d "$(TOOLCHAIN_PATH)/bin" ]; then \
		echo "\033[1;36m===> 📂 Creating toolchain directory...\033[0m"; \
		mkdir -p "$(TOOLCHAIN_PATH)"; \
		echo "\033[1;33m===> ⬇️  Downloading prebuilt toolchain...\033[0m"; \
		curl -fL --retry 3 --progress-bar "$(TOOLCHAIN_URL)" | tar -xJ -C "$(TOOLCHAIN_PATH)" || { \
			echo "\033[1;31m===> ❌ Toolchain download failed. Building from source...\033[0m"; \
			rm -rf "$(TOOLCHAIN_PATH)"; \
			$(MAKE) -C "$(TOPDIR)/toolchain" build CT_PREFIX="$(TOOLCHAIN_PATH)" CT_TARGET="$(TOOLCHAIN)" || exit 1; \
		}; \
	fi
	@echo "\033[1;32m===> ✅ Toolchain ready:\033[0m \033[1;34m$(TOOLCHAIN)\033[0m"
	@$(MAKE) prepare-headers

	@echo "\033[1;36m===> 🔎 Validating firmware configuration...\033[0m"
	@if [ ! -f "$(CONFIG_FILE)" ]; then \
		echo "\033[1;31m===> ❌ Missing .config file.\033[0m"; \
		echo "\033[1;36m===> 💡 Available build targets:\033[0m"; \
		for p in $(PRODUCTS); do echo "  - $$p"; done; \
		exit 1; \
	fi

	@echo "\033[1;32m===> 🛠️  Initiating firmware compilation...\033[0m"
	@$(MAKE) -C $(SOURCE_DIR)

# Ensure sys/queue.h exists for musl-based toolchain (required by some source files)
QUEUE_H     := $(TOOLCHAIN_PATH)/$(TOOLCHAIN)/sysroot/usr/include/sys/queue.h
QUEUE_H_URL := https://raw.githubusercontent.com/bminor/glibc/master/misc/sys/queue.h

ifeq ($(TOOLCHAIN),mipsel-linux-musl)
prepare-headers:
	@echo "\033[1;36m===> 🔎 Checking sys/queue.h...\033[0m"
	@if [ ! -f "$(QUEUE_H)" ]; then \
		echo "\033[1;36m===> ⬇️  Installing sys/queue.h...\033[0m"; \
		curl -fL --retry 3 --progress-bar "$(QUEUE_H_URL)" -o "$(QUEUE_H)" || { \
			echo "\033[1;31m===> ❌ queue.h installation failed. Check your network or URL.\033[0m"; exit 1; }; \
		echo "\033[1;32m===> ✅ queue.h successfully installed.\033[0m"; \
	else \
		echo "\033[1;32m===> ✅ sys/queue.h already exists.\033[0m"; \
	fi
else
prepare-headers:
	@true
endif

clean:
	@echo "\033[1;36m===> 🧼 Cleaning build environment...\033[0m"
	@$(MAKE) -C $(SOURCE_DIR) clean
	@rm -f $(CONFIG_FILE)
	@rm -rf $(TOOLCHAIN_PATH)
	@echo "\033[1;32m===> ♻️  Clean operation completed.\033[0m"

# Target: Device-specific firmware configuration and build
$(PRODUCTS):
	@echo "\033[1;36m===> ⚙️  Setting up configuration for target: $@...\033[0m"
	@cp -f "$(TEMPLATE_DIR)/$@.config" "$(CONFIG_FILE)"
	@echo >> "$(CONFIG_FILE)"
	@echo "CONFIG_CROSS_COMPILER_ROOT=$(TOOLCHAIN_PATH)" >> "$(CONFIG_FILE)"
	@echo "CONFIG_TOOLCHAIN=$(TOOLCHAIN)" >> "$(CONFIG_FILE)"
	@echo "CONFIG_CCACHE=y" >> "$(CONFIG_FILE)"
	@echo "\033[1;32m===> 📝  Configuration generated: $(CONFIG_FILE)\033[0m"
	@$(MAKE) build
