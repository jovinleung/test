# =====================================================
#  Padavan Build System Makefile
#  Author: OpenAI's ChatGPT
#  Purpose: Streamlined and maintainable build process
# =====================================================

TOPDIR           := $(CURDIR)
SOURCE_DIR       := $(TOPDIR)/trunk
TEMPLATE_DIR     := $(SOURCE_DIR)/configs/templates
CONFIG           := $(SOURCE_DIR)/.config

# Toolchain Settings
TOOLCHAIN        := mipsel-linux-musl
TOOLCHAIN_ROOT   := $(TOPDIR)/toolchain
TOOLCHAIN_DIR    := $(TOOLCHAIN_ROOT)/$(TOOLCHAIN)
TOOLCHAIN_URL    := https://github.com/jovinleung/test/releases/download/toolchain/$(TOOLCHAIN).tar.xz

# Auto-discovered product targets
PRODUCTS         := $(notdir $(basename $(wildcard $(TEMPLATE_DIR)/*.config)))

.PHONY: all build clean $(PRODUCTS)

all: build

build:
	@echo "\033[1;36m🔍 Checking toolchain...\033[0m"
	@if [ ! -d "$(TOOLCHAIN_DIR)/bin" ]; then \
		echo "\033[1;33m⏳ Downloading prebuilt toolchain...\033[0m"; \
		mkdir -p "$(TOOLCHAIN_DIR)"; \
		curl -fL --progress-bar "$(TOOLCHAIN_URL)" | tar -xJ -C "$(TOOLCHAIN_DIR)" || { \
			echo "\033[1;31m❌ Download failed. Falling back to source build...\033[0m"; \
			rm -rf "$(TOOLCHAIN_DIR)"; \
			$(MAKE) -C "$(TOPDIR)/toolchain" build CT_PREFIX="$(TOOLCHAIN_DIR)" CT_TARGET="$(TOOLCHAIN)" || exit 1; \
		}; \
	fi
	@echo "\033[1;32m✅ Toolchain is ready:\033[0m \033[1;34m$(TOOLCHAIN)\033[0m"
	@$(MAKE) install-queueh

# Install sys/queue.h if missing (required by musl toolchain)
ifeq ($(TOOLCHAIN),mipsel-linux-musl)
install-queueh:
	@echo "\033[1;36m🔍 Checking sys/queue.h...\033[0m"
	@if [ ! -f "$(TOOLCHAIN_DIR)/$(TOOLCHAIN)/sysroot/usr/include/sys/queue.h" ]; then \
		echo "\033[1;36m📥 Installing sys/queue.h...\033[0m"; \
		curl -fL --progress-bar "https://raw.githubusercontent.com/bminor/glibc/master/misc/sys/queue.h" -o "$(TOOLCHAIN_DIR)/$(TOOLCHAIN)/sysroot/usr/include/sys/queue.h" || { \
			echo "\033[1;31m❌ queue.h download failed. Please check the network or URL.\033[0m"; exit 1; }; \
		echo "\033[1;32m✔️ queue.h installed successfully.\033[0m"; \
	fi
else
install-queueh:
	@true
endif

# ------------------------
# Config Validation Rule
# ------------------------

	@if [ ! -f "$(CONFIG)" ]; then \
		echo ""; \
		echo "\033[1;31m✖️ ERROR: Missing .config file\033[0m"; \
		echo "\033[1;36m💡 Available product configurations:\033[0m"; \
		for p in $(PRODUCTS); do echo "  - $$p"; done; \
		echo ""; \
		exit 1; \
	fi

	@echo "\033[1;32m🚀 Starting build process...\033[0m"
	@$(MAKE) -C $(SOURCE_DIR)

# ------------------------
# Clean Target
# ------------------------

clean:
	@echo "\033[1;36m🧹 Cleaning build artifacts...\033[0m"
	@$(MAKE) -C $(SOURCE_DIR) clean
	@rm -f $(CONFIG)
	@echo "\033[1;32m♻️ Clean completed.\033[0m"

# ------------------------
# Product-Specific Targets
# ------------------------

$(PRODUCTS):
	@echo "\033[1;36m🔧 Generating config for $@...\033[0m"
	@cp -f "$(TEMPLATE_DIR)/$@.config" "$(CONFIG)"
	@echo  >> "$(CONFIG)"
	@echo "CONFIG_CROSS_COMPILER_ROOT=$(TOOLCHAIN_DIR)" >> "$(CONFIG)"
	@echo "CONFIG_TOOLCHAIN=$(TOOLCHAIN)" >> "$(CONFIG)"
	@echo "CONFIG_CCACHE=y" >> "$(CONFIG)"
	@echo "\033[1;32m📝 Configuration file created: $(CONFIG)\033[0m"
	@$(MAKE) build
