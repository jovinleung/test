# ====================
#   Build Configuration
# ====================
TOPDIR         := $(CURDIR)
CT_TARGET      := mipsel-linux-musl
CT_PREFIX      := $(TOPDIR)/$(CT_TARGET)
all: build

build:
	@echo "\033[1;32m✅ Build toolchain for $(CT_TARGET)\033[0m"
	./bootstrap && \
	./configure --enable-local && \
	make && \
	./ct-ng $(CT_TARGET) && \
	./ct-ng build

clean:
	@echo "\033[1;36m♻️  Cleaning artifacts...\033[0m"
	@if [ -f ct-ng ]; then ./ct-ng distclean; fi; \
	@if [ -f Makefile ]; then make distclean; fi; \
	@if [ -d $(CT_PREFIX) ]; then rm -rf $(CT_PREFIX); fi
