.PHONY: all clean download openssl boost nlohmann_json toolchain

.DEFAULT_GOAL := all

HOST ?= x86_64-w64-mingw32
BASE_DIR := $(CURDIR)
PREFIX   := $(BASE_DIR)/$(HOST)
SOURCES  := $(BASE_DIR)/sources
WORK     := $(BASE_DIR)/work/$(HOST)

CC  := $(HOST)-gcc-posix
CXX := $(HOST)-g++-posix
AR  := $(HOST)-ar
RANLIB := $(HOST)-ranlib

JOBS ?= $(shell nproc 2>/dev/null || echo 2)

include packages/openssl.mk
include packages/boost.mk
include packages/nlohmann_json.mk

all: openssl boost nlohmann_json toolchain
	@echo
	@echo "Dependencies for $(HOST) are in $(PREFIX)"
	@echo "Build the node with:"
	@echo "  cmake -S . -B build-win -DCMAKE_BUILD_TYPE=Release \\"
	@echo "        -DCMAKE_TOOLCHAIN_FILE=depends/$(HOST)/toolchain.cmake \\"
	@echo "        -DSTATIC_DEPS=ON"

$(SOURCES) $(WORK) $(PREFIX):
	@mkdir -p $@

define fetch
	@mkdir -p $(SOURCES)
	@if [ ! -f $(SOURCES)/$(2) ]; then \
	  echo "Fetching $(2)"; \
	  curl -L --fail --progress-bar -o $(SOURCES)/$(2).part "$(1)" || \
	    { echo "Download failed: $(1)"; rm -f $(SOURCES)/$(2).part; exit 1; }; \
	  echo "$(3)  $(SOURCES)/$(2).part" | sha256sum -c - || \
	    { echo "Hash mismatch for $(2), discarded"; rm -f $(SOURCES)/$(2).part; exit 1; }; \
	  mv $(SOURCES)/$(2).part $(SOURCES)/$(2); \
	else \
	  echo "$(3)  $(SOURCES)/$(2)" | sha256sum -c - || \
	    { echo "Hash mismatch for $(2) already on disk"; exit 1; }; \
	fi
endef

download:
	$(call fetch,$(openssl_url),$(openssl_file),$(openssl_sha256))
	$(call fetch,$(boost_url),$(boost_file),$(boost_sha256))
	$(call fetch,$(nlohmann_json_url),$(nlohmann_json_file),$(nlohmann_json_sha256))

toolchain: | $(PREFIX)
	@echo "Writing $(PREFIX)/toolchain.cmake"
	@printf '%s\n' \
	  '# Written by depends/Makefile. Do not edit; it is rewritten on every run.' \
	  'set(CMAKE_SYSTEM_NAME Windows)' \
	  'set(CMAKE_SYSTEM_PROCESSOR x86_64)' \
	  '' \
	  'set(CMAKE_C_COMPILER   $(CC))' \
	  'set(CMAKE_CXX_COMPILER $(CXX))' \
	  'set(CMAKE_RC_COMPILER  $(HOST)-windres)' \
	  '' \
	  '# Look for libraries and headers here first, and only here.' \
	  'set(CMAKE_FIND_ROOT_PATH $(PREFIX))' \
	  'set(CMAKE_PREFIX_PATH    $(PREFIX))' \
	  'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' \
	  'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' \
	  'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' \
	  'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)' \
	  '' \
	  'set(OPENSSL_ROOT_DIR $(PREFIX))' \
	  'set(Boost_DIR        $(PREFIX)/lib/cmake/Boost-$(boost_version))' \
	  'set(Boost_NO_SYSTEM_PATHS ON)' \
	  'set(Boost_USE_STATIC_LIBS ON)' \
	  '# Boost here was built with runtime-link=static, and CMake refuses' \
	  '# those libraries unless it is told to expect them.' \
	  'set(Boost_USE_STATIC_RUNTIME ON)' \
	  '' \
	  '# A Windows binary that expects nothing beside it.' \
	  'set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc -static-libstdc++")' \
	  > $(PREFIX)/toolchain.cmake

clean:
	rm -rf $(WORK) $(PREFIX)

clean-sources:
	rm -rf $(SOURCES)
