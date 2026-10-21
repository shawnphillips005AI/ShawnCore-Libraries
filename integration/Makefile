# C integration checks for the ShawnCore static library.
#
# Targets:
#   make            - build and run the smoke test (default)
#   make syntax     - syntax-only check of the HAL stub file
#   make cxx        - build and run the C++ smoke test (header must parse as C++)
#   make smoke      - build the smoke executable
#   make run        - run the smoke executable
#   make asan       - build and run the smoke executable under AddressSanitizer
#   make valgrind   - run the smoke executable under Valgrind
#   make clean      - remove the executables produced here
#
# `make`, `make smoke`, `make run`, and `make asan` build the Rust static
# library automatically. `make syntax` checks the HAL template only.
#
# Note: the sanitizer/Valgrind targets instrument only the C caller and the
# linked archive. They do not instrument Rust dependencies unless the archive is
# rebuilt with a working Rust sanitizer configuration.

ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CC        ?= cc
CXX       ?= c++
CARGO     ?= cargo
CSTD      ?= -std=c11
CXXSTD    ?= -std=c++17
CWARN     ?= -Wall -Wextra -Werror
INCLUDE   := -I $(ROOT)/shawncore-ffi/include
PROFILE   ?= release
STATICLIB := $(ROOT)/target/$(PROFILE)/libshawncore_ffi.a
BUILDDIR  ?= $(ROOT)/target/c-integration

ifeq ($(PROFILE),release)
CARGO_PROFILE_FLAG := --release
else ifeq ($(PROFILE),debug)
CARGO_PROFILE_FLAG :=
else
$(error PROFILE must be "release" or "debug")
endif

SMOKE_SRC := $(ROOT)/integration/c_api_smoke.c
HAL_SRC   := $(ROOT)/integration/hal_stubs.c
SMOKE_BIN := $(BUILDDIR)/shawncore-c-api-smoke
CXX_SRC   := $(ROOT)/integration/cxx_smoke.cpp
CXX_BIN   := $(BUILDDIR)/shawncore-cxx-smoke
ASAN_BIN  := $(BUILDDIR)/shawncore-c-api-smoke-asan

.PHONY: all syntax rustlib smoke run cxx asan valgrind clean

all: run

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

rustlib:
	$(CARGO) build --manifest-path $(ROOT)/Cargo.toml --package shawncore-ffi $(CARGO_PROFILE_FLAG)

syntax: $(HAL_SRC)
	$(CC) $(CSTD) $(CWARN) $(INCLUDE) -fsyntax-only $(HAL_SRC)

smoke: $(SMOKE_BIN)

$(SMOKE_BIN): rustlib $(SMOKE_SRC) | $(BUILDDIR)
	$(CC) $(CSTD) $(CWARN) $(INCLUDE) $(SMOKE_SRC) $(STATICLIB) -o $@

run: $(SMOKE_BIN)
	$(SMOKE_BIN)

$(CXX_BIN): rustlib $(CXX_SRC) | $(BUILDDIR)
	$(CXX) $(CXXSTD) $(CWARN) -pedantic $(INCLUDE) $(CXX_SRC) $(STATICLIB) -o $@

cxx: $(CXX_BIN)
	$(CXX_BIN)

$(ASAN_BIN): rustlib $(SMOKE_SRC) | $(BUILDDIR)
	$(CC) $(CSTD) $(CWARN) -fsanitize=address -fno-omit-frame-pointer \
		$(INCLUDE) $(SMOKE_SRC) $(STATICLIB) -o $@

asan: $(ASAN_BIN)
	ASAN_OPTIONS=detect_leaks=1 $(ASAN_BIN)

valgrind: $(SMOKE_BIN)
	valgrind --error-exitcode=1 --leak-check=full $(SMOKE_BIN)

clean:
	rm -f $(SMOKE_BIN) $(ASAN_BIN) $(CXX_BIN)
