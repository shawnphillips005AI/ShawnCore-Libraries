# C integration checks for the ShawnCore static library.
#
# Targets:
#   make            - build and run the smoke test (default)
#   make syntax     - syntax-only check of the HAL stub file
#   make smoke      - build the smoke executable
#   make run        - run the smoke executable
#   make asan       - build and run the smoke executable under AddressSanitizer
#   make valgrind   - run the smoke executable under Valgrind
#   make clean      - remove the executables produced here
#
# The Rust static library must be built first:
#   cargo build -p shawncore-ffi --release
#
# Note: the sanitizer/Valgrind targets instrument only the C caller and the
# linked archive. They do not instrument Rust dependencies unless the archive is
# rebuilt with a working Rust sanitizer configuration.

ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CC        ?= cc
CSTD      ?= -std=c11
CWARN     ?= -Wall -Wextra -Werror
INCLUDE   := -I $(ROOT)/shawncore-ffi/include
PROFILE   ?= release
STATICLIB := $(ROOT)/target/$(PROFILE)/libshawncore_ffi.a
BUILDDIR  ?= $(ROOT)/target/c-integration

SMOKE_SRC := $(ROOT)/integration/c_api_smoke.c
HAL_SRC   := $(ROOT)/integration/martac_hal_stubs.c
SMOKE_BIN := $(BUILDDIR)/shawncore-c-api-smoke
ASAN_BIN  := $(BUILDDIR)/shawncore-c-api-smoke-asan

.PHONY: all syntax smoke run asan valgrind clean

all: run

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(STATICLIB):
	@echo "error: $(STATICLIB) not found." >&2
	@echo "Run: cargo build -p shawncore-ffi --release" >&2
	@false

syntax: $(HAL_SRC)
	$(CC) $(CSTD) $(CWARN) $(INCLUDE) -fsyntax-only $(HAL_SRC)

smoke: $(SMOKE_BIN)

$(SMOKE_BIN): $(SMOKE_SRC) $(STATICLIB) | $(BUILDDIR)
	$(CC) $(CSTD) $(CWARN) $(INCLUDE) $(SMOKE_SRC) $(STATICLIB) -o $@

run: $(SMOKE_BIN)
	$(SMOKE_BIN)

$(ASAN_BIN): $(SMOKE_SRC) $(STATICLIB) | $(BUILDDIR)
	$(CC) $(CSTD) $(CWARN) -fsanitize=address -fno-omit-frame-pointer \
		$(INCLUDE) $(SMOKE_SRC) $(STATICLIB) -o $@

asan: $(ASAN_BIN)
	ASAN_OPTIONS=detect_leaks=1 $(ASAN_BIN)

valgrind: $(SMOKE_BIN)
	valgrind --error-exitcode=1 --leak-check=full $(SMOKE_BIN)

clean:
	rm -f $(SMOKE_BIN) $(ASAN_BIN)
