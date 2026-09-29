# Makefile at repo root

# -------- OS detection (for clean commands) --------
ifeq ($(OS),Windows_NT)
SHELL := cmd
PATH_SEP := \\
RM_LOCK := del /F /Q Cargo.lock 2>nul || exit /B 0
else
SHELL := /bin/sh
PATH_SEP := /
RM_LOCK := rm -f Cargo.lock
endif

# -------- Headless package set (what CI builds/tests) --------
# Keep GUI crates (e.g., client-bevy) out of CI to avoid winit display issues.
HEADLESS_PKGS := fpp-types fpp-wire fpp-crypto fpp-merkle fpp-ffi common client-core gs-core gs-sim vs tools
PKG_FLAGS := $(foreach p,$(HEADLESS_PKGS),-p $(p))

# -------- Phonies --------
.PHONY: help ci check build-headless test-headless test-stage interop ffi-c-test ffi-c-test-i686 \
        sim-positive clean-build clean-lock-build \
        check-all build-all test-all

# -------- Help --------
help:
	@echo "Targets:"
	@echo "  ci                 - fmt+clippy only for headless crates, build, test, smoke"
	@echo "  check              - fmt+clippy (headless crates only)"
	@echo "  build-headless     - build headless crates (-p $(HEADLESS_PKGS))"
	@echo "  test-headless      - cargo test for headless crates"
	@echo "  test-stage         - test headless crates + run smoke (VS <-> GS <-> client)"
	@echo "  interop            - check FPP golden vectors with the independent Python verifier"
	@echo "  ffi-c-test         - C SDK conformance (x86_64); ffi-c-test-i686 for the Halo ABI"
	@echo "  sim-positive       - just run the smoke harness (gen_keys + smoke)"
	@echo "  clean-build        - cargo clean + fmt + build (workspace, all targets)"
	@echo "  clean-lock-build   - destructive: clean + remove Cargo.lock + fmt + build (workspace)"
	@echo "  check-all          - fmt+clippy for the whole workspace"
	@echo "  build-all          - build the whole workspace (includes GUI crates)"
	@echo "  test-all           - cargo test for the whole workspace"

# -------- CI (headless only) --------
ci:
	@echo "Lint (fmt + clippy)..."
	cargo fmt --all -- --check
	cargo clippy --all-targets $(PKG_FLAGS) -- -D warnings
	@echo "Build headless crates..."
	cargo build --all-targets $(PKG_FLAGS)
	@echo "Run tests + smoke..."
	$(MAKE) test-stage
	@echo "Interop: independent Python verifier on the FPP golden vectors..."
	$(MAKE) interop
	@echo "C SDK: conformance program against include/fpp.h + libfpp.a..."
	$(MAKE) ffi-c-test
	@echo "CI-lite completed ✅"

# -------- Local convenience (headless) --------
check:
	cargo fmt --all -- --check
	cargo clippy --all-targets $(PKG_FLAGS) -- -D warnings

build-headless:
	cargo build --all-targets $(PKG_FLAGS)

test-headless:
	cargo test --all-targets $(PKG_FLAGS)

# Run tests AND the smoke test (VS <-> gs-sim <-> client-sim happy path)
test-stage: test-headless
	@echo "Running smoke test (\`vs\` + \`gs-sim --test-once\` + \`client-sim --smoke-test\`)..."
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin smoke

# FPP v1 golden vectors, checked by the independent Python implementation.
# (The Rust side is checked by crates/fpp-crypto/tests/golden.rs.)
interop:
	python3 interop/python/fpp_interop.py

# C SDK conformance: compile a C program against only include/fpp.h and the
# static library, run it, and check that what it signs is byte-identical to the
# golden vectors and passes the independent verifier. The i686 variant is the
# ABI of the Halo: CE port (32-bit x86); it needs gcc-multilib and
# `rustup target add i686-unknown-linux-gnu`.
FFI_LIBS := -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
ffi-c-test:
	cargo build -p fpp-ffi
	cc -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/conformance.c target/debug/libfpp.a $(FFI_LIBS) -o target/fpp-conformance
	./target/fpp-conformance > target/fpp-conformance.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance.jsonl

ffi-c-test-i686:
	cargo build -p fpp-ffi --target i686-unknown-linux-gnu
	cc -m32 -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/conformance.c target/i686-unknown-linux-gnu/debug/libfpp.a $(FFI_LIBS) \
		-o target/fpp-conformance-i686
	./target/fpp-conformance-i686 > target/fpp-conformance-i686.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance-i686.jsonl

# Quick local sanity: just the smoke harness
sim-positive:
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin smoke

# -------- Clean flows --------
clean-build:
	@echo "Cleaning target/ (non-destructive: keeps Cargo.lock)..."
	cargo clean
	cargo fmt --all
	cargo build --workspace --all-targets

clean-lock-build:
	@echo "Cleaning target/ and Cargo.lock (DEV-ONLY destructive clean)..."
	cargo clean
	$(RM_LOCK)
	cargo fmt --all
	cargo build --workspace --all-targets

# -------- Whole-workspace (includes GUI crates) --------
check-all:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

build-all:
	cargo build --workspace --all-targets

test-all:
	cargo test --workspace --all-targets

# -------- Bevy (GUI client) orchestration --------
# Builds everything needed, then runs VS + GS + client-bevy via tools/bin/play
play:
	@echo "Building client-bevy sanity3d..."
	cargo build -p client-bevy --bin sanity3d
	@echo "Running sanity3d (3D render/input/PBR sanity)..."
	cargo run -p client-bevy --bin sanity3d -- --sanity

play-full:
	@echo "Building headless crates..."
	cargo build --all-targets $(PKG_FLAGS)
	@echo "Building client-bevy..."
	cargo build -p client-bevy
	@echo "Ensuring VS keys + launching VS, GS, and Bevy client..."
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin play