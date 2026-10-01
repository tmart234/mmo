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
HEADLESS_PKGS := fpp-types fpp-wire fpp-crypto fpp-merkle fpp-tokens fpp-session fpp-ffi fpp-audit fpp-log fpp-svc svc-log attest-core attest-android attest-apple attest-tpm common client-core gs-sim svc-liveness svc-verifier svc-broker svc-revocation svc-evidence tools
PKG_FLAGS := $(foreach p,$(HEADLESS_PKGS),-p $(p))

# -------- Phonies --------
.PHONY: help ci check build-headless test-headless test-stage interop ffi-c-test ffi-c-test-i686 \
        pi-cell pi-cell-smoke ffi-c-test-aarch64 sim-positive clean-build clean-lock-build \
        check-all build-all test-all

# -------- Help --------
help:
	@echo "Targets:"
	@echo "  ci                 - fmt+clippy only for headless crates, build, test, smoke"
	@echo "  check              - fmt+clippy (headless crates only)"
	@echo "  build-headless     - build headless crates (-p $(HEADLESS_PKGS))"
	@echo "  test-headless      - cargo test for headless crates"
	@echo "  test-stage         - test headless crates + run smoke (cell <-> GS <-> client) + revocation and split-view exit tests"
	@echo "  interop            - check FPP golden vectors with the independent Python verifier"
	@echo "  ffi-c-test         - C SDK conformance (x86_64); ffi-c-test-i686 for the Halo ABI"
	@echo "  pi-cell            - cross-build the cell's services (and gen_keys, fpp-cell) for a Raspberry Pi (aarch64)"
	@echo "  pi-cell-smoke      - smoke test with the aarch64 services under qemu-aarch64-static"
	@echo "  ffi-c-test-aarch64 - C SDK conformance for the Pi 5 host (aarch64, under qemu)"
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

# Run tests AND the smoke test (a cell of services <-> gs-sim <-> client-sim)
test-stage: test-headless
	@echo "Running smoke test (\`svc-liveness\`, \`svc-verifier\`, \`svc-broker\` + \`gs-sim --test-once\` + \`client-sim --smoke-test\`)..."
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin smoke
	@echo "Revocation exit tests (kick p99 <= 5 s, denied admission, SAR lapse of a rogue GS)..."
	cargo run -p tools --bin revocation_load
	@echo "Split-view exit test (a player proves a rogue GS showed it another Checkpoint; GS revoked)..."
	cargo run -p tools --bin split_view

# FPP v1 golden vectors, checked by the independent Python implementation.
# (The Rust side is checked by crates/fpp-crypto/tests/golden.rs.)
interop:
	python3 interop/python/fpp_interop.py

# C SDK conformance: compile a C program against only include/fpp.h and the
# static library, run it, and check that what it signs is byte-identical to the
# golden vectors and passes the independent verifier. Then the P2P session
# test (M2): join, traffic, and the H03/H04 attacks, all through the C ABI. The i686 variant is the
# ABI of the Halo: CE port (32-bit x86); it needs gcc-multilib and
# `rustup target add i686-unknown-linux-gnu`.
FFI_LIBS := -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
ffi-c-test:
	cargo build -p fpp-ffi
	cc -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/conformance.c target/debug/libfpp.a $(FFI_LIBS) -o target/fpp-conformance
	./target/fpp-conformance > target/fpp-conformance.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance.jsonl
	cc -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/p2p.c target/debug/libfpp.a $(FFI_LIBS) -o target/fpp-p2p
	./target/fpp-p2p

ffi-c-test-i686:
	cargo build -p fpp-ffi --target i686-unknown-linux-gnu
	cc -m32 -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/conformance.c target/i686-unknown-linux-gnu/debug/libfpp.a $(FFI_LIBS) \
		-o target/fpp-conformance-i686
	./target/fpp-conformance-i686 > target/fpp-conformance-i686.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance-i686.jsonl
	cc -m32 -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/p2p.c target/i686-unknown-linux-gnu/debug/libfpp.a $(FFI_LIBS) \
		-o target/fpp-p2p-i686
	./target/fpp-p2p-i686

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
# Builds everything needed, then runs the cell + GS + client-bevy via tools/bin/play
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
	@echo "Ensuring dev keys + launching the cell, GS, and Bevy client..."
	cargo run -p tools --bin gen_keys
	cargo run -p tools --bin play
# -------- Raspberry Pi (aarch64): the cell on a Pi Zero 2 W, SDK for the Pi 5 host --------
# Cross-builds with clang + lld and Debian/Ubuntu's aarch64 sysroot, so no
# aarch64 gcc is needed:
#   rustup target add aarch64-unknown-linux-gnu
#   apt-get install clang lld llvm libc6-dev-arm64-cross libgcc-13-dev-arm64-cross qemu-user-static
# deploy/pi/README.md installs the result.
PI_TARGET := aarch64-unknown-linux-gnu
PI_ENV := CC_aarch64_unknown_linux_gnu=clang CXX_aarch64_unknown_linux_gnu=clang++ \
	CFLAGS_aarch64_unknown_linux_gnu=--target=aarch64-linux-gnu \
	CXXFLAGS_aarch64_unknown_linux_gnu=--target=aarch64-linux-gnu \
	AR_aarch64_unknown_linux_gnu=llvm-ar \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=clang \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=--target=aarch64-linux-gnu -C link-arg=-fuse-ld=lld"
PI_QEMU := qemu-aarch64-static
PI_SYSROOT := /usr/aarch64-linux-gnu

pi-cell:
	$(PI_ENV) cargo build --release -p svc-liveness -p svc-verifier -p svc-broker -p svc-revocation -p svc-evidence -p svc-log -p fpp-svc -p tools --target $(PI_TARGET)
	@echo "Cell for the Pi: target/$(PI_TARGET)/release/svc-{log,revocation,evidence,liveness,verifier,broker}, fpp-enforce, fpp-evidence (install: deploy/pi/README.md)"

# The full smoke test with the services the Pi runs, emulated.
pi-cell-smoke: pi-cell
	cargo build -p gs-sim -p client-core -p tools -p svc-revocation -p svc-evidence
	cargo run -p tools --bin gen_keys
	SMOKE_BIN_DIR=target/$(PI_TARGET)/release SMOKE_WRAPPER=$(PI_QEMU) SMOKE_STARTUP_MS=1500 \
		QEMU_LD_PREFIX=$(PI_SYSROOT) cargo run -p tools --bin smoke

# libfpp.a for the Pi 5 host loader (LP64 aarch64; the itself is ILP32,
# docs/anticheat/08 §8), checked as ffi-c-test checks the x86 builds.
ffi-c-test-aarch64:
	$(PI_ENV) cargo build -p fpp-ffi --target $(PI_TARGET)
	clang --target=aarch64-linux-gnu -fuse-ld=lld -std=c99 -Wall -Wextra -Werror -pedantic \
		-Icrates/fpp-ffi/include crates/fpp-ffi/tests/c/conformance.c \
		target/$(PI_TARGET)/debug/libfpp.a $(FFI_LIBS) -o target/fpp-conformance-aarch64
	QEMU_LD_PREFIX=$(PI_SYSROOT) $(PI_QEMU) ./target/fpp-conformance-aarch64 > target/fpp-conformance-aarch64.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance-aarch64.jsonl
	clang --target=aarch64-linux-gnu -fuse-ld=lld -std=c99 -Wall -Wextra -Werror -pedantic \
		-Icrates/fpp-ffi/include crates/fpp-ffi/tests/c/p2p.c \
		target/$(PI_TARGET)/debug/libfpp.a $(FFI_LIBS) -o target/fpp-p2p-aarch64
	QEMU_LD_PREFIX=$(PI_SYSROOT) $(PI_QEMU) ./target/fpp-p2p-aarch64
