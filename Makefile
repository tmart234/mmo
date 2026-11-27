# Makefile at repo root

ifeq ($(OS),Windows_NT)
SHELL := cmd
RM_LOCK := del /F /Q Cargo.lock 2>nul || exit /B 0
else
SHELL := /bin/sh
RM_LOCK := rm -f Cargo.lock
endif

.PHONY: help ci check build test test-stage interop ffi-c-test ffi-c-test-i686 ffi-c-verified \
        pi-cell pi-cell-smoke ffi-c-test-aarch64 sim-positive clean-build clean-lock-build

help:
	@echo "Targets:"
	@echo "  ci                 - fmt, clippy, build, test, all 5 exit tests, interop, C SDK conformance"
	@echo "  check              - fmt + clippy across the 5-crate workspace"
	@echo "  build              - cargo build --workspace --all-targets"
	@echo "  test               - cargo test --workspace --all-features"
	@echo "  test-stage         - unit/integration tests + smoke, revocation, split-view, TPM attestation, and C verified-playlist exit tests"
	@echo "  interop            - verify FPP golden vectors with the independent Python verifier"
	@echo "  ffi-c-test         - C SDK conformance + P2P tests (x86_64)"
	@echo "  ffi-c-test-i686    - C SDK conformance + P2P tests (32-bit x86 Halo ABI)"
	@echo "  ffi-c-verified     - build C dedicated host against libfpp.a (--features gs-link)"
	@echo "  pi-cell            - cross-build fppd for Raspberry Pi (aarch64)"
	@echo "  pi-cell-smoke      - smoke test with aarch64 fppd under qemu-aarch64-static"
	@echo "  ffi-c-test-aarch64 - C SDK conformance for Pi 5 host (aarch64 under qemu)"
	@echo "  sim-positive       - build fppd + run smoke test"
	@echo "  clean-build        - cargo clean + fmt + build"
	@echo "  clean-lock-build   - destructive: clean + remove Cargo.lock + fmt + build"

ci:
	@echo "Lint (fmt + clippy)..."
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	@echo "Build workspace..."
	cargo build --workspace --all-targets
	@echo "Run tests + adversarial exit suites..."
	$(MAKE) test-stage
	@echo "Interop: independent Python verifier on FPP golden vectors..."
	$(MAKE) interop
	@echo "C SDK: conformance + P2P suite against include/fpp.h + libfpp.a..."
	$(MAKE) ffi-c-test
	@echo "CI completed ✅"

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace --all-features

test-stage: test
	@echo "Ensuring fppd binary is built..."
	cargo build -p fppd
	@echo "Running smoke test (fppd serve + external witness + P-256 client + Evidence Store + Transparency Log + failure domains)..."
	cargo run -p fpp-sim --bin smoke
	@echo "Running revocation exit tests (kick p99 <= 5 s, denied admission, rogue GS SAR lapse)..."
	cargo run -p fpp-sim --bin revocation_load
	@echo "Running split-view exit test (player proves rogue GS equivocation via Transparency Log; GS revoked)..."
	cargo run -p fpp-sim --bin split_view
	@echo "Running P3 hardware attestation exit tests (PC TPM 2.0 on swtpm)..."
	cargo run -p fpp-sim --bin attestation_exit
	@echo "Running H5 verified-playlist exit test (C dedicated host on fpp_gs_link_* against fppd)..."
	$(MAKE) ffi-c-verified
	cargo run -p fpp-sim --bin verified_exit

interop:
	python3 interop/python/fpp_interop.py

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

ffi-c-verified:
	cargo build -p fpp-ffi --features gs-link
	cc -std=c99 -Wall -Wextra -Werror -pedantic -DFPP_GS_LINK -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/verified_host.c target/debug/libfpp.a $(FFI_LIBS) -o target/fpp-verified-host

ffi-c-test-i686:
	cargo build -p fpp-ffi --features gs-link --target i686-unknown-linux-gnu
	cc -m32 -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/conformance.c target/i686-unknown-linux-gnu/debug/libfpp.a $(FFI_LIBS) \
		-o target/fpp-conformance-i686
	./target/fpp-conformance-i686 > target/fpp-conformance-i686.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance-i686.jsonl
	cc -m32 -std=c99 -Wall -Wextra -Werror -pedantic -Icrates/fpp-ffi/include \
		crates/fpp-ffi/tests/c/p2p.c target/i686-unknown-linux-gnu/debug/libfpp.a $(FFI_LIBS) \
		-o target/fpp-p2p-i686
	./target/fpp-p2p-i686

sim-positive:
	cargo build -p fppd
	cargo run -p fpp-sim --bin smoke

clean-build:
	cargo clean
	cargo fmt --all
	cargo build --workspace --all-targets

clean-lock-build:
	cargo clean
	$(RM_LOCK)
	cargo fmt --all
	cargo build --workspace --all-targets

# -------- Raspberry Pi (aarch64) --------
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
	$(PI_ENV) cargo build --release -p fppd --target $(PI_TARGET)
	@echo "Authority daemon for Pi: target/$(PI_TARGET)/release/fppd (install: deploy/pi/README.md)"

pi-cell-smoke: pi-cell
	cargo build -p fpp-sim --bin smoke
	SMOKE_BIN_DIR=target/$(PI_TARGET)/release SMOKE_WRAPPER=$(PI_QEMU) SMOKE_STARTUP_MS=15000 \
		QEMU_LD_PREFIX=$(PI_SYSROOT) cargo run -p fpp-sim --bin smoke

ffi-c-test-aarch64:
	$(PI_ENV) cargo build -p fpp-ffi --features gs-link --target $(PI_TARGET)
	clang --target=aarch64-linux-gnu -fuse-ld=lld -std=c99 -Wall -Wextra -Werror -pedantic \
		-Icrates/fpp-ffi/include crates/fpp-ffi/tests/c/conformance.c \
		target/$(PI_TARGET)/debug/libfpp.a $(FFI_LIBS) -o target/fpp-conformance-aarch64
	QEMU_LD_PREFIX=$(PI_SYSROOT) $(PI_QEMU) ./target/fpp-conformance-aarch64 > target/fpp-conformance-aarch64.jsonl
	python3 interop/python/check_c_sdk.py target/fpp-conformance-aarch64.jsonl
	clang --target=aarch64-linux-gnu -fuse-ld=lld -std=c99 -Wall -Wextra -Werror -pedantic \
		-Icrates/fpp-ffi/include crates/fpp-ffi/tests/c/p2p.c \
		target/$(PI_TARGET)/debug/libfpp.a $(FFI_LIBS) -o target/fpp-p2p-aarch64
	QEMU_LD_PREFIX=$(PI_SYSROOT) $(PI_QEMU) ./target/fpp-p2p-aarch64
