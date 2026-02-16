.PHONY: all build test fmt lint kat gate clean check

all: build

build:
	cargo build --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt-check lint test

kat:
	cargo test --workspace -- --nocapture rho_ unc1_ golden_

gate:
	RUST_LOG=info cargo run -p ubl_gate

clean:
	cargo clean
