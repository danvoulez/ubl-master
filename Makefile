.PHONY: all build test fmt lint kat gate clean check load-validate rollout-check

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

load-validate:
	cargo test -p ubl_chipstore --test load_validation -- --ignored --nocapture

rollout-check:
	bash scripts/rollout_p0_p1_check.sh \
		--runtime-hash "$${RUNTIME_HASH:?set RUNTIME_HASH}" \
		--allow-placeholder-signatures \
		--report-file ./data/rollout_report.json

clean:
	cargo clean
