test:
	cargo test
test-no-std:
	cargo test --features no_std
clippy:
	cargo clippy
fmt:
	cargo fmt --check

ci: fmt clippy test test-no-std

.PHONY: test test-no-std clippy fmt ci

