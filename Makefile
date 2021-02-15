CARGO  = $(or $(shell which cargo),  $(HOME)/.cargo/bin/cargo)
RUSTUP = $(or $(shell which rustup), $(HOME)/.cargo/bin/rustup)

.PHONY: build
build:
	$(CARGO) build --release

.PHONY: build-ios
build-ios: setup-ios-rs
	$(CARGO) lipo --release

.PHONY: build-android
build-android: setup-android-rs
	$(CARGO) ndk --platform 21 --target aarch64-linux-android --target armv7-linux-androideabi --target x86_64-linux-android --target i686-linux-android build --release

.PHONY: format
format:
	$(CARGO) fmt --all

.PHONY: check-format
check-format:
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint:
	$(CARGO) clippy --all-targets --all -- -D warnings -A renamed_and_removed_lints

.PHONY: clean
clean:
	rm -rf ./target
	rm ./Cargo.lock

.PHONY: setup-rs
setup-rs:
	$(RUSTUP) update
	$(CARGO) install cbindgen

.PHONY: setup-android-rs
setup-android-rs:
	$(CARGO) install cargo-ndk
	$(RUSTUP) target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

.PHONY: setup-ios-rs
setup-ios-rs:
	$(CARGO) install cargo-lipo
	$(RUSTUP) target add aarch64-apple-ios x86_64-apple-ios

.PHONY: cbindgen
cbindgen: setup-rs
	cbindgen --config ./cbindgen.toml --crate musig-c --output ./schnorr_musig.h

run_example:
	cd musig-c/example-c && cc main.c -o example -l musig_c  -L../../target/release && ./example
