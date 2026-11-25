# Heavily inspired by rbuilder: https://github.com/flashbots/rbuilder/blob/develop/Makefile
.DEFAULT_GOAL := help

GIT_VER ?= $(shell git describe --tags --always --dirty="-dev")
GIT_TAG ?= $(shell git describe --tags --abbrev=0)

FEATURES ?=
FEATURE_ARGS = $(if $(strip $(FEATURES)),--features "$(FEATURES)")
COMMA := ,
# The provider exposes Azure quote generation through its attestation dependency.
PROVIDER_FEATURE_ARGS = $(if $(filter azure attested-tls/azure,$(subst $(COMMA), ,$(FEATURES))),--features "attestation/azure-attester")

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: v
v: ## Show the current version
	@echo "Version: ${GIT_VER}"

##@ Build

.PHONY: clean
clean: ## Clean up
	cargo clean

# Detect the current architecture
ARCH := $(shell uname -m)

# Determine if we're on x86_64
ifeq ($(ARCH),x86_64)
    IS_X86_64 = 1
else
    IS_X86_64 = 0
endif

# Set build profile and flags based on architecture
ifeq ($(IS_X86_64),1)
    # x86_64: Use reproducible profile with reproducible build flags
    BUILD_PROFILE = reproducible
    BUILD_TARGET = x86_64-unknown-linux-gnu

    # Environment variables for reproducible builds
    # Initialize RUSTFLAGS
    RUST_BUILD_FLAGS =
    # Optimize for modern CPUs
    RUST_BUILD_FLAGS += -C target-cpu=x86-64-v3
    # Remove build ID from the binary to ensure reproducibility across builds
    RUST_BUILD_FLAGS += -C link-arg=-Wl,--build-id=none
    # Remove metadata hash from symbol names to ensure reproducible builds
    RUST_BUILD_FLAGS += -C metadata=''
    # Remap paths to ensure reproducible builds
    RUST_BUILD_FLAGS += --remap-path-prefix $(shell pwd)=.
    # Set timestamp from last git commit for reproducible builds
    SOURCE_DATE ?= $(shell git log -1 --pretty=%ct)
    # Set C locale for consistent string handling and sorting
    LOCALE_VAL = C
    # Set UTC timezone for consistent time handling across builds
    TZ_VAL = UTC

    # Environment setup for reproducible builds
    BUILD_ENV = SOURCE_DATE_EPOCH=$(SOURCE_DATE) \
                RUSTFLAGS="${RUST_BUILD_FLAGS}" \
                LC_ALL=${LOCALE_VAL} \
                TZ=${TZ_VAL}
else
    # Non-x86_64: Use release profile without reproducible build flags
    BUILD_PROFILE = release
    BUILD_TARGET =
    RUST_BUILD_FLAGS =
    BUILD_ENV =
endif

CARGO_BUILD_ARGS = --locked $(if $(BUILD_TARGET),--target $(BUILD_TARGET)) --profile $(BUILD_PROFILE)

.PHONY: install-cargo-auditable
install-cargo-auditable:
	@command -v cargo-auditable >/dev/null 2>&1 || cargo install cargo-auditable@0.7.7 --locked

.PHONY: build
build: install-cargo-auditable ## Build (release version)
	$(BUILD_ENV) cargo auditable build -p attested-tls-proxy $(FEATURE_ARGS) $(CARGO_BUILD_ARGS)

.PHONY: build-attestation-provider
build-attestation-provider: install-cargo-auditable ## Build the provider from the pinned upstream revision
	provider_source=$$(python3 scripts/prepare-attestation-provider.py --target "$(BUILD_TARGET)" --profile "$(BUILD_PROFILE)") && \
		$(BUILD_ENV) cargo auditable build -p attestation-provider-server \
			--manifest-path "$$provider_source/Cargo.toml" --target-dir "$(CURDIR)/target" \
			--config "$(CURDIR)/target/attestation-provider-profile.toml" \
			$(PROVIDER_FEATURE_ARGS) $(CARGO_BUILD_ARGS)

.PHONY: build-dev
build-dev: ## Build (debug version)
	cargo build -p attested-tls-proxy $(FEATURE_ARGS)

##@ Debian Packages

.PHONY: install-cargo-deb
install-cargo-deb:
	@command -v cargo-deb >/dev/null 2>&1 || cargo install cargo-deb@3.6.0 --locked

CARGO_DEB_ARGS = --profile $(BUILD_PROFILE) --no-build --no-dbgsym --no-strip \
	$(if $(BUILD_TARGET),--target $(BUILD_TARGET)) \
	$(if $(VERSION),--deb-version "1~$(VERSION)")

.PHONY: build-deb
build-deb: install-cargo-deb ## Package both previously built binaries
	$(BUILD_ENV) cargo deb -p attested-tls-proxy $(CARGO_DEB_ARGS)

##@ Dev

.PHONY: lint
lint: ## Run the linters
	cargo fmt --all -- --check
	cargo clippy --workspace $(FEATURE_ARGS) -- -D warnings

.PHONY: test
test:
	cargo test --workspace --verbose $(FEATURE_ARGS)

.PHONY: lt
lt: lint test ## Run "lint" and "test"

.PHONY: fmt
fmt: ## Format the code
	cargo fmt --all
	cargo fix --workspace --allow-staged
	cargo clippy --workspace $(FEATURE_ARGS) --fix --allow-staged
