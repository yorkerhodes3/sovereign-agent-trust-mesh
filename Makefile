# SATM developer entry points.
#
# Windows users: `make` is typically absent. Use the equivalent PowerShell runner:
#   .\make.ps1 <target>
# Both files intentionally expose the SAME target names.

SHELL := /bin/bash
.DEFAULT_GOAL := help

CONTRACTS := contracts
ANVIL_L2_PORT ?= 8545
ANVIL_L1_PORT ?= 8546
# anvil account #0 — a well-known devnet key. NEVER use outside a local chain.
DEVNET_PK ?= 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- contracts --

.PHONY: deps
deps: ## Install locked contract dependencies
	cd $(CONTRACTS) && forge soldeer install

.PHONY: build
build: ## Compile contracts
	cd $(CONTRACTS) && forge build

.PHONY: test
test: ## Run the contract test suite
	cd $(CONTRACTS) && forge test -vv

.PHONY: test-gas
test-gas: ## Run tests with a gas report
	cd $(CONTRACTS) && forge test --gas-report

.PHONY: fmt
fmt: ## Format Solidity sources
	cd $(CONTRACTS) && forge fmt

.PHONY: lint
lint: ## Check formatting without writing
	cd $(CONTRACTS) && forge fmt --check

.PHONY: coverage
coverage: ## Contract coverage report
	cd $(CONTRACTS) && forge coverage --report summary

# ------------------------------------------------------------------ devnet --
# NOTE: full devnet (Postgres, IPFS, Dex, SAM control plane + router) requires
# Docker and lands with P0-3/P0-4. `devnet-chains` is the subset that works with
# Foundry alone and is what Phase 0 actually verifies today.

.PHONY: devnet-chains
devnet-chains: ## Start both anvil chains (L2 role + L1 role)
	@echo "starting anvil L2 on :$(ANVIL_L2_PORT) and L1 on :$(ANVIL_L1_PORT)"
	@anvil --port $(ANVIL_L2_PORT) --chain-id 31337 --silent & \
	 anvil --port $(ANVIL_L1_PORT) --chain-id 31338 --silent & \
	 sleep 3 && echo "both chains up"

.PHONY: devnet-down
devnet-down: ## Stop the local chains
	-@pkill -f "anvil --port $(ANVIL_L2_PORT)" || true
	-@pkill -f "anvil --port $(ANVIL_L1_PORT)" || true
	@echo "chains stopped"

.PHONY: deploy-local
deploy-local: ## Deploy ERC-8004 registries to the local L2 chain
	cd $(CONTRACTS) && PRIVATE_KEY=$(DEVNET_PK) forge script script/DeployRegistries.s.sol \
	  --rpc-url http://127.0.0.1:$(ANVIL_L2_PORT) --broadcast

.PHONY: devnet-up
devnet-up: devnet-chains deploy-local ## Chains + registries (Phase 0 subset)
	@echo "devnet ready — see contracts/deployments/31337.json"

# ------------------------------------------------------------------- checks --

.PHONY: verify-vendor
verify-vendor: ## Confirm vendored ERC-8004 sources match the pinned commit
	@bash tools/verify-vendor.sh

.PHONY: ci
ci: lint build test verify-vendor ## Everything CI runs

.PHONY: clean
clean: ## Remove build artifacts
	cd $(CONTRACTS) && rm -rf out cache broadcast
