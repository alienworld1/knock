.PHONY: build check abi

build:
	go build -trimpath -o bin/ ./cmd/knock ./cmd/knockd

check: build
	go vet ./...
	go test ./...
	forge fmt --check --root contracts
	forge test --root contracts
	$(MAKE) abi

abi:
	forge build --root contracts
	python3 -c 'import json, pathlib; p=pathlib.Path; abi=json.loads(p("contracts/out/KnockRegistry.sol/KnockRegistry.json").read_text())["abi"]; expected=json.loads(p("internal/chain/registry.abi.json").read_text()); assert expected == abi, "KnockRegistry ABI has changed"'
