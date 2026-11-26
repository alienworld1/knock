.PHONY: build console console-check check abi release-linux-amd64

build: console
	go build -trimpath -o bin/ ./cmd/knock ./cmd/knockd

release-linux-amd64:
	GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 $(MAKE) build
	tar --transform='s,^,knock-linux-amd64/,' -czf bin/knock-linux-amd64.tar.gz \
		bin/knock bin/knockd LICENSE deploy/network.diana.json \
		deploy/door.example.json deploy/door.metered.example.json deploy/knock-tunnel.sudoers \
		deploy/systemd/knockd.service deploy/systemd/10-ssh.conf
	cd bin && sha256sum knock-linux-amd64.tar.gz > SHA256SUMS

console:
	pnpm --dir web/console build

console-check: console
	pnpm --dir web/console format:check
	pnpm --dir web/console test
	pnpm --dir web/console test:browser

check: build console-check
	go vet ./...
	go test ./...
	forge fmt --check --root contracts
	forge test --root contracts
	$(MAKE) abi

abi:
	forge build --root contracts
	python3 -c 'import json, pathlib; p=pathlib.Path; abi=json.loads(p("contracts/out/KnockRegistry.sol/KnockRegistry.json").read_text())["abi"]; expected=json.loads(p("internal/chain/registry.abi.json").read_text()); assert expected == abi, "KnockRegistry ABI has changed"'
