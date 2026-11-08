.PHONY: run test docs docs-serve

CONFIG_PATH ?= config.example.json

run:
	CONFIG_PATH=$(CONFIG_PATH) go run .

test:
	go test ./...

docs:
	cd docs && mdbook build

docs-serve:
	cd docs && mdbook serve
