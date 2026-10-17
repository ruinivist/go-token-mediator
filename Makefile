.PHONY: run test

CONFIG_PATH ?= config.example.json

run:
	CONFIG_PATH=$(CONFIG_PATH) go run .

test:
	go test ./...
