.PHONY: generate test tidy

generate:
	go generate ./...

test:
	go test ./...

tidy:
	go mod tidy
