.PHONY: fmt lint

 
fmt:
	gofmt -s -w .

 
lint:
	golangci-lint run

 
pre-commit: fmt lint 