.PHONY: fmt lint

# 格式化代码
fmt:
	gofmt -s -w .

# 运行代码检查
lint:
	golangci-lint run

# 在提交代码前运行的检查
pre-commit: fmt lint 