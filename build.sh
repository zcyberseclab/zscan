#!/bin/bash

# 版本号
VERSION="v1.0.0"
# 构建时间
BUILD_TIME=$(date "+%F %T")
# 提交哈希
COMMIT_SHA=$(git rev-parse HEAD)

# 构建参数
LDFLAGS="-X 'main.Version=$VERSION' -X 'main.BuildTime=$BUILD_TIME' -X 'main.CommitSHA=$COMMIT_SHA' -w -s"

# 创建 release 目录
mkdir -p release

# 跨平台构建
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o release/zscan_windows_amd64.exe cmd/main.go
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o release/zscan_linux_amd64 cmd/main.go
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o release/zscan_darwin_amd64 cmd/main.go
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o release/zscan_darwin_arm64 cmd/main.go

# 打包配置文件和其他必要文件
cp -r config release/
cp README.md release/

# 创建压缩包
cd release
zip -r zscan_windows_amd64.zip zscan_windows_amd64.exe config README.md
tar czf zscan_linux_amd64.tar.gz zscan_linux_amd64 config README.md
tar czf zscan_darwin_amd64.tar.gz zscan_darwin_amd64 config README.md
tar czf zscan_darwin_arm64.tar.gz zscan_darwin_arm64 config README.md 