## 不查询地理信息（默认）
./zscan -target 192.168.1.1

## 启用地理信息查询
./zscan -target 192.168.1.1 -geo

## censys

go run .\cmd\main.go -target 23.94.151.97 -geo -censys -censys-api-key 542a7dff-813c-4566-b8f9-9c1f51dfc9a5 -censys-secret PUdEd9sjMagkpw2ZRDPQRnTeZJSORx54

go run .\cmd\main.go -target 116.204.41.88