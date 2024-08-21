OUT_DIR := out
PROTOS_DIR := protos

.PHONY: cli
cli: protos
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-lambda-cli main.go

.PHONY: server
server: protos
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-lambda-server cmd/server/server.go

.PHONY: protos
protos:
	mkdir -p $(OUT_DIR)
	protoc --go_out=paths=source_relative:$(OUT_DIR) --go-grpc_out=paths=source_relative:$(OUT_DIR) $(PROTOS_DIR)/api.proto

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

.PHONY: all
all: clean cli server
