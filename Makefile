OUT_DIR := out
PROTOS_DIR := protos

.PHONY: build
build: generate-protos
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-lambda main.go

.PHONY: generate-protos
generate-protos:
	mkdir -p $(OUT_DIR)
	protoc --go_out=paths=source_relative:$(OUT_DIR) --go-grpc_out=paths=source_relative:$(OUT_DIR) $(PROTOS_DIR)/api.proto

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

.PHONY: all
all: clean build
