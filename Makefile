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

.PHONY: client
client: protos
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-lambda-client cmd/client/client.go

.PHONY: protos
protos:
	mkdir -p $(OUT_DIR)
	protoc --go_out=paths=source_relative:$(OUT_DIR) --go-grpc_out=paths=source_relative:$(OUT_DIR) $(PROTOS_DIR)/api.proto

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

.PHONY: guestinit
guestinit:
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-guestinit cmd/guestinit/guestinit.go

.PHONY: guestrootfs
guestrootfs:
	mkdir -p $(OUT_DIR)
	./resources/scripts/rootfs/rootfs-from-dockerfile.sh

.PHONY: guest
guest: guestinit guestrootfs

.PHONY: all
all: cli server client guestinit guestrootfs guest
