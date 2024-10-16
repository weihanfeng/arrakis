OUT_DIR := out
PROTOS_DIR := protos

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

# Build the guest init binary explicitly statically if "os" or "net" are used by
# using the CGO_ENABLED=0 flag.
.PHONY: guestinit
guestinit:
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -o $(OUT_DIR)/chv-guestinit cmd/guestinit/guestinit.go

# TODO: Try to avoid sudo here.
.PHONY: guestrootfs
guestrootfs: guestinit
	mkdir -p $(OUT_DIR)
	sudo ./resources/scripts/rootfs/rootfs-from-dockerfile.sh

.PHONY: guest
guest: guestinit guestrootfs

.PHONY: all
all: server client guestinit guestrootfs guest
