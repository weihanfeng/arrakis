OUT_DIR := out
PROTOS_DIR := protos

.PHONY: grpcserver
grpcserver: protos
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-lambda-grpcserver cmd/grpcserver/main.go

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
guest: guestinit codeserver guestrootfs

.PHONY: codeserver
codeserver: protos
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -o $(OUT_DIR)/chv-lambda-codeserver cmd/codeserver/codeserver.go

.PHONY: all
all: grpcserver client guestinit codeserver guestrootfs guest
