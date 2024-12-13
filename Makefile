OUT_DIR := out
PROTOS_DIR := protos

.PHONY: restserver
restserver: protos
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-lambda-restserver cmd/restserver/main.go

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

.PHONY: rootfsmaker
rootfsmaker:
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/chv-rootfsmaker cmd/rootfsmaker/main.go

# TODO: Try to avoid sudo here.
.PHONY: guestrootfs
guestrootfs: guestinit rootfsmaker
	mkdir -p $(OUT_DIR)
	sudo $(OUT_DIR)/chv-rootfsmaker create -d ./resources/scripts/rootfs/Dockerfile

.PHONY: guest
guest: rootfsmaker guestinit codeserver cmdserver guestrootfs

.PHONY: codeserver
codeserver: protos
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -o $(OUT_DIR)/chv-lambda-codeserver cmd/codeserver/codeserver.go

.PHONY: cmdserver
cmdserver: protos
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -o $(OUT_DIR)/chv-lambda-cmdserver cmd/cmdserver/main.go

.PHONY: all
all: restserver client guestinit codeserver cmdserver guestrootfs guest
