BIN=$HOME/projects/chv-lambda/resources/bin
CHV_BIN=${BIN}/cloud-hypervisor
KERNEL=${BIN}/compiled-vmlinux.bin
ROOTFS=${BIN}/ext4.img
CPUS=1
MEMORY=512M

${CHV_BIN} \
	--kernel ${KERNEL} \
	--cmdline "console=ttyS0 root=/dev/vda rw init=/bin/bash" \
	--console off \
	--serial tty \
	--disk path=${ROOTFS} \
	--cpus boot=${CPUS} \
	--memory size=${MEMORY}
