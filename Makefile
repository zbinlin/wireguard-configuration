CLANG ?= clang
GCC ?= gcc
BPFTOOL ?= bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BUILD_DIR ?= build

BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wno-missing-declarations -I$(BUILD_DIR) -I/usr/include
LDFLAGS = -lbpf -lelf -lz

all: $(BUILD_DIR)/router_ctl

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/local_router.bpf.o: bpf/local_router.bpf.c $(BUILD_DIR)/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/local_router.skel.h: $(BUILD_DIR)/local_router.bpf.o | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/router_ctl: src/router_ctl.c $(BUILD_DIR)/local_router.skel.h | $(BUILD_DIR)
	$(GCC) -O2 -I$(BUILD_DIR) -Isrc -I. $< $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
