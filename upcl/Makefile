# Universal Performance Collection Library Makefile

# Compiler and flags
CC = gcc
CLANG = clang
CFLAGS = -Wall -O2 -g -fPIC -D_GNU_SOURCE
LDFLAGS = -lpthread -lbpf -lelf -lz
INCLUDES = -I./include -I/usr/include/bpf

# Kernel build
KERNEL_VERSION = $(shell uname -r)
KERNEL_DIR = /lib/modules/$(KERNEL_VERSION)/build

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
LIB_DIR = lib
BIN_DIR = bin
EBPF_DIR = src/ebpf
KMOD_DIR = kernel

# Create directories
$(shell mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR))

# Source files
CORE_SRCS = $(SRC_DIR)/upcl_core.c \
            $(SRC_DIR)/upcl_perf.c \
            $(SRC_DIR)/upcl_ebpf.c \
            $(SRC_DIR)/upcl_platform.c \
            $(SRC_DIR)/upcl_intel.c \
            $(SRC_DIR)/upcl_amd.c \
            $(SRC_DIR)/upcl_arm.c \
            $(SRC_DIR)/upcl_export.c \
            $(SRC_DIR)/upcl_utils.c

# Object files
CORE_OBJS = $(CORE_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# eBPF programs
EBPF_PROGS = $(EBPF_DIR)/trace.bpf.c \
             $(EBPF_DIR)/sample.bpf.c \
             $(EBPF_DIR)/probe.bpf.c

EBPF_OBJS = $(EBPF_PROGS:.bpf.c=.bpf.o)

# Library name
LIB_NAME = libupcl.so
STATIC_LIB = libupcl.a

# Example programs
EXAMPLES = example_basic example_ebpf example_ai example_kernel

# Default target
all: $(LIB_DIR)/$(LIB_NAME) $(LIB_DIR)/$(STATIC_LIB) $(EXAMPLES) ebpf

# Build shared library
$(LIB_DIR)/$(LIB_NAME): $(CORE_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Build static library
$(LIB_DIR)/$(STATIC_LIB): $(CORE_OBJS)
	ar rcs $@ $^

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Build eBPF programs
ebpf: $(EBPF_OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86 -I$(INC_DIR) -c $< -o $@

# Build examples
example_basic: examples/example_basic.c $(LIB_DIR)/$(LIB_NAME)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BIN_DIR)/$@ $< -L$(LIB_DIR) -lupcl -Wl,-rpath,$(LIB_DIR)

example_ebpf: examples/example_ebpf.c $(LIB_DIR)/$(LIB_NAME)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BIN_DIR)/$@ $< -L$(LIB_DIR) -lupcl -Wl,-rpath,$(LIB_DIR)

example_ai: examples/example_ai.c $(LIB_DIR)/$(LIB_NAME)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BIN_DIR)/$@ $< -L$(LIB_DIR) -lupcl -Wl,-rpath,$(LIB_DIR)

example_kernel: examples/example_kernel.c $(LIB_DIR)/$(LIB_NAME)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BIN_DIR)/$@ $< -L$(LIB_DIR) -lupcl -Wl,-rpath,$(LIB_DIR)

# Build kernel module
kmod:
	$(MAKE) -C $(KMOD_DIR)

# Install
install: $(LIB_DIR)/$(LIB_NAME) $(LIB_DIR)/$(STATIC_LIB)
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include
	install -m 755 $(LIB_DIR)/$(LIB_NAME) $(DESTDIR)/usr/local/lib/
	install -m 644 $(LIB_DIR)/$(STATIC_LIB) $(DESTDIR)/usr/local/lib/
	install -m 644 $(INC_DIR)/upcl.h $(DESTDIR)/usr/local/include/
	install -m 644 $(INC_DIR)/upcl_types.h $(DESTDIR)/usr/local/include/
	ldconfig

# Clean
clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)
	rm -f $(EBPF_OBJS)
	$(MAKE) -C $(KMOD_DIR) clean

# Run tests
test: all
	./tests/run_tests.sh

.PHONY: all clean install kmod ebpf test