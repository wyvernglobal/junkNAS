CC ?= gcc
PKG_CONFIG ?= pkg-config

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

FUSE_CFLAGS := $(shell $(PKG_CONFIG) --cflags fuse3 2>/dev/null)
FUSE_LIBS := $(shell $(PKG_CONFIG) --libs fuse3 2>/dev/null)
CJSON_CFLAGS := $(shell $(PKG_CONFIG) --cflags cjson 2>/dev/null)
CJSON_LIBS := $(shell $(PKG_CONFIG) --libs cjson 2>/dev/null)

CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic
CFLAGS += -Iinclude $(FUSE_CFLAGS) $(CJSON_CFLAGS)

LDLIBS := $(CJSON_LIBS)

ifeq ($(strip $(FUSE_LIBS)),)
FUSE_LIBS := -lfuse3
endif
ifeq ($(strip $(CJSON_LIBS)),)
CJSON_LIBS := -lcjson
LDLIBS := $(CJSON_LIBS)
endif

JUNKNAS_SRCS := \
	$(SRC_DIR)/junknas_fuse_main.c \
	$(SRC_DIR)/config.c \
	$(SRC_DIR)/fuse_fs.c \
	$(SRC_DIR)/mesh.c \
	$(SRC_DIR)/web_server.c \
	$(SRC_DIR)/wireguard.c

TEST_CONFIG_SRCS := \
	$(SRC_DIR)/test_config.c \
	$(SRC_DIR)/config.c

TEST_WG_SRCS := \
	$(SRC_DIR)/test_wireguard.c \
	$(SRC_DIR)/wireguard.c

JUNKNAS_OBJS := $(JUNKNAS_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TEST_CONFIG_OBJS := $(TEST_CONFIG_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TEST_WG_OBJS := $(TEST_WG_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

BIN_JUNKNAS := $(BIN_DIR)/junknas_fuse
BIN_TEST_CONFIG := $(BIN_DIR)/test_config
BIN_TEST_WG := $(BIN_DIR)/test_wireguard

.PHONY: all init clean

all: $(BIN_JUNKNAS) $(BIN_TEST_CONFIG) $(BIN_TEST_WG)

init: all
	@mkdir -p $(HOME)/.config/junkNAS $(HOME)/.local/share/junknas/data /mnt/junknas
	@echo "Initialized build artifacts and local test directories."

$(BIN_JUNKNAS): $(JUNKNAS_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(JUNKNAS_OBJS) $(LDLIBS) $(FUSE_LIBS) -pthread

$(BIN_TEST_CONFIG): $(TEST_CONFIG_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_CONFIG_OBJS) $(LDLIBS) -pthread

$(BIN_TEST_WG): $(TEST_WG_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_WG_OBJS) $(LDLIBS) -pthread

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
