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

TEST_SRCS := \
	$(SRC_DIR)/test_config.c \
	$(SRC_DIR)/config.c

JUNKNAS_OBJS := $(JUNKNAS_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TEST_OBJS := $(TEST_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

BIN_JUNKNAS := $(BIN_DIR)/junknas_fuse
BIN_TEST := $(BIN_DIR)/test_config

.PHONY: all init clean

all: $(BIN_JUNKNAS) $(BIN_TEST)

init: all
	@mkdir -p /tmp/junknas-data /tmp/junknas-mount
	@echo "Initialized build artifacts and local test directories."

$(BIN_JUNKNAS): $(JUNKNAS_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(JUNKNAS_OBJS) $(LDLIBS) $(FUSE_LIBS) -pthread

$(BIN_TEST): $(TEST_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(LDLIBS) -pthread

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
