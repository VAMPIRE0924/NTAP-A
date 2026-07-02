ifeq ($(OS),Windows_NT)
EXEEXT := .exe
BUILD_FLAVOR := msys2
MKDIR_P := /usr/bin/mkdir -p
RM_RF := /usr/bin/rm -rf
NET_LIBS := -lws2_32
THREAD_LIBS :=
ifeq ($(origin CC),default)
CC := /ucrt64/bin/gcc
endif
ifeq ($(origin PKG_CONFIG),undefined)
PKG_CONFIG := /ucrt64/bin/pkg-config
endif
else
EXEEXT :=
BUILD_FLAVOR := linux
MKDIR_P := mkdir -p
RM_RF := rm -rf
NET_LIBS :=
THREAD_LIBS := -pthread
ifeq ($(origin CC),default)
CC := gcc
endif
PKG_CONFIG ?= pkg-config
endif

BUILD_DIR ?= build/$(BUILD_FLAVOR)
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

CPPFLAGS += -Isrc
CFLAGS += -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lcrypto
endif

SQLITE_CFLAGS := $(shell $(PKG_CONFIG) --cflags sqlite3 2>/dev/null)
SQLITE_LIBS := $(shell $(PKG_CONFIG) --libs sqlite3 2>/dev/null)
ifeq ($(strip $(SQLITE_LIBS)),)
SQLITE_LIBS := -lsqlite3
endif
COMPONENT_CFLAGS := $(OPENSSL_CFLAGS) $(SQLITE_CFLAGS)
COMPONENT_LIBS := $(OPENSSL_LIBS) $(SQLITE_LIBS)

COMMON_SRCS := \
	src/common/buffer.c \
	src/common/config.c \
	src/common/hash.c \
	src/common/log.c \
	src/common/net.c \
	src/common/proto.c \
	src/common/tap_linux.c \
	src/common/time.c \
	src/common/wire.c

COMPONENT_SRCS := \
	src/a/api_server.c \
	src/a/config.c \
	src/a/db_sqlite.c \
	src/a/main.c \
	src/a/node_server.c

COMMON_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(COMMON_SRCS))
COMPONENT_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(COMPONENT_SRCS))

.PHONY: all config-test clean

all: $(BIN_DIR)/ntap-a$(EXEEXT)

config-test: all
	./$(BIN_DIR)/ntap-a$(EXEEXT) -c conf/ntap-a.conf.example -t

$(BIN_DIR)/ntap-a$(EXEEXT): $(COMMON_OBJS) $(COMPONENT_OBJS)
	@$(MKDIR_P) $(@D)
	$(CC) $^ $(COMPONENT_LIBS) $(NET_LIBS) $(THREAD_LIBS) -o $@

$(OBJ_DIR)/%.o: %.c
	@$(MKDIR_P) $(@D)
	$(CC) $(CPPFLAGS) $(COMPONENT_CFLAGS) $(CFLAGS) -c $< -o $@

clean:
	$(RM_RF) $(BUILD_DIR)