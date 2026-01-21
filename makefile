# --- Configuration ---
COMPILER  ?= clang
TARGET_OS ?= auto
ARCH      ?= auto
LIB_NAME   = mylib_CHANGE

SRC_DIR = src
INC_DIR = include

# --- OS & Architecture Auto-Detection ---
ifeq ($(OS),Windows_NT)
    HOST_OS := windows
    ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
        HOST_ARCH := amd64
    else ifeq ($(PROCESSOR_ARCHITECTURE),ARM64)
        HOST_ARCH := arm64
    endif
else
    HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')
    UNAME_M := $(shell uname -m)
    ifeq ($(UNAME_M),x86_64)
        HOST_ARCH := amd64
    else ifneq (,$(filter $(UNAME_M),arm64 aarch64))
        HOST_ARCH := arm64
    endif
endif

# Resolve "auto" values
ifeq ($(TARGET_OS),auto)
    TARGET_OS := $(HOST_OS)
endif
ifeq ($(ARCH),auto)
    ARCH := $(HOST_ARCH)
endif

# Pathing setup
BUILD_ID = $(TARGET_OS)-$(ARCH)
OBJ_DIR  = obj/$(BUILD_ID)
BIN_DIR  = lib/$(BUILD_ID)

# --- Commands & Extensions ---
ifeq ($(HOST_OS),windows)
    RM = del /Q /S
    MKDIR = mkdir
else
    # Check if we are in a Unix-like shell on Windows (MinGW/MSYS)
    ifneq (,$(findstring mingw,$(shell $(COMPILER) -dumpmachine 2>/dev/null)))
        RM = del /Q /S
        MKDIR = mkdir
    else
        RM = rm -rf
        MKDIR = mkdir -p
    endif
endif

# --- Compiler Setup ---
ifeq ($(COMPILER),cl)
    # MSVC specific (Windows)
    CC = cl
    CFLAGS = /I$(INC_DIR) /c
    AR = lib
    TARGET = $(BIN_DIR)/$(LIB_NAME).lib
    ARFLAGS = /OUT:$(TARGET)
    OBJ_EXT = obj
else
    # GCC/Clang (Linux, macOS, Windows/MinGW)
    CC = $(COMPILER)
    CFLAGS = -Wall -Wextra -I$(INC_DIR) -fPIC
    
    ifeq ($(ARCH),arm64)
        CFLAGS += -march=armv8-a
    else
        CFLAGS += -m64
    endif

    ifeq ($(TARGET_OS),macos)
        CFLAGS += -target $(ARCH)-apple-macos
    endif

    AR = ar rcs
    TARGET = $(BIN_DIR)/lib$(LIB_NAME).a
    OBJ_EXT = o
endif

# --- Sources and Objects ---
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.$(OBJ_EXT), $(SRCS))

# --- Rules ---
all: $(TARGET)

$(TARGET): $(OBJS)
	@if not exist "$(BIN_DIR)" $(MKDIR) "$(BIN_DIR)" 2>nul || $(MKDIR) "$(BIN_DIR)"
	$(AR) $(ARFLAGS) $(if $(filter cl,$(COMPILER)),$(OBJS),$@ $(OBJS))

$(OBJ_DIR)/%.$(OBJ_EXT): $(SRC_DIR)/%.cpp
	@if not exist "$(OBJ_DIR)" $(MKDIR) "$(OBJ_DIR)" 2>nul || $(MKDIR) "$(OBJ_DIR)"
	$(CC) $(CFLAGS) $< $(if $(filter cl,$(COMPILER)),/Fo$@,-o $@)

clean:
	$(RM) obj lib
