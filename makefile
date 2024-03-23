# Compiler
CC := gcc

# Directories
SRC_DIR := .
OBJ_DIR := obj
BIN_DIR := bin

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC))
BINS := $(BIN_DIR)/icmput $(BIN_DIR)/icmput_server

# Compiler flags
CFLAGS := -Wall -Wextra

# Linker flags for server
SRVLDFLAGS := -lpcap

# Build targets
all: $(BINS)

# Rule to compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/icmput_server: $(OBJ_DIR)/icmput_server.o | $(BIN_DIR)
	$(CC) $(SRVLDFLAGS) $< -o $@
	echo "Attempting to add cap_net_raw and cap_net_admin permissions to server"
	sudo setcap cap_net_raw,cap_net_admin=eip $@
	
$(BIN_DIR)/icmput: $(OBJ_DIR)/icmput.o | $(BIN_DIR)
	$(CC) $< -o $@

# Create the directories if they don't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean
