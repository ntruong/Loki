CC=gcc
CFLAGS=-std=gnu99 -c -g
BIN=bin
BUILD=build
SRC=src
SRCS=$(wildcard $(SRC)/*.c)
OBJS=$(SRCS:$(SRC)/%.c=$(BUILD)/%.o)
TARGET=loki

.SECONDARY:



.PHONY: all
all : $(BIN)/$(TARGET)

$(BIN)/% : $(OBJS)
	$(CC) $(OBJS) -o $(BIN)/$(TARGET)

$(OBJS) : $(BIN) $(BUILD)

$(BUILD)/%.o : $(SRC)/%.c
	$(CC) $(CFLAGS) $< -o $@

$(BIN) :
	@mkdir -p $(BIN)

$(BUILD) :
	@mkdir -p $(BUILD)

.PHONY: test
test : all
	@./$(BIN)/$(TARGET) account pass

.PHONY: clean
clean :
	rm -rf $(BUILD)/*
	rm -rf $(BIN)/*

