CC=gcc
CFLAGS=-std=gnu99 -O3
SRC=$(wildcard src/*.c)
TARGET=loki

.PHONY: all test clean

all : $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

test : all
	@./$(BIN)/$(TARGET) account pass

clean :
	rm -rf $(TARGET)*
