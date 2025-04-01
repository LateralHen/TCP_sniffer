# Nome dell'eseguibile
TARGET = sniffer

# File sorgenti
SRC = main.c

# Compilatore e flag
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Comando di default: build
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Pulizia dei file generati
clean:
	rm -f $(TARGET)
