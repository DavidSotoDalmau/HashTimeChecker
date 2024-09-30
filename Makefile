# Compiler and flags
CC = gcc
CFLAGS = -O3

# Target to build
TARGET = HashTimeChecker
LDFLAGS = -o $(TARGET)

# Libraries
LIBS = -lssl -lcrypto

# Object files
OBJS = hashes.o blake2b.o blake2b-ref.o blake2bp.o blake2bp-ref.o blake3.o

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o $(TARGET)

# Command line to build
# gcc -O3 -o hash_calculator hashes.c blake2b.c blake2b-ref.c blake2bp.c blake2bp-ref.c blake3.c -lssl -lcrypto

