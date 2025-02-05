CC = g++
LDFLAGS = -lcrypto

all: build run

build: part1 part2

part1: part1.cpp
	$(CC) part1.cpp -o part1 $(LDFLAGS)

part2: part2.cpp
	$(CC) part2.cpp -o part2 $(LDFLAGS)

run: part1 part2
	./part1
	./part2

clean:
	rm -f part1 part2

.PHONY: all build run clean