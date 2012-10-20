CC := gcc
CFLAGS := -pedantic -Wall -std=c99 -O2 -D_GNU_SOURCE
LDFLAGS := -lpcap

PROGS := udpbuster
OBJECTS := udptable.o

all: $(PROGS)

$(OBJECTS): %.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

$(PROGS): %: %.c $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(PROGS) $(OBJECTS)

