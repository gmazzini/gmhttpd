CC=gcc
CFLAGS=-O3 -march=native -Wall -Wextra -Werror -std=gnu89
LDLIBS=-lssl -lcrypto

all: gmhttpd

gmhttpd: gmhttpd.c
	$(CC) $(CFLAGS) -o gmhttpd gmhttpd.c $(LDLIBS)

clean:
	rm -f gmhttpd
