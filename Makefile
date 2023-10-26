CC=gcc
CFLAGS=-pedantic -Wall -Wextra -g -lpcap -std=gnu99
NAME=ipk-sniffer

all:
		$(CC) $(GFLAGS) ipk-sniffer.c -o $(NAME) -lpcap
Clean:

		-rm -f *.o $(NAME)
