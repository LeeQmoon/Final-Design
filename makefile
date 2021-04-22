#.SUFFIXES:.c .o
CC=gcc
SRCS=final.c\
	hash.c
OBJS=$(SRCS:.c=.o)
EXEC=final

build:$(OBJS)
	$(CC) -Wall -g -o $(EXEC) $(OBJS) -lpcap
	@echo '-------------OK------------'

.c.o:
	$(CC) -Wall -g -o $@ -c $<

clean:
	rm -f $(OBJS)
	rm -f $(EXEC)
