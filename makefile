#.SUFFIXES:.c .o
CC=gcc
SRCS=final.c\
	hash.c
OBJS=$(SRCS:.c=.o)
EXEC=final

build:$(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -lpcap
	@echo '-------------OK------------'

clean:
	rm -f $(OBJS)
	rm -f $(EXEC)
