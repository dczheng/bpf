CC			= gcc
CFLAGS		= -Wall -Wextra
LDFLAGS		=

SRCS		= $(wildcard *.c)
OBJS		= $(SRCS:.c=.o)
EXEC_SRCS	= $(filter-out bpf.c,$(SRCS))
INCL		= $(wildcard *.h)
EXEC		= $(EXEC_SRCS:.c=)

.PHONY: all clean
all: $(EXEC)

$(OBJS): %.o:%.c $(INCL) Makefile
	$(CC) $(CFLAGS) $< -c

$(EXEC): %:%.o bpf.o
	$(CC) $< bpf.o $(LDFLAGS) -o $@

clean:
	rm -rf $(EXEC) $(OBJS)
