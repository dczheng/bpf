CC			= gcc
CFLAGS		= -Wall -Wextra
LDFLAGS		=

SRCS		= $(wildcard *.c)
INCL		= $(wildcard *.h)
EXEC		= $(SRCS:.c=)

.PHONY: all clean
all: $(EXEC)

$(EXEC): %:%.c $(INCL) Makefile
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf $(EXEC)
