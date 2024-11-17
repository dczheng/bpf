CC			= gcc
LDFLAGS		=
CFLAGS		= -Wall -Wextra

SRCS		= $(wildcard *.c)
INCL		= $(wildcard *.h)
EXEC        = $(SRCS:.c=)

.PHONY: all config clean
all: $(EXEC)

$(EXEC): %:%.c $(INCL) Makefile
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf $(EXEC)
