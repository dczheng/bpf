CC			= gcc
LDFLAGS		=
CFLAGS		= -Wall -Wextra

SRCS		= $(wildcard *.c)
INCL		= $(wildcard *.h)
EXEC        = $(SRCS:.c=)

.PHONY: all config clean
all: $(EXEC)

print = @echo "[$(1)] $($(1))"

$(EXEC): %:%.c $(INCL) Makefile
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf $(EXEC)
