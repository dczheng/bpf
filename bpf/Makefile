include ../config.mk

SRCS		= $(wildcard *.c)
OBJS		= $(SRCS:.c=.o)
EXEC_SRCS	= $(filter-out bpf.c,$(SRCS))
INCL		= $(wildcard *.h)
EXEC		= $(EXEC_SRCS:.c=)
INCL	   += ../tools.h

.PHONY: all clean
all: $(EXEC)

$(OBJS): %.o:%.c $(INCL) Makefile
	$(call compile,$(CC),$<,$@)

$(EXEC): %:%.o bpf.o
	$(call link,$(CC),$< bpf.o,$@)

clean:
	$(call clean,$(EXEC) $(OBJS))
