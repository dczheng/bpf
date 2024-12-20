CC			= ccache gcc
CXX			= ccache g++

CFLAGS		= -Wall -Wextra
LDFLAGS		=
INCL		= ../tools.h ../tools-common.h

RED			= \033[38;5;1m
GREEN		= \033[38;5;10m
BLUE		= \033[38;5;4m
YELLOW		= \033[38;5;11m
WHITE		= \033[38;5;15m

run = @t=$$(date +%s) && $(2) && \
		echo "$(3)[$$(hostname)] $1 ... \
			 $$(echo "$$(date +%s)-$${t}" | bc)s$(WHITE)"

generate = $(call run,generate $(1),$(2),$(RED))
compile = $(call run,compile $(2),$(1) $(CFLAGS) $(2) -c -o $(3))
link = $(call run,link $(3),$(1) $(2) $(LDFLAGS) -o $(3),$(GREEN))
build = $(call run,build $(3),$(1) $(CFLAGS) $(2) $(LDFLAGS) -o $(3),$(GREEN))
clean = $(call run,clean $(1),rm -rf $(1),$(RED))
