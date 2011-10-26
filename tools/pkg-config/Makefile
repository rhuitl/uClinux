HOSTCC ?= cc

EXEC=pkg-config
OBJS=main.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(HOSTCC) -g -Werror -Wall -DHAVE_MKSTEMP -o $@ $^

clean:
	$(RM) -f $(OBJS) $(EXEC)
