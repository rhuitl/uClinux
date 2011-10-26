NAME = fconfig
SRC = fconfig.c debug.c crc.c ftypes.c crunchfc.c
OBJ = $(subst .c,.o, $(SRC))

all: $(NAME)

%.d: %.c
	$(SHELL) -ec '$(CC) -M $(CPPFLAGS) $< \
		| sed '\''s/\($*\)\.o[ :]*/\1.o $@ : /g'\'' > $@; \
		[ -s $@ ] || rm -f $@'

ifneq ($(MAKECMDGOALS), clean)
-include $(SRC:.c=.d)
endif

$(NAME): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

romfs:
	[ "$(CONFIG_USER_FCONFIG_FCONFIG)" != y ] \
		|| cp $(NAME) $(ROMFSDIR)/bin/.

clean:
	-rm -f $(NAME) *.d *.o

