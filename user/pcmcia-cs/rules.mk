# Global defaults

COFLAGS = -kv
YFLAGS = -d

%.c %.h : %.y
	$(YACC) $(YFLAGS) $<
	mv y.tab.c $*.c
	mv y.tab.h $*.h

%.s : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -S $<

MD=$(PREFIX)$(MODDIR)/pcmcia
install-modules: $(MODULES)
	@mkdir -p $(MD)
	@for F in $(MODULES) ; do rm -f $(MD)/$$F ; done
	cp $(MODULES) $(MD)

# Stuff to automatically maintain dependency files

%.o : %.c
	$(CC) -MD $(CFLAGS) $(CPPFLAGS) -c $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

-include $(SRCS:%.c=.depfiles/%.d)
