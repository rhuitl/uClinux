include nessus.tmpl


PLUGNAME=plugin

all : $(PLUGNAME).nes
$(PLUGNAME).nes : $(PLUGNAME).c
	$(SHELL) libtool $(CC) $(DEFS) $(include) -c  $(PLUGNAME).c
	$(SHELL) libtool $(CC) $(DEFS) -o lib$(PLUGNAME).la $(PLUGNAME).lo $(LIBS) \
	-rpath $(prefix)/plugins/
	
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
