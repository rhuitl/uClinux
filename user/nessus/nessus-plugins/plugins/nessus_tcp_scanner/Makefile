include ../../nessus.tmpl

PLUGNAME=nessus_tcp_scanner

# If you compile this plugin with -DSTATISTICS or -DCOMPUTE_RTT, 
# add -lm after $LIBS

all : $(PLUGNAME).nes
$(PLUGNAME).nes : $(PLUGNAME).c 
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c  $(PLUGNAME).c
	$(LIBTOOL) $(CC) $(DEFS) -o lib$(PLUGNAME).la $(PLUGNAME).lo $(LIBS) -lm $(LIBUTIL) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
