
SUBDIRS = res

EXTRA_DIST = tst tst_sdp tst_rfc3264 CHECK

if COMPILE_TESTS
noinst_PROGRAMS = torture_rfc3264 torture_test turl tfrom tto tcontact tvia tcallid tcontentt trecordr troute twwwa

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/osipparser2
AM_CFLAGS = $(SIP_CFLAGS) $(SIP_PARSER_FLAGS) $(SIP_EXTRA_FLAGS)

twwwa_SOURCES =  twwwa.c
twwwa_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la

tcontentt_SOURCES =  tcontentt.c
tcontentt_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

turl_SOURCES =  turls.c
turl_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

tfrom_SOURCES =  tfrom.c
tfrom_LDADD =  $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

tto_SOURCES =  tto.c
tto_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 


tcontact_SOURCES =  tcontact.c
tcontact_LDADD =  $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

trecordr_SOURCES =  trecordr.c
trecordr_LDADD =  $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

troute_SOURCES =  troute.c
troute_LDADD =  $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

tvia_SOURCES =  tvia.c
tvia_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

tcallid_SOURCES =  tcallid.c
tcallid_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

#torture_sdp_test_SOURCES =  torture_sdp.c
#torture_sdp_test_LDADD = $(PARSER_LIB) $(FSM_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la $(top_builddir)/src/osip2/libosip2.la 

torture_rfc3264_SOURCES =  torture_rfc3264.c
torture_rfc3264_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 

torture_test_SOURCES =  torture.c
torture_test_LDADD = $(PARSER_LIB) $(EXTRA_LIB) $(top_builddir)/src/osipparser2/libosipparser2.la 



check:
	@echo " *******************************"
	@echo " ****** starting tests! ********"
	@echo " *******************************"
	@./$(top_srcdir)/src/test/tst ./$(top_srcdir)/src/test/res -c
	@./$(top_srcdir)/src/test/tst_rfc3264 ./$(top_srcdir)/src/test/res/torture_sdps -v -c > ./osipsdp-chk.log 2>&1

	@echo ""
	@echo "In case you have a doubt, send the generated"
	@echo "log file with your comment to <jack@atosc.org>."
else
check:
	@echo " ************************************"
	@echo " Please use ./configure --enable-test"
	@echo " ************************************"
endif
