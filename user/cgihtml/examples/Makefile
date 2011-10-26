# Makefile for cgihtml examples
# Based on original Makefile of Eugene Eric Kim <eekim@eekim.com>
#
# Adapted to the uClinux dist by
# Heiko Degenhardt <linux@sentec-elektronik.de>
# Version: 	01.00
# Date:		20030325
#
# ATTENTION!
# There are security bugs in that version of cgihtml!
# Don't use this version on a remote accessible server!
# Search for "cgihtml" at http://www.securityfocus.com/search!
# 
# CHANGES
#
# 20030325  - adapted to the uClinux-dist
#             (hede)


# macros and variables
LIB = ../cgihtml.a

EXEC = query-results mail.cgi index-sample.cgi ignore.cgi test.cgi


# targets
all: $(LIB) $(EXEC) 

query-results: query-results.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB) $(LDLIBS$(LDLIBS_$@))

mail.cgi: mail.cgi.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB) $(LDLIBS$(LDLIBS_$@))

index-sample.cgi: index-sample.cgi.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB) $(LDLIBS$(LDLIBS_$@))

ignore.cgi: ignore.cgi.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB) $(LDLIBS$(LDLIBS_$@))

test.cgi: test.cgi.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB) $(LDLIBS$(LDLIBS_$@))



$(LIB):
	cd ..; make cgihtml.a


romfs:
	$(ROMFSINST) query-results /home/httpd/cgi-bin/query-results
	$(ROMFSINST) mail.cgi /home/httpd/cgi-bin/mail.cgi
	$(ROMFSINST) index-sample.cgi /home/httpd/cgi-bin/index-sample.cgi
	$(ROMFSINST) ignore.cgi /home/httpd/cgi-bin/ignore.cgi
	$(ROMFSINST) test.cgi /home/httpd/cgi-bin/test.cgi

clean:
	-rm -f $(EXEC) $(OBJ) *.elf *.gdb *.o

