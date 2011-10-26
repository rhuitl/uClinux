
sbin_PROGRAMS = clamsmtpd

clamsmtpd_SOURCES = clamsmtpd.c clamsmtpd.h \
			../common/spio.c ../common/smtppass.c ../common/smtppass.h ../common/sppriv.h \
			../common/stringx.c ../common/stringx.h ../common/sock_any.c ../common/sock_any.h \
			../common/usuals.h ../common/compat.c ../common/compat.h 

clamsmtpd_CFLAGS = -I${top_srcdir}/common/ -I${top_srcdir}/

all-local:
	@echo "NOTE: Ignore any warnings about mktemp(). It's used safely in this case."
	@echo 
	  