ifdef HOSTBUILD
	# Can't convince PAM to use a different path
	CONFIG_USER_FNORD_NOAUTH=y

	# This one runs in server mode so that we don't need tcpserver
	CFLAGS += -DDEBUG -DLOG_TO_SYSLOG -DSERVER_MODE #-DCHECK_STR_COPY
endif
