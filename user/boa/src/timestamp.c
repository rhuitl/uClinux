#include "boa.h"
#include "syslog.h"


void timestamp(void)
{
#if 0
	log_error_time();
	fprintf(stderr, "boa: server version %s\n", SERVER_VERSION);
	log_error_time();
	fprintf(stderr, "boa: server built " __DATE__ " at " __TIME__ \
			".\n");
	log_error_time();
	fprintf(stderr, "boa: starting server pid=%d, port %d\n",
			getpid(), server_port);
#endif
	syslog(LOG_INFO, SERVER_VERSION" started");
}
