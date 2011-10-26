#ifndef _SYSLOGD_H
#define _SYSLOGD_H

#include "syslogd_config.h"

/*#define DEBUG_TO_FILE*/
/*#define DEBUG_TO_STDERR*/

#ifdef DEBUG_TO_FILE
	void debug_printf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
#elif defined DEBUG_TO_STDERR
	#define debug_printf(FMT...) fprintf(stderr, FMT), fputc('\n', stderr)
#else
	#define debug_printf(FMT...)
#endif

void shutdown_local_targets(syslogd_config_t *config);
void init_local_targets(syslogd_config_t *config);
void log_local_message(syslogd_local_config_t *local, const char *msg);

void init_remote_targets(syslogd_config_t *config);
void shutdown_remote_targets(syslogd_config_t *config);
void log_remote_message(syslogd_remote_config_t *remote, const char *msg);

void init_email_targets(syslogd_config_t *config);
void shutdown_email_targets(syslogd_config_t *config);
void log_email_message(syslogd_email_config_t *email, const char *msg);

void ipcsyslog_init(void);
void ipcsyslog_cleanup(void);

void syslog_local_message(const char *format, ...)
		__attribute__ ((format (printf, 1, 2)));
void syslog_message(int pri, const char *msg);
int syslog_name_to_pri(const char *name);

#endif
