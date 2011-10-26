#ifndef SYSLOGD_CONFIG_H
#define SYSLOGD_CONFIG_H

#define SYSLOG_TARGET_LOCAL 0
#define SYSLOG_TARGET_REMOTE 1
#define SYSLOG_TARGET_EMAIL 2

/* We have an extra log level which causes nothing to be logged */
#define LOG_NONE -1

typedef struct syslogd_target_s {
	struct syslogd_target_s *next;
	int target;
	int level;
	void *priv;
} syslogd_target_t;

typedef struct {
	syslogd_target_t common;
	char *host;
	int port;
	char *name;
} syslogd_remote_config_t;

typedef struct {
	syslogd_target_t common;
	char *logfile;
	/* max size of message file before being rotated (in KB) */
	int maxsize;
	/* interval between marks in seconds */
	int markinterval;
	/* number of rotated message files */
	int numfiles;
	int circular_logging;
} syslogd_local_config_t;

typedef struct {
	syslogd_target_t common;
	char *server;
	char *addr;
	char *fromhost;
	char *sender;
	char *from;
	int delay;
	int freq;
} syslogd_email_config_t;

typedef struct {
	int iso;
	int repeat;
	/* localhost's name */
	char local_hostname[64];
	/* This is a list of targets. We always have a local target */
	syslogd_local_config_t local;
} syslogd_config_t;

int syslogd_load_config(const char *filename, syslogd_config_t *config);
void syslogd_discard_config(syslogd_config_t *config);

#endif
