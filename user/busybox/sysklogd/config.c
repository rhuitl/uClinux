#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <syslog.h>

#include "syslogd.h"
#include "syslogd_config.h"

static const char *__log_file = "/var/log/messages";

static int syslogd_level(const char *name)
{
	int pri;

	if (strcmp(name, "none") == 0) {
		return LOG_NONE;
	}

	pri = syslog_name_to_pri(name);
	if (pri < 0) {
		debug_printf("Warning: Level %s not found, returning debug", name);
		pri = LOG_DEBUG;
	}
	return pri;
}

int syslogd_load_config(const char *filename, syslogd_config_t *config)
{
	FILE *fh = fopen(filename, "r");
	char buf[512];

	/* Initialise the default config */
	memset(config, 0, sizeof(*config));

	config->local.common.target = SYSLOG_TARGET_LOCAL;
	config->local.common.level = LOG_DEBUG;
	config->local.common.priv = 0;
	config->local.common.next = 0;
	config->local.maxsize = 16;
	config->local.logfile = (char *) __log_file;
	config->local.numfiles = 1;
#ifndef EMBED
	config->local.markinterval = 20 * 60;
#endif

	if (!fh) {
		return 1;
	}

	while (fgets(buf, sizeof(buf), fh)) {
		syslogd_target_t *target;

		char *type = strtok(buf, " \t\n");
		if (type && *type && *type != '#') {
			char *token;

			if (strcmp(type, "global") == 0) {
				target = 0;
			}
			else if (strcmp(type, "local") == 0) {
				target = &config->local.common;
			}
			else if (strcmp(type, "remote") == 0) {
				syslogd_remote_config_t *remote = malloc(sizeof(*remote));

				memset(remote, 0, sizeof(*remote));

				target = &remote->common;
				target->target = SYSLOG_TARGET_REMOTE;
				target->level = LOG_DEBUG;
				target->next = config->local.common.next;
				config->local.common.next = target;

				remote->port = 514;
			}
			else if (strcmp(type, "email") == 0) {
				syslogd_email_config_t *email = malloc(sizeof(*email));

				memset(email, 0, sizeof(*email));

				target = &email->common;
				target->target = SYSLOG_TARGET_EMAIL;
				target->level = LOG_ERR;
				target->next = config->local.common.next;
				config->local.common.next = target;

				email->delay = 60;
			}
			else {
				debug_printf("Unknown target type: %s", type);
				continue;
			}

			/* Now fill in the parameters */
			while ((token = strtok(0, " \t\n")) != 0) {
				char *value = strchr(token, '=');
				if (value) {
					*value++ = 0;

					/* Now we finally have type, token and value */
					if (target == 0) {
						if (strcmp(token, "iso") == 0) {
							config->iso = atoi(value);
						}
						else if (strcmp(token, "repeat") == 0) {
							config->repeat = atoi(value);
						}
						else {
							debug_printf("Unknown %s: %s=%s", type, token, value);
						}
						continue;
					}

					if (strcmp(token, "level") == 0) {
						target->level = syslogd_level(value);
						continue;
					}

					switch (target->target) {
						case SYSLOG_TARGET_LOCAL:
							{
								syslogd_local_config_t *local = (syslogd_local_config_t *)target;

								if (strcmp(token, "maxsize") == 0) {
									local->maxsize = atoi(value);
								}
								else if (strcmp(token, "markinterval") == 0) {
									local->markinterval = atoi(value) * 60;
								}
								else if (strcmp(token, "numfiles") == 0) {
									local->numfiles = atoi(value);
								}
								else if (strcmp(token, "logfile") == 0) {
									local->logfile = strdup(value);
								}
								else {
									debug_printf("Unknown %s: %s=%s", type, token, value);
								}
							}
							break;

						case SYSLOG_TARGET_REMOTE:
							{
								syslogd_remote_config_t *remote = (syslogd_remote_config_t *)target;

								if (strcmp(token, "host") == 0) {
									remote->host = strdup(value);
								}
								else if (strcmp(token, "port") == 0) {
									remote->port = atoi(value);
								}
								else if (strcmp(token, "name") == 0) {
									remote->name = strdup(value);
								}
								else {
									debug_printf("Unknown %s: %s=%s", type, token, value);
								}
							}
							break;

						case SYSLOG_TARGET_EMAIL:
							{
								syslogd_email_config_t *email = (syslogd_email_config_t *)target;

								if (strcmp(token, "server") == 0) {
									email->server = strdup(value);
								}
								else if (strcmp(token, "addr") == 0) {
									if (!email->addr) {
										email->addr = strdup(value);
									}
									else {
										/* Append this one */
										char *pt = malloc(strlen(email->addr) + strlen(value) + 2);
										sprintf(pt, "%s %s", email->addr, value);
										free(email->addr);
										email->addr = pt;
									}
								}
								else if (strcmp(token, "sender") == 0) {
									email->sender = strdup(value);
								}
								else if (strcmp(token, "from") == 0) {
									email->from = strdup(value);
								}
								else if (strcmp(token, "fromhost") == 0) {
									email->fromhost = strdup(value);
								}
								else if (strcmp(token, "delay") == 0) {
									email->delay = atoi(value);
								}
								else if (strcmp(token, "freq") == 0) {
									email->freq = atoi(value);
								}
								else {
									debug_printf("Unknown %s: %s=%s", type, token, value);
								}
							}
					}
				}
			}

			/* REVISIT: Validate that the required fields are set for each type */
		}
	}

	fclose(fh);

	return 0;
}

void syslogd_discard_config(syslogd_config_t *config)
{
	while (config->local.common.next) {
		syslogd_target_t *target = config->local.common.next;

		config->local.common.next = target->next;

		free(target->priv);

		switch (target->target) {
#ifdef CONFIG_FEATURE_REMOTE_LOG
			case SYSLOG_TARGET_REMOTE:
				{
					syslogd_remote_config_t *remote = (syslogd_remote_config_t *)target;

					free(remote->host);
					free(remote->name);
				}
				break;
#endif

#ifdef CONFIG_USER_SMTP_SMTPCLIENT
			case SYSLOG_TARGET_EMAIL:
				{
					syslogd_email_config_t *email = (syslogd_email_config_t *)target;

					free(email->server);
					free(email->addr);
					free(email->fromhost);
					free(email->sender);
					free(email->from);
				}
				break;
#endif
			default:
				break;
		}
		free(target);
	}

	if (config->local.logfile != __log_file)
		free(config->local.logfile);
	free(config->local.common.priv);
}
