#ifndef _ULOGD_DB_H
#define _ULOGD_DB_H

#include <ulogd/ulogd.h>

struct db_driver {
	int (*get_columns)(struct ulogd_pluginstance *upi);
	int (*open_db)(struct ulogd_pluginstance *upi);
	int (*close_db)(struct ulogd_pluginstance *upi);
	int (*escape_string)(struct ulogd_pluginstance *upi,
			     char *dst, const char *src, unsigned int len);
	int (*execute)(struct ulogd_pluginstance *upi,
			const char *stmt, unsigned int len);
};

struct db_instance {
	char *stmt; /* buffer for our insert statement */
	char *stmt_val; /* pointer to the beginning of the "VALUES" part */
	char *stmt_ins; /* pointer to current inser position in statement */
	char *schema;
	time_t reconnect;
	int (*interp)(struct ulogd_pluginstance *upi);
	struct db_driver *driver;
};
#define TIME_ERR		((time_t)-1)	/* Be paranoid */

#define DB_CES							\
		{						\
			.key = "table",				\
			.type = CONFIG_TYPE_STRING,		\
			.options = CONFIG_OPT_MANDATORY,	\
		},						\
		{						\
			.key = "reconnect",			\
			.type = CONFIG_TYPE_INT,		\
		},						\
		{						\
			.key = "ip_as_string",			\
			.type = CONFIG_TYPE_INT,		\
		},						\
		{						\
			.key = "connect_timeout",		\
			.type = CONFIG_TYPE_INT,		\
		}

#define DB_CE_NUM	4
#define table_ce(x)	(x->ces[0])
#define reconnect_ce(x)	(x->ces[1])
#define asstring_ce(x)	(x->ces[2])
#define timeout_ce(x)	(x->ces[3])

void ulogd_db_signal(struct ulogd_pluginstance *upi, int signal);
int ulogd_db_start(struct ulogd_pluginstance *upi);
int ulogd_db_stop(struct ulogd_pluginstance *upi);
int ulogd_db_interp(struct ulogd_pluginstance *upi);
int ulogd_db_configure(struct ulogd_pluginstance *upi,
			struct ulogd_pluginstance_stack *stack);


#endif
