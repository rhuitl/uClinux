/* ulogd_PGSQL.c, Version $Revision: 6369 $
 *
 * ulogd output plugin for logging to a PGSQL database
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org> 
 * This software is distributed under the terms of GNU GPL 
 * 
 * This plugin is based on the MySQL plugin made by Harald Welte.
 * The support PostgreSQL were made by Jakab Laszlo.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/db.h>

#include <libpq-fe.h>

#ifdef DEBUG_PGSQL
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

struct pgsql_instance {
	struct db_instance db_inst;

	PGconn *dbh;
	PGresult *pgres;
	unsigned char pgsql_have_schemas;
};
#define TIME_ERR	((time_t)-1)

/* our configuration directives */
static struct config_keyset pgsql_kset = {
	.num_ces = DB_CE_NUM + 6,
	.ces = {
		DB_CES,
		{ 
			.key = "db", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "host", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{ 
			.key = "user", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "pass", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key = "port",
			.type = CONFIG_TYPE_INT,
		},
		{
			.key = "schema", 
			.type = CONFIG_TYPE_STRING,
			.u.string = "public",
		},
	},
};
#define db_ce(x)	(x->ces[DB_CE_NUM+0])
#define host_ce(x)	(x->ces[DB_CE_NUM+1])
#define user_ce(x)	(x->ces[DB_CE_NUM+2])
#define pass_ce(x)	(x->ces[DB_CE_NUM+3])
#define port_ce(x)	(x->ces[DB_CE_NUM+5])
#define schema_ce(x)	(x->ces[DB_CE_NUM+6])

#define PGSQL_HAVE_NAMESPACE_TEMPLATE 			\
	"SELECT nspname FROM pg_namespace n WHERE n.nspname='%s'"

/* Determine if server support schemas */
static int pgsql_namespace(struct ulogd_pluginstance *upi)
{
	struct pgsql_instance *pi = (struct pgsql_instance *) upi->private;
	char pgbuf[strlen(PGSQL_HAVE_NAMESPACE_TEMPLATE) + 
		   strlen(schema_ce(upi->config_kset).u.string) + 1];

	if (!pi->dbh)
		return 1;

	sprintf(pgbuf, PGSQL_HAVE_NAMESPACE_TEMPLATE,
		schema_ce(upi->config_kset).u.string);
	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);
	
	pi->pgres = PQexec(pi->dbh, pgbuf);
	if (!pi->pgres) {
		ulogd_log(ULOGD_DEBUG, "\n result false");
		return 1;
	}

	if (PQresultStatus(pi->pgres) == PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "using schema %s\n",
			  schema_ce(upi->config_kset).u.string);
		pi->db_inst.schema = schema_ce(upi->config_kset).u.string;
	} else {
		pi->db_inst.schema = NULL;
	}

	PQclear(pi->pgres);
	
	return 0;
}

#define PGSQL_GETCOLUMN_TEMPLATE 			\
	"SELECT  a.attname FROM pg_class c, pg_attribute a WHERE c.relname ='%s' AND a.attnum>0 AND a.attrelid=c.oid ORDER BY a.attnum"

#define PGSQL_GETCOLUMN_TEMPLATE_SCHEMA 		\
	"SELECT a.attname FROM pg_attribute a, pg_class c LEFT JOIN pg_namespace n ON c.relnamespace=n.oid WHERE c.relname ='%s' AND n.nspname='%s' AND a.attnum>0 AND a.attrelid=c.oid AND a.attisdropped=FALSE ORDER BY a.attnum"

/* find out which columns the table has */
static int get_columns_pgsql(struct ulogd_pluginstance *upi)
{
	struct pgsql_instance *pi = (struct pgsql_instance *) upi->private;
	char pgbuf[strlen(PGSQL_GETCOLUMN_TEMPLATE_SCHEMA)
		   + strlen(table_ce(upi->config_kset).u.string) 
		   + strlen(pi->db_inst.schema) + 2];
	int i;

	if (!pi->dbh) {
		ulogd_log(ULOGD_ERROR, "no database handle\n");
		return 1;
	}

	if (pi->db_inst.schema) {
		snprintf(pgbuf, sizeof(pgbuf)-1,
			 PGSQL_GETCOLUMN_TEMPLATE_SCHEMA,
			 table_ce(upi->config_kset).u.string,
			 pi->db_inst.schema);
	} else {
		snprintf(pgbuf, sizeof(pgbuf)-1, PGSQL_GETCOLUMN_TEMPLATE,
			 table_ce(upi->config_kset).u.string);
	}

	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);

	pi->pgres = PQexec(pi->dbh, pgbuf);
	if (!pi->pgres) {
		ulogd_log(ULOGD_DEBUG, "result false (%s)",
			  PQerrorMessage(pi->dbh));
		return -1;
	}

	if (PQresultStatus(pi->pgres) != PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "pres_command_not_ok (%s)",
			  PQerrorMessage(pi->dbh));
		PQclear(pi->pgres);
		return -1;
	}

	if (upi->input.keys)
		free(upi->input.keys);

	upi->input.num_keys = PQntuples(pi->pgres);
	ulogd_log(ULOGD_DEBUG, "%u fields in table\n", upi->input.num_keys);
	upi->input.keys = malloc(sizeof(struct ulogd_key) *
						upi->input.num_keys);
	if (!upi->input.keys) {
		upi->input.num_keys = 0;
		ulogd_log(ULOGD_ERROR, "ENOMEM\n");
		PQclear(pi->pgres);
		return -ENOMEM;
	}

	memset(upi->input.keys, 0, sizeof(struct ulogd_key) *
						upi->input.num_keys);

	for (i = 0; i < PQntuples(pi->pgres); i++) {
		char buf[ULOGD_MAX_KEYLEN+1];
		char *underscore;
		int id;

		/* replace all underscores with dots */
		strncpy(buf, PQgetvalue(pi->pgres, i, 0), ULOGD_MAX_KEYLEN);
		while ((underscore = strchr(buf, '_')))
			*underscore = '.';

		DEBUGP("field '%s' found: ", buf);

		/* add it to list of input keys */
		strncpy(upi->input.keys[i].name, buf, ULOGD_MAX_KEYLEN);
	}

	/* FIXME: id? */

	PQclear(pi->pgres);
	return 0;
}

static int close_db_pgsql(struct ulogd_pluginstance *upi)
{
	struct pgsql_instance *pi = (struct pgsql_instance *) upi->private;

	PQfinish(pi->dbh);

	return 0;
}

/* make connection and select database */
static int open_db_pgsql(struct ulogd_pluginstance *upi)
{
	struct pgsql_instance *pi = (struct pgsql_instance *) upi->private;
	int len;
	char *connstr;
	char *server = host_ce(upi->config_kset).u.string;
	char *port = port_ce(upi->config_kset).u.string;
	char *user = user_ce(upi->config_kset).u.string;
	char *pass = pass_ce(upi->config_kset).u.string;
	char *db = db_ce(upi->config_kset).u.string;

	/* 80 is more than what we need for the fixed parts below */
	len = 80 + strlen(user) + strlen(db);

	/* hostname and  and password are the only optionals */
	if (server)
		len += strlen(server);
	if (pass)
		len += strlen(pass);
	if (port)
		len += 20;

	connstr = (char *) malloc(len);
	if (!connstr) 
		return -ENOMEM;

	if (server) {
		strcpy(connstr, " host=");
		strcat(connstr, server);
	}

	if (port) {
		char portbuf[20];
		snprintf(portbuf, sizeof(portbuf), " port=%u", port);
		strcat(connstr, portbuf);
	}

	strcat(connstr, " dbname=");
	strcat(connstr, db);
	strcat(connstr, " user=");
	strcat(connstr, user);

	if (pass) {
		strcat(connstr, " password=");
		strcat(connstr, pass);
	}
	
	pi->dbh = PQconnectdb(connstr);
	if (PQstatus(pi->dbh) != CONNECTION_OK) {
		ulogd_log(ULOGD_ERROR, "unable to connect to db (%s): %s\n",
			  connstr, PQerrorMessage(pi->dbh));
		close_db_pgsql(upi);
		return -1;
	}

	if (pgsql_namespace(upi)) {
		ulogd_log(ULOGD_ERROR, "unable to test for pgsql schemas\n");
		close_db_pgsql(upi);
		return -1;
	}

	return 0;
}

static int escape_string_pgsql(struct ulogd_pluginstance *upi,
			       char *dst, const char *src, unsigned int len)
{
	PQescapeString(dst, src, strlen(src)); 
	return 0;
}

static int execute_pgsql(struct ulogd_pluginstance *upi,
			 const char *stmt, unsigned int len)
{
	struct pgsql_instance *pi = (struct pgsql_instance *) upi->private;

	pi->pgres = PQexec(pi->dbh, stmt);
	if (!pi->pgres || PQresultStatus(pi->pgres) != PGRES_COMMAND_OK) {
		ulogd_log(ULOGD_ERROR, "execute failed (%s)\n",
			  PQerrorMessage(pi->dbh));
		return -1;
	}

	return 0;
}

static struct db_driver db_driver_pgsql = {
	.get_columns	= &get_columns_pgsql,
	.open_db	= &open_db_pgsql,
	.close_db	= &close_db_pgsql,
	.escape_string	= &escape_string_pgsql,
	.execute	= &execute_pgsql,
};

static int configure_pgsql(struct ulogd_pluginstance *upi,
			   struct ulogd_pluginstance_stack *stack)
{
	struct pgsql_instance *pi = (struct pgsql_instance *) upi->private;

	pi->db_inst.driver = &db_driver_pgsql;

	return ulogd_db_configure(upi, stack);
}

static struct ulogd_plugin pgsql_plugin = { 
	.name 		= "PGSQL", 
	.input 		= {
		.keys	= NULL,
		.num_keys = 0,
		.type	= ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output 	= {
		.type	= ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &pgsql_kset,
	.priv_size	= sizeof(struct pgsql_instance),
	.configure	= &configure_pgsql,
	.start		= &ulogd_db_start,
	.stop		= &ulogd_db_stop,
	.signal		= &ulogd_db_signal,
	.interp		= &ulogd_db_interp,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&pgsql_plugin);
}
