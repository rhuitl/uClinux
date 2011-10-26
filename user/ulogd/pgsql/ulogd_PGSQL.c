/* ulogd_PGSQL.c, Version $Revision: 714 $
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
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <libpq-fe.h>


#ifdef DEBUG_PGSQL
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

struct _field {
	char name[ULOGD_MAX_KEYLEN];
	unsigned int id;
	struct _field *next;
};

/* the database handle we are using */
static PGconn *dbh;

/* a linked list of the fields the table has */
static struct _field *fields;

/* buffer for our insert statement */
static char *stmt;

/* pointer to the beginning of the "VALUES" part */
static char *stmt_val;

/* pointer to current inser position in statement */
static char *stmt_ins;

/* our configuration directives */
static config_entry_t db_ce = { 
	.key = "db", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t host_ce = { 
	.next = &db_ce, 
	.key = "host", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_NONE,
};

static config_entry_t user_ce = { 
	.next = &host_ce, 
	.key = "user", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t pass_ce = { 
	.next = &user_ce, 
	.key = "pass", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_NONE,
};

static config_entry_t table_ce = { 
	.next = &pass_ce, 
	.key = "table", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t schema_ce = { 
	.next = &table_ce, 
	.key = "schema", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_NONE,
	.u.string = "public",
};

static config_entry_t port_ce = {
	.next = &schema_ce,
	.key = "port",
	.type = CONFIG_TYPE_INT,
	.options = CONFIG_OPT_NONE,
};

static unsigned char pgsql_have_schemas;

/* our main output function, called by ulogd */
static int pgsql_output(ulog_iret_t *result)
{
	struct _field *f;
	ulog_iret_t *res;
	PGresult   *pgres;
#ifdef IP_AS_STRING
	char *tmpstr;		/* need this for --log-ip-as-string */
	struct in_addr addr;
#endif

	stmt_ins = stmt_val;

	for (f = fields; f; f = f->next) {
		res = keyh_getres(f->id);

		if (!res) {
			ulogd_log(ULOGD_NOTICE,
				"no result for %s ?!?\n", f->name);
		}

		if (!res || !IS_VALID((*res))) {
			/* no result, we have to fake something */
			sprintf(stmt_ins, "NULL,");
			stmt_ins = stmt + strlen(stmt);
			continue;
		}

		switch (res->type) {
			case ULOGD_RET_INT8:
				sprintf(stmt_ins, "%d,", res->value.i8);
				break;
			case ULOGD_RET_INT16:
				sprintf(stmt_ins, "%d,", res->value.i16);
				break;
			case ULOGD_RET_INT32:
				sprintf(stmt_ins, "%d,", res->value.i32);
				break;
			case ULOGD_RET_INT64:
				sprintf(stmt_ins, "%lld,", res->value.i64);
				break;
			case ULOGD_RET_UINT8:
				sprintf(stmt_ins, "%u,", res->value.ui8);
				break;
			case ULOGD_RET_UINT16:
				sprintf(stmt_ins, "%u,", res->value.ui16);
				break;
			case ULOGD_RET_IPADDR:
#ifdef IP_AS_STRING
				*stmt_ins++ = '\'';
				memset(&addr, 0, sizeof(addr));
				addr.s_addr = ntohl(res->value.ui32);
				tmpstr = (char *)inet_ntoa(addr);
				PQescapeString(stmt_ins,tmpstr,strlen(tmpstr)); 
				stmt_ins = stmt + strlen(stmt);
				sprintf(stmt_ins, "',");
				break;
#endif /* IP_AS_STRING */
				/* EVIL: fallthrough when logging IP as
				 * u_int32_t */

			case ULOGD_RET_UINT32:
				sprintf(stmt_ins, "%u,", res->value.ui32);
				break;
			case ULOGD_RET_UINT64:
				sprintf(stmt_ins, "%llu,", res->value.ui64);
				break;
			case ULOGD_RET_BOOL:
				sprintf(stmt_ins, "'%d',", res->value.b);
				break;
			case ULOGD_RET_STRING:
				*stmt_ins++ = '\'';
				PQescapeString(stmt_ins,res->value.ptr,strlen(res->value.ptr)); 
				stmt_ins = stmt + strlen(stmt);
				sprintf(stmt_ins, "',");
				break;
			case ULOGD_RET_RAW:
				ulogd_log(ULOGD_NOTICE,"%s: pgsql doesn't support type RAW\n",res->key);
				sprintf(stmt_ins, "NULL,");
				break;
			default:
				ulogd_log(ULOGD_NOTICE,
					"unknown type %d for %s\n",
					res->type, res->key);
				break;
		}
		stmt_ins = stmt + strlen(stmt);
	}
	*(stmt_ins - 1) = ')';
	DEBUGP("stmt=#%s#\n", stmt);

	/* now we have created our statement, insert it */
	/* Added code by Jaki */
	pgres = PQexec(dbh, stmt);
	if(!pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
		ulogd_log(ULOGD_ERROR, "sql error during insert: %s\n",
				PQresultErrorMessage(pgres));
		return 1;
	}

	return 0;
}

#define PGSQL_HAVE_NAMESPACE_TEMPLATE "SELECT nspname FROM pg_namespace n WHERE n.nspname='%s'"

/* Determine if server support schemas */
static int pgsql_namespace(void) {
	PGresult *result;
	char pgbuf[strlen(PGSQL_HAVE_NAMESPACE_TEMPLATE)+strlen(schema_ce.u.string)+1];

	if (!dbh)
		return 1;

	sprintf(pgbuf, PGSQL_HAVE_NAMESPACE_TEMPLATE, schema_ce.u.string);
	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);
	
	result = PQexec(dbh, pgbuf);
	if (!result) {
		ulogd_log(ULOGD_DEBUG, "\n result false");
		return 1;
	}

	if (PQresultStatus(result) == PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "using schema %s\n", schema_ce.u.string);
		pgsql_have_schemas = 1;
	} else {
		pgsql_have_schemas = 0;
	}

	PQclear(result);
	
	return 0;
}

#define PGSQL_INSERTTEMPL   "insert into X (Y) values (Z)"
#define PGSQL_VALSIZE	100

/* create the static part of our insert statement */
static int pgsql_createstmt(void)
{
	struct _field *f;
	unsigned int size;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;

	if (stmt) {
		ulogd_log(ULOGD_NOTICE, "createstmt called, but stmt"
			" already existing\n");
		return 1;
	}

	/* caclulate the size for the insert statement */
	size = strlen(PGSQL_INSERTTEMPL) + strlen(table_ce.u.string) + strlen(schema_ce.u.string) + 1;

	for (f = fields; f; f = f->next) {
		/* we need space for the key and a comma, as well as
		 * enough space for the values */
		size += strlen(f->name) + 1 + PGSQL_VALSIZE;
	}

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	stmt = (char *) malloc(size);

	if (!stmt) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return 1;
	}

	if (pgsql_have_schemas) {
		sprintf(stmt, "insert into %s.%s (", schema_ce.u.string, table_ce.u.string);
	} else {
		sprintf(stmt, "insert into %s (", table_ce.u.string);
	}

	stmt_val = stmt + strlen(stmt);

	for (f = fields; f; f = f->next) {
		strncpy(buf, f->name, ULOGD_MAX_KEYLEN);
		while ((underscore = strchr(buf, '.')))
			*underscore = '_';
		sprintf(stmt_val, "%s,", buf);
		stmt_val = stmt + strlen(stmt);
	}
	*(stmt_val - 1) = ')';

	sprintf(stmt_val, " values (");
	stmt_val = stmt + strlen(stmt);

	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", stmt);

	return 0;
}

#define PGSQL_GETCOLUMN_TEMPLATE "SELECT  a.attname FROM pg_class c, pg_attribute a WHERE c.relname ='%s' AND a.attnum>0 AND a.attrelid=c.oid ORDER BY a.attnum"

#define PGSQL_GETCOLUMN_TEMPLATE_SCHEMA "SELECT a.attname FROM pg_attribute a, pg_class c LEFT JOIN pg_namespace n ON c.relnamespace=n.oid WHERE c.relname ='%s' AND n.nspname='%s' AND a.attnum>0 AND a.attrelid=c.oid AND a.attisdropped=FALSE ORDER BY a.attnum"

/* find out which columns the table has */
static int pgsql_get_columns(const char *table)
{
	PGresult *result;
	char buf[ULOGD_MAX_KEYLEN];
	char pgbuf[strlen(PGSQL_GETCOLUMN_TEMPLATE_SCHEMA)+strlen(table)+strlen(schema_ce.u.string)+2];
	char *underscore;
	struct _field *f;
	int id;
	int intaux;

	if (!dbh)
		return 1;

	if (pgsql_have_schemas) {
		snprintf(pgbuf, sizeof(pgbuf)-1, PGSQL_GETCOLUMN_TEMPLATE_SCHEMA, table, schema_ce.u.string);
	} else {
		snprintf(pgbuf, sizeof(pgbuf)-1, PGSQL_GETCOLUMN_TEMPLATE, table);
	}

	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);

	result = PQexec(dbh, pgbuf);
	if (!result) {
		ulogd_log(ULOGD_DEBUG, "\n result false");
		return 1;
	}

	if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "\n pres_command_not_ok");
		return 1;
	}

	for (intaux=0; intaux<PQntuples(result); intaux++) {

		/* replace all underscores with dots */
		strncpy(buf, PQgetvalue(result, intaux, 0), ULOGD_MAX_KEYLEN);
		while ((underscore = strchr(buf, '_')))
			*underscore = '.';

		DEBUGP("field '%s' found: ", buf);

		if (!(id = keyh_getid(buf))) {
			DEBUGP(" no keyid!\n");
			continue;
		}

		DEBUGP("keyid %u\n", id);

		/* prepend it to the linked list */
		f = (struct _field *) malloc(sizeof *f);
		if (!f) {
			ulogd_log(ULOGD_ERROR, "OOM!\n");
			return 1;
		}
		strncpy(f->name, buf, ULOGD_MAX_KEYLEN);
		f->id = id;
		f->next = fields;
		fields = f;
	}

	PQclear(result);
	return 0;
}

static int exit_nicely(PGconn *conn)
{
	PQfinish(conn);
	return 0;;
}

/* make connection and select database */
static int pgsql_open_db(char *server, int port, char *user, char *pass, 
			 char *db)
{
	int len;
	char *connstr;

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
		return 1;

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
	
	dbh = PQconnectdb(connstr);
	if (PQstatus(dbh)!=CONNECTION_OK) {
		exit_nicely(dbh);
		return 1;
	}

	return 0;
}

static int pgsql_init(void)
{
	/* have the opts parsed */
	config_parse_file("PGSQL", &port_ce);

	if (pgsql_open_db(host_ce.u.string, port_ce.u.value, user_ce.u.string,
			   pass_ce.u.string, db_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "can't establish database connection\n");
		return 1;
	}

	if (pgsql_namespace()) {
		return 1;
		ulogd_log(ULOGD_ERROR, "unable to test for pgsql schemas\n");
	}

	/* read the fieldnames to know which values to insert */
	if (pgsql_get_columns(table_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "unable to get pgsql columns\n");
		return 1;
	}
	pgsql_createstmt();

	return 0;
}

static void pgsql_fini(void)
{
	PQfinish(dbh);
}

static ulog_output_t pgsql_plugin = { 
	.name = "pgsql", 
	.output = &pgsql_output,
	.init = &pgsql_init,
	.fini = &pgsql_fini,
};

void _init(void)
{
	register_output(&pgsql_plugin);
}
