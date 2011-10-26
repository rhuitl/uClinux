/* ulogd_MYSQL.c, Version $Revision: 705 $
 *
 * ulogd output plugin for logging to a MySQL database
 *
 * (C) 2000-2001 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 * $Id: ulogd_MYSQL.c 705 2005-02-16 11:25:09Z laforge $
 *
 * 15 May 2001, Alex Janssen <alex@ynfonatic.de>:
 *      Added a compability option for older MySQL-servers, which
 *      don't support mysql_real_escape_string
 *
 * 17 May 2001, Alex Janssen <alex@ynfonatic.de>:
 *      Added the --with-mysql-log-ip-as-string feature. This will log
 *      IP's as string rather than an unsigned long integer to the database.
 *	See ulogd/doc/mysql.table.ipaddr-as-string as an example.
 *	BE WARNED: This has _WAY_ less performance during table searches.
 *
 * 09 Feb 2005, Sven Schuster <schuster.sven@gmx.de>:
 * 	Added the "port" parameter to specify ports different from 3306
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <mysql/mysql.h>

#ifdef DEBUG_MYSQL
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
static MYSQL *dbh;

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
	.options = CONFIG_OPT_MANDATORY,
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
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t table_ce = { 
	.next = &pass_ce, 
	.key = "table", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t port_ce = {
	.next = &table_ce,
	.key = "port",
	.type = CONFIG_TYPE_INT,
};

/* our main output function, called by ulogd */
static int mysql_output(ulog_iret_t *result)
{
	struct _field *f;
	ulog_iret_t *res;
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
				memset(&addr, 0, sizeof(addr));
				addr.s_addr = ntohl(res->value.ui32);
				*stmt_ins++ = '\'';
				tmpstr = inet_ntoa(addr);
#ifdef OLD_MYSQL
				mysql_escape_string(stmt_ins, tmpstr,
						    strlen(tmpstr));
#else
				mysql_real_escape_string(dbh, stmt_ins,
							 tmpstr,
							 strlen(tmpstr));
#endif /* OLD_MYSQL */
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
#ifdef OLD_MYSQL
				mysql_escape_string(stmt_ins, res->value.ptr,
					strlen(res->value.ptr));
#else
				mysql_real_escape_string(dbh, stmt_ins,
					res->value.ptr, strlen(res->value.ptr));
#endif
				stmt_ins = stmt + strlen(stmt);
				sprintf(stmt_ins, "',");
			/* sprintf(stmt_ins, "'%s',", res->value.ptr); */
				break;
			case ULOGD_RET_RAW:
				ulogd_log(ULOGD_NOTICE,
					"%s: type RAW not supported by MySQL\n",
					res->key);
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

	if(mysql_real_query(dbh, stmt, strlen(stmt))) {
		ulogd_log(ULOGD_ERROR, "sql error during insert: %s\n",
				mysql_error(dbh));
		return 1;
	}

	return 0;
}

#define MYSQL_INSERTTEMPL   "insert into X (Y) values (Z)"
#define MYSQL_VALSIZE	100

/* create the static part of our insert statement */
static int mysql_createstmt(void)
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
	size = strlen(MYSQL_INSERTTEMPL) + strlen(table_ce.u.string);

	for (f = fields; f; f = f->next) {
		/* we need space for the key and a comma, as well as
		 * enough space for the values */
		size += strlen(f->name) + 1 + MYSQL_VALSIZE;
	}	

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	stmt = (char *) malloc(size);

	if (!stmt) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return 1;
	}

	sprintf(stmt, "insert into %s (", table_ce.u.string);
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

/* find out which columns the table has */
static int mysql_get_columns(const char *table)
{
	MYSQL_RES *result;
	MYSQL_FIELD *field;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	struct _field *f;
	int id;

	if (!dbh) 
		return 1;

	result = mysql_list_fields(dbh, table, NULL);
	if (!result)
		return 1;

	while ((field = mysql_fetch_field(result))) {

		/* replace all underscores with dots */
		strncpy(buf, field->name, ULOGD_MAX_KEYLEN);
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

	mysql_free_result(result);
	return 0;
}

/* make connection and select database */
static int mysql_open_db(char *server, int port, char *user, char *pass, 
			 char *db)
{
	dbh = mysql_init(NULL);
	if (!dbh)
		return 1;

	if (!mysql_real_connect(dbh, server, user, pass, db, port, NULL, 0))
		return 1;

	return 0;
}

static int _mysql_init(void)
{
	/* have the opts parsed */
	config_parse_file("MYSQL", &port_ce);

	if (mysql_open_db(host_ce.u.string, port_ce.u.value, user_ce.u.string, 
			   pass_ce.u.string, db_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "can't establish database connection\n");
		return -1;
	}

	/* read the fieldnames to know which values to insert */
	if (mysql_get_columns(table_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "unable to get mysql columns\n");
		return -1;
	}
	mysql_createstmt();

	return 0;
}

static void _mysql_fini(void)
{
	mysql_close(dbh);
}

static ulog_output_t mysql_plugin = { 
	.name = "mysql", 
	.output = &mysql_output, 
	.init = &_mysql_init,
	.fini = &_mysql_fini,
};

void _init(void) 
{
	register_output(&mysql_plugin);
}
