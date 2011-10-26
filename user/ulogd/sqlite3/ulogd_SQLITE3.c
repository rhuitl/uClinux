/*
 * ulogd output plugin for logging to a SQLITE database
 *
 * (C) 2005 by Ben La Monica <ben.lamonica@gmail.com>
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
 *  This module has been adapted from the ulogd_MYSQL.c written by
 *  Harald Welte <laforge@gnumonks.org>
 *  Alex Janssen <alex@ynfonatic.de>
 *
 *  You can see benchmarks and an explanation of the testing
 *  at http://www.pojo.us/ulogd/
 *
 *  2005-02-09 Harald Welte <laforge@gnumonks.org>:
 *  	- port to ulogd-1.20 
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <sqlite3.h>

#ifdef DEBUG_SQLITE3
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
static sqlite3 *dbh;

/* a linked list of the fields the table has */
static struct _field *fields;

/* buffer for our insert statement */
static char *stmt;

/* pointer to the final prepared statement */
static sqlite3_stmt *p_stmt;

/* number of statements to buffer before we commit */
static int buffer_size;

/* number of statements currently in the buffer */
static int buffer_ctr;

/* our configuration directives */
static config_entry_t db_ce = { 
	.key = "db", 
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t table_ce = { 
	.next = &db_ce, 
	.key = "table",
	.type = CONFIG_TYPE_STRING,
	.options = CONFIG_OPT_MANDATORY,
};

static config_entry_t buffer_ce = { 
	.next = &table_ce,
	.key = "buffer",
	.type = CONFIG_TYPE_INT,
	.options = CONFIG_OPT_MANDATORY,
};

/* our main output function, called by ulogd */
static int _sqlite3_output(ulog_iret_t *result)
{
	struct _field *f;
	ulog_iret_t *res;
	int col_counter;
#ifdef IP_AS_STRING
	char *ipaddr;
	struct in_addr addr;
#endif

	col_counter = 0;
	for (f = fields; f; f = f->next) {
		res = keyh_getres(f->id);

		if (!res) {
			ulogd_log(ULOGD_NOTICE,
				"no result for %s ?!?\n", f->name);
		}
			
		if (!res || !IS_VALID((*res))) {
			/* no result, pass a null */
			col_counter++;
			continue;
		}
		
		switch (res->type) {
			case ULOGD_RET_INT8:
				sqlite3_bind_int(p_stmt,col_counter,res->value.i8);
				break;
			case ULOGD_RET_INT16:
				sqlite3_bind_int(p_stmt,col_counter,res->value.i16);
				break;
			case ULOGD_RET_INT32:
				sqlite3_bind_int(p_stmt,col_counter,res->value.i32);
				break;
			case ULOGD_RET_INT64:
				sqlite3_bind_int64(p_stmt,col_counter,res->value.i64);
				break;
			case ULOGD_RET_UINT8:
				sqlite3_bind_int(p_stmt,col_counter,res->value.ui8);
				break;
			case ULOGD_RET_UINT16:
				sqlite3_bind_int(p_stmt,col_counter,res->value.ui8);
				break;
			case ULOGD_RET_IPADDR:
#ifdef IP_AS_STRING
				memset(&addr, 0, sizeof(addr));
				addr.s_addr = ntohl(res->value.ui32);
				ipaddr = inet_ntoa(addr);
				sqlite3_bind_text(p_stmt,col_counter,ipaddr,strlen(ipaddr),SQLITE_STATIC);
                                break;
#endif /* IP_AS_STRING */
			/* EVIL: fallthrough when logging IP as u_int32_t */
			case ULOGD_RET_UINT32:
				sqlite3_bind_int(p_stmt,col_counter,res->value.ui32);
				break;
			case ULOGD_RET_UINT64:
				sqlite3_bind_int64(p_stmt,col_counter,res->value.ui64);
				break;
			case ULOGD_RET_BOOL:
				sqlite3_bind_int(p_stmt,col_counter,res->value.b);
				break;
			case ULOGD_RET_STRING:
				sqlite3_bind_text(p_stmt,col_counter,res->value.ptr,strlen(res->value.ptr),SQLITE_STATIC);
				break;
			default:
				ulogd_log(ULOGD_NOTICE,
					"unknown type %d for %s\n",
					res->type, res->key);
				break;
		} 

		col_counter++;
	}

	/* now we have created our statement, insert it */

	if (sqlite3_step(p_stmt) == SQLITE_DONE) {
		sqlite3_reset(p_stmt);
		buffer_ctr++;
	} else {
		ulogd_log(ULOGD_ERROR, "sql error during insert: %s\n",
				sqlite3_errmsg(dbh));
		return 1;
	}

	/* commit all of the inserts to the database, ie flush buffer */
	if (buffer_ctr >= buffer_size) {
		if (sqlite3_exec(dbh,"commit",NULL,NULL,NULL) != SQLITE_OK)
			ulogd_log(ULOGD_ERROR,"unable to commit records to db.");

		if (sqlite3_exec(dbh,"begin deferred",NULL,NULL,NULL) != SQLITE_OK)
			ulogd_log(ULOGD_ERROR,"unable to begin a new transaction.");

		buffer_ctr = 0;
		DEBUGP("committing.\n");
	}

	return 0;
}

#define _SQLITE3_INSERTTEMPL   "insert into X (Y) values (Z)"

/* create the static part of our insert statement */
static int _sqlite3_createstmt(void)
{
	struct _field *f;
	unsigned int size;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	char *stmt_pos;
	int col_count;
	int i;

	if (stmt) {
		ulogd_log(ULOGD_NOTICE, "createstmt called, but stmt"
			" already existing\n");	
		return 1;
	}

	/* caclulate the size for the insert statement */
	size = strlen(_SQLITE3_INSERTTEMPL) + strlen(table_ce.u.string);

	DEBUGP("initial size: %u\n", size);

	col_count = 0;
	for (f = fields; f; f = f->next) {
		/* we need space for the key and a comma, and a ? */
		size += strlen(f->name) + 3;
		DEBUGP("size is now %u since adding %s\n",size,f->name);
		col_count++;
	}

	DEBUGP("there were %d columns\n",col_count);
	DEBUGP("after calc name length: %u\n",size);

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	stmt = (char *) malloc(size);

	if (!stmt) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return 1;
	}

	sprintf(stmt, "insert into %s (", table_ce.u.string);
	stmt_pos = stmt + strlen(stmt);

	for (f = fields; f; f = f->next) {
		strncpy(buf, f->name, ULOGD_MAX_KEYLEN);	
		while ((underscore = strchr(buf, '.')))
			*underscore = '_';
		sprintf(stmt_pos, "%s,", buf);
		stmt_pos = stmt + strlen(stmt);
	}

	*(stmt_pos - 1) = ')';

	sprintf(stmt_pos, " values (");
	stmt_pos = stmt + strlen(stmt);

	for (i = 0; i < col_count - 1; i++) {
		sprintf(stmt_pos,"?,");
		stmt_pos += 2;
	}

	sprintf(stmt_pos, "?)");
	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", stmt);

	DEBUGP("about to prepare statement.\n");

	sqlite3_prepare(dbh,stmt,-1,&p_stmt,0);

	DEBUGP("statement prepared.\n");

	if (!p_stmt) {
		ulogd_log(ULOGD_ERROR,"unable to prepare statement");
		return 1;
	}

	return 0;
}


/* length of "select * from \0" */
#define SQLITE_SELECT_LEN 15

/* find out which columns the table has */
static int _sqlite3_get_columns(const char *table)
{
	char buf[ULOGD_MAX_KEYLEN];
	char query[SQLITE_SELECT_LEN + CONFIG_VAL_STRING_LEN] = "select * from \0";
	char *underscore;
	struct _field *f;
	sqlite3_stmt *schema_stmt;
	int column;
	int result;
	int id;

	if (!dbh)
		return 1;

	strncat(query,table,LINE_LEN);
	
	result = sqlite3_prepare(dbh,query,-1,&schema_stmt,0);
	
	if (result != SQLITE_OK)
		return 1;

	for (column = 0; column < sqlite3_column_count(schema_stmt); column++) {
		/* replace all underscores with dots */
		strncpy(buf, sqlite3_column_name(schema_stmt,column), ULOGD_MAX_KEYLEN);
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

	sqlite3_finalize(schema_stmt);
	return 0;
}

/** 
 * make connection and select database 
 * returns 0 if database failed to open.
 */
static int _sqlite3_open_db(char *db_file)
{
	DEBUGP("opening database.\n");
	return sqlite3_open(db_file,&dbh);
}

/* give us an opportunity to close the database down properly */
static void _sqlite3_fini(void)
{
	DEBUGP("cleaning up db connection\n");

	/* free up our prepared statements so we can close the db */
	if (p_stmt) {
		sqlite3_finalize(p_stmt);
		DEBUGP("prepared statement finalized\n");
	}

	if (dbh) {
		int result;
		/* flush the remaining insert statements to the database. */
		result = sqlite3_exec(dbh,"commit",NULL,NULL,NULL);

		if (result != SQLITE_OK)
			ulogd_log(ULOGD_ERROR,"unable to commit remaining records to db.");

		sqlite3_close(dbh);
		DEBUGP("database file closed\n");
	}
}

#define _SQLITE3_BUSY_TIMEOUT 300

static int _sqlite3_init(void)
{
	/* have the opts parsed */
	config_parse_file("SQLITE3", &buffer_ce);

	if (_sqlite3_open_db(db_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "can't open the database file\n");
		return 1;
	}

	/* set the timeout so that we don't automatically fail
         * if the table is busy. */
	sqlite3_busy_timeout(dbh, _SQLITE3_BUSY_TIMEOUT);

	/* read the fieldnames to know which values to insert */
	if (_sqlite3_get_columns(table_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "unable to get sqlite columns\n");
		return 1;
	}

	/* initialize our buffer size and counter */
	buffer_size = buffer_ce.u.value;
	buffer_ctr = 0;

	DEBUGP("Have a buffer size of : %d\n", buffer_size);

	if (sqlite3_exec(dbh,"begin deferred",NULL,NULL,NULL) != SQLITE_OK)
		ulogd_log(ULOGD_ERROR,"can't create a new transaction\n");

	/* create and prepare the actual insert statement */
	_sqlite3_createstmt();

	return 0;
}

static ulog_output_t _sqlite3_plugin = { 
	.name = "sqlite3", 
	.output = &_sqlite3_output, 
	.init = &_sqlite3_init,
	.fini = &_sqlite3_fini,
};

void _init(void) 
{
	register_output(&_sqlite3_plugin);
}

