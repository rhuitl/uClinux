/* db.c, Version $Revision: 6304 $
 *
 * ulogd helper functions for Database / SQL output plugins
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  Portions (C) 2001 Alex Janssen <alex@ynfonatic.de>,
 *           (C) 2005 Sven Schuster <schuster.sven@gmx.de>,
 *           (C) 2005 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
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
 * $Id: ulogd_output_MYSQL.c 6304 2005-12-08 09:43:19Z /C=DE/ST=Berlin/L=Berlin/O=Netfilter Project/OU=Development/CN=laforge/emailAddress=laforge@netfilter.org $
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include <ulogd/ulogd.h>
#include <ulogd/db.h>

/* generic db layer */

static int __interp_db(struct ulogd_pluginstance *upi);

/* this is a wrapper that just calls the current real
 * interp function */
int ulogd_db_interp(struct ulogd_pluginstance *upi)
{
	struct db_instance *dbi = (struct db_instance *) &upi->private;
	return dbi->interp(upi);
}

/* no connection, plugin disabled */
static int disabled_interp_db(struct ulogd_pluginstance *upi)
{
	return 0;
}

#define SQL_INSERTTEMPL   "insert into X (Y) values (Z)"
#define SQL_VALSIZE	100

/* create the static part of our insert statement */
static int sql_createstmt(struct ulogd_pluginstance *upi)
{
	struct db_instance *mi = (struct db_instance *) upi->private;
	unsigned int size;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	int i;
	char *table = table_ce(upi->config_kset).u.string;

	if (mi->stmt)
		free(mi->stmt);

	/* caclulate the size for the insert statement */
	size = strlen(SQL_INSERTTEMPL) + strlen(table);

	for (i = 0; i < upi->input.num_keys; i++) {
		if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
			continue;
		/* we need space for the key and a comma, as well as
		 * enough space for the values */
		size += strlen(upi->input.keys[i].name) + 1 + SQL_VALSIZE;
	}	

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	mi->stmt = (char *) malloc(size);
	if (!mi->stmt) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return -ENOMEM;
	}

	if (mi->schema)
		sprintf(mi->stmt, "insert into %s.%s (", mi->schema, table);
	else
		sprintf(mi->stmt, "insert into %s (", table);
	mi->stmt_val = mi->stmt + strlen(mi->stmt);

	for (i = 0; i < upi->input.num_keys; i++) {
		if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
			continue;

		strncpy(buf, upi->input.keys[i].name, ULOGD_MAX_KEYLEN);	
		while ((underscore = strchr(buf, '.')))
			*underscore = '_';
		sprintf(mi->stmt_val, "%s,", buf);
		mi->stmt_val = mi->stmt + strlen(mi->stmt);
	}
	*(mi->stmt_val - 1) = ')';

	sprintf(mi->stmt_val, " values (");
	mi->stmt_val = mi->stmt + strlen(mi->stmt);

	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", mi->stmt);

	return 0;
}

int ulogd_db_configure(struct ulogd_pluginstance *upi,
			struct ulogd_pluginstance_stack *stack)
{
	struct db_instance *di = (struct db_instance *) upi->private;
	int ret;

	ulogd_log(ULOGD_NOTICE, "(re)configuring\n");

	/* First: Parse configuration file section for this instance */
	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "error parsing config file\n");
		return ret;
	}

	/* Second: Open Database */
	ret = di->driver->open_db(upi);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "error in open_db\n");
		return ret;
	}

	/* Third: Determine required input keys for given table */
	ret = di->driver->get_columns(upi);
	if (ret < 0)
		ulogd_log(ULOGD_ERROR, "error in get_columns\n");
	
	/* Close database, since ulogd core could just call configure
	 * but abort during input key resolving routines.  configure
	 * doesn't have a destructor... */
	di->driver->close_db(upi);
	
	return ret;
}

int ulogd_db_start(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;
	int ret;

	ulogd_log(ULOGD_NOTICE, "starting\n");

	ret = di->driver->open_db(upi);
	if (ret < 0)
		return ret;

	ret = sql_createstmt(upi);
	if (ret < 0)
		di->driver->close_db(upi);

	return ret;
}

int ulogd_db_stop(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;
	ulogd_log(ULOGD_NOTICE, "stopping\n");
	di->driver->close_db(upi);

	/* try to free our dynamically allocated input key array */
	if (upi->input.keys) {
		free(upi->input.keys);
		upi->input.keys = NULL;
	}
	return 0;
}

static int _init_db(struct ulogd_pluginstance *upi);

static int _init_reconnect(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;

	if (reconnect_ce(upi->config_kset).u.value) {
		di->reconnect = time(NULL);
		if (di->reconnect != TIME_ERR) {
			ulogd_log(ULOGD_ERROR, "no connection to database, "
				  "attempting to reconnect after %u seconds\n",
				  reconnect_ce(upi->config_kset).u.value);
			di->reconnect += reconnect_ce(upi->config_kset).u.value;
			di->interp = &_init_db;
			return -1;
		}
	}

	/* Disable plugin permanently */
	ulogd_log(ULOGD_ERROR, "permanently disabling plugin\n");
	di->interp = &disabled_interp_db;
	
	return 0;
}

static int _init_db(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;

	if (di->reconnect && di->reconnect > time(NULL))
		return 0;
	
	if (di->driver->open_db(upi)) {
		ulogd_log(ULOGD_ERROR, "can't establish database connection\n");
		return _init_reconnect(upi);
	}

	/* enable 'real' logging */
	di->interp = &__interp_db;

	di->reconnect = 0;

	/* call the interpreter function to actually write the
	 * log line that we wanted to write */
	return __interp_db(upi);
}


/* our main output function, called by ulogd */
static int __interp_db(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) &upi->private;
	int i;

	di->stmt_ins = di->stmt_val;

	for (i = 0; i < upi->input.num_keys; i++) { 
		struct ulogd_key *res = upi->input.keys[i].u.source;

		if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
			continue;

		if (!res)
			ulogd_log(ULOGD_NOTICE, "no source for `%s' ?!?\n",
				  upi->input.keys[i].name);
			
		if (!res || !IS_VALID(*res)) {
			/* no result, we have to fake something */
			di->stmt_ins += sprintf(di->stmt_ins, "NULL,");
			continue;
		}
		
		switch (res->type) {
			char *tmpstr;
			struct in_addr addr;
		case ULOGD_RET_INT8:
			sprintf(di->stmt_ins, "%d,", res->u.value.i8);
			break;
		case ULOGD_RET_INT16:
			sprintf(di->stmt_ins, "%d,", res->u.value.i16);
			break;
		case ULOGD_RET_INT32:
			sprintf(di->stmt_ins, "%d,", res->u.value.i32);
			break;
		case ULOGD_RET_INT64:
			sprintf(di->stmt_ins, "%lld,", res->u.value.i64);
			break;
		case ULOGD_RET_UINT8:
			sprintf(di->stmt_ins, "%u,", res->u.value.ui8);
			break;
		case ULOGD_RET_UINT16:
			sprintf(di->stmt_ins, "%u,", res->u.value.ui16);
			break;
		case ULOGD_RET_IPADDR:
			if (asstring_ce(upi->config_kset).u.value) {
				memset(&addr, 0, sizeof(addr));
				addr.s_addr = ntohl(res->u.value.ui32);
				*(di->stmt_ins++) = '\'';
				tmpstr = inet_ntoa(addr);
				di->driver->escape_string(upi, di->stmt_ins,
							  tmpstr, strlen(tmpstr));
                                di->stmt_ins = di->stmt + strlen(di->stmt);
				sprintf(di->stmt_ins, "',");
				break;
			}
			/* fallthrough when logging IP as u_int32_t */
		case ULOGD_RET_UINT32:
			sprintf(di->stmt_ins, "%u,", res->u.value.ui32);
			break;
		case ULOGD_RET_UINT64:
			sprintf(di->stmt_ins, "%llu,", res->u.value.ui64);
			break;
		case ULOGD_RET_BOOL:
			sprintf(di->stmt_ins, "'%d',", res->u.value.b);
			break;
		case ULOGD_RET_STRING:
			*(di->stmt_ins++) = '\'';
			if (res->u.value.ptr) {
				di->stmt_ins += 
				di->driver->escape_string(upi, di->stmt_ins, 
							  res->u.value.ptr,
							strlen(res->u.value.ptr));
			}
			sprintf(di->stmt_ins, "',");
			break;
		case ULOGD_RET_RAW:
			ulogd_log(ULOGD_NOTICE,
				"%s: type RAW not supported by MySQL\n",
				upi->input.keys[i].name);
			break;
		default:
			ulogd_log(ULOGD_NOTICE,
				"unknown type %d for %s\n",
				res->type, upi->input.keys[i].name);
			break;
		}
		di->stmt_ins = di->stmt + strlen(di->stmt);
	}
	*(di->stmt_ins - 1) = ')';

	/* now we have created our statement, insert it */

	if (di->driver->execute(upi, di->stmt, strlen(di->stmt)) < 0)
		return _init_db(upi);

	return 0;
}

void ulogd_db_signal(struct ulogd_pluginstance *upi, int signal)
{
	switch (signal) {
	case SIGHUP:
		/* reopen database connection */
		ulogd_db_stop(upi);
		ulogd_db_start(upi);
		break;
	default:
		break;
	}
}
