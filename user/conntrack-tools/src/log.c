/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: Logging support for the conntrack daemon
 */

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

FILE *init_log(char *filename)
{
	FILE *fd;

	fd = fopen(filename, "a+");
	if (fd == NULL) {
		fprintf(stderr, "can't open log file `%s'\n", filename);
		return NULL;
	}

	return fd;
}

void dlog(FILE *fd, char *format, ...)
{
	time_t t = time(NULL);
	char *buf = ctime(&t);
	va_list args;

	buf[strlen(buf)-1]='\0';
	va_start(args, format);
	fprintf(fd, "[%s] (pid=%d) ", buf, getpid());
	vfprintf(fd, format, args);
	va_end(args);
	fprintf(fd, "\n");
	fflush(fd);
}

void close_log(FILE *fd)
{
	fclose(fd);
}
