/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  vscan.c -- Called from localcache.c if virus scanning is enabled. We
  have two phases of operation: INCOMING and OUTGOING.

  When RETR is received it is forwarded to the server and we enter
  INCOMING mode. All incoming data is written to a temporary file, and
  the buffer length zeroed so it doesn't get written to either cache
  or client. The server's 150 reply is intercepted, and a multiline
  150 reply started instead - a line at a time every few seconds to
  prevent timeouts.

  On data connection close during INCOMING we scan the temporary file. 
  If infected we send an error and return -1. If clean we switch to
  OUTGOING mode, and reopen the file for reading. This fd is returned
  and will become the new server_data fd.

  During the OUTGOING phase we do nothing. The data read from our
  temporary file will be sent to both client and cache file. On close
  we delete the temporary file.

problems:
  o Uploads not scanned
  o Sensitive to order of calls in l_retr_end and l_inc_data.
  o The file is written to disk on two occasions.

TODO Modify localcache.c to delete cache file header on failed scan.
  ***************************************/
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "common.h"
#include "control.h"
#include "cache.h"
#include "vscan.h"

char ext_info[6][BUF_LEN];
static char *argv[26]; // 20 + # ext vars from ext_info

static enum { NONE, INCOMING, OUTGOING } status = NONE;
static enum { STARTING, FINISHED, NOTHING } expected_reply = NOTHING;
static int size;
static int tsize;
static int fd = -1;
static char scanfile[BUF_LEN];
static time_t lastprog;

int vscan_scan(void);

/*This function run as root to allow making tmp dir*/
int vscan_init(void)
{
	int i;
	char *p = config.vscanner;

	if(!config.vscanner)
		return 0;

	for(i = 0; i < 25; i++) {
		while(*p != 0 && *p++ != '"');
		if(*p == 0)
			break;
		argv[i] = p;
		while(*p != 0 && *p != '"')
			p++;
		if(*p == 0)
			break;
		*p++ = 0;
		argv[i] = (!strcmp(argv[i], "%f"))? ext_info[0]:
		          (!strcmp(argv[i], "%r"))? ext_info[1]:
		          (!strcmp(argv[i], "%o"))? ext_info[2]:
		          (!strcmp(argv[i], "%x"))? ext_info[3]:
		          (!strcmp(argv[i], "%a"))? ext_info[4]:
		          (!strcmp(argv[i], "%v"))? ext_info[5]:
		          (!strcmp(argv[i], "%s"))? scanfile:argv[i];
	}
	argv[i] = NULL;

	if(make_tmpdir() == -1)
		return (-1);

	snprintf(scanfile, BUF_LEN, "%s/tmp/VS_%d", config.chroot, getpid());
	write_log(VERBOSE, "VS: Virus scanner temp file is %s", scanfile);
	return 0;
}

void vscan_new(int sz)
{
	if(!config.vscanner)
		return;
	fd = creat(scanfile, S_IRUSR | S_IWUSR);
	status = INCOMING;
	expected_reply = STARTING;
	time(&lastprog);
	size = sz;
	tsize = 0;
	write_log(VERBOSE, "VS: Downloading to temporary file");
}

void vscan_inc(sstr * inc)
{
	time_t tmp;

	if(!config.vscanner)
		return;
	if(status == INCOMING) {
		tsize += sstr_len(inc);
		sstr_write(fd, inc, 0);
		sstr_empty(inc);
		time(&tmp);
		if(config.vscanpm && tmp - lastprog > config.vscanpm &&
		   expected_reply != STARTING) {
			sstr *msg;
			msg = sstr_init(500);
			if(size)
				sstr_apprintf(msg,
					      "150-Downloaded %d/%d bytes to proxy",
					      tsize, size);
			else
				sstr_apprintf(msg,
					      "150-Downloaded %d bytes to proxy",
					      tsize);
			send_message(0, msg);
			sstr_free(msg);
			lastprog = tmp;
		}
	}
}

int vscan_switchover(void)
{
	int tmp;

	if(status != INCOMING)
		return FALSE;

	rclose(&fd);

	status = OUTGOING;
	if(!vscan_scan()) {
		write_log(VERBOSE, "VS: Scan failed");
		if(config.vscanpm)
			send_cmessage(150, "Not starting Transfer");
		send_cmessage(451, "File contains virus. Aborting");
		unlink(scanfile);
		status = NONE;
		info->virus = TRUE;
		return FALSE;
	}
	info->virus = FALSE;
	write_log(VERBOSE, "VS: Scan complete. Changing fd");
	send_cmessage(150, "Starting Transfer");
	tmp = open(scanfile, O_RDONLY);
	unlink(scanfile);
	if(dup2(tmp, info->server_data.fd) == -1) {
		debug_perr("dup2");
		die(ERROR, "Error changing file descriptors in vscan", 0, 0,
		    -1);
	}
	close(tmp);
	return TRUE;
}

int vscan_end(void)
{
	if(status == INCOMING)
		die(ERROR, "In vscan_end() and shouldn't be", 0, 0, -1);
	if(status == OUTGOING) {
		status = NONE;
		write_log(VERBOSE, "VS: Finished forwarding scanned file");
		send_cmessage(226, "Transfer Complete");
		return (VSCAN_OK);
	}
	return (VSCAN_OK);
}

void vscan_abort(void)
{
	if(status == INCOMING)
		unlink(scanfile);
	status = NONE;
}

int vscan_parsed_reply(int code, sstr * msg)
{
	switch (expected_reply) {
	case NOTHING:
		return (FALSE);
	case STARTING:
		if(code <= 0)
			return (TRUE);
		if(code > 299) {	/*Failure */
			expected_reply = NOTHING;
			status = NONE;
			close(fd);
			unlink(scanfile);
			return (FALSE);
		}
		if(config.vscanpm) {
			send_cmessage(-150, "Starting Transfer");
			send_cmessage(0, "150-There'll be a delay while we "
				      "scan for viruses");
		}
		expected_reply = FINISHED;
		return (TRUE);
	case FINISHED:
		if(code <= 0)
			return (TRUE);
		expected_reply = NOTHING;
		if(code > 299) {	/*Failure */
			status = NONE;
			close(fd);
			if(config.vscanpm)
				send_cmessage(150, "Error. Aborting.");
			return (FALSE);
		}
		return (TRUE);
	}

	if(status == INCOMING)
		return (TRUE);
	return (FALSE);
}

int vscan_scan(void)
{
	int i;
	int fd, fdlimit;

	write_log(VERBOSE, "VS: Now scanning file");
	if(config.vscanpm)
		send_cmessage(0, "150-Scanning file for viruses");

	switch (fork()) {
	case 0:		/*Child */
		fdlimit = sysconf(_SC_OPEN_MAX);
		for(fd = 0; fd < fdlimit; fd++)
			close(fd);
		open("/dev/null", O_RDWR);
		dup(0);
		dup(0);

		strncpy(ext_info[0], inet_ntoa(info->client_control.address.sin_addr),
				BUF_LEN);
		strncpy(ext_info[1], info->upload?"up":"down",    BUF_LEN);
		strncpy(ext_info[2], sstr_buf(info->username),    BUF_LEN);
		strncpy(ext_info[3], sstr_buf(info->server_name), BUF_LEN);
		strncpy(ext_info[4], sstr_buf(info->strictpath),  BUF_LEN);
		strncpy(ext_info[5], sstr_buf(info->filename),    BUF_LEN);
		execvp(argv[0], argv);
		die(ERROR, "Failed to exec virus scanner", 0, 0, -1);
	case -1:
		die(ERROR, "Error forking for virus scanner", 0, 0, -1);
		break;
	 /*FIXME*/ default:
		break;
	}
	wait(&i);
	if(!WIFEXITED(i))
		return (FALSE);

	return (WEXITSTATUS(i) == config.vscanok);
}
