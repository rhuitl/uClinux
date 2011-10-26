/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * from: @(#)cmdtab.c	5.10 (Berkeley) 6/1/90
 */
char cmdtab_rcsid[] = 
  "$Id: cmdtab.c,v 1.1 2000-07-18 01:47:08 gerg Exp $";

#include <string.h>   /* for NULL */
#include "ftp_var.h"
#include "cmds.h"

/*
 * User FTP -- Command Tables.
 */

const char accounthelp[] = "send account command to remote server";
const char appendhelp[] =  "append to a file";
const char asciihelp[] =   "set ascii transfer type";
const char beephelp[] =    "beep when command completed";
const char binaryhelp[] =  "set binary transfer type";
const char casehelp[] =    "toggle mget upper/lower case id mapping";
const char cdhelp[] =      "change remote working directory";
const char cduphelp[] = "change remote working directory to parent directory";
const char chmodhelp[] =   "change file permissions of remote file";
const char connecthelp[] = "connect to remote ftp";
const char crhelp[] =      "toggle carriage return stripping on ascii gets";
const char deletehelp[] =  "delete remote file";
const char debughelp[] =   "toggle/set debugging mode";
const char dirhelp[] =     "list contents of remote directory";
const char disconhelp[] =  "terminate ftp session";
const char domachelp[] =   "execute macro";
const char formhelp[] =	"set file transfer format";
const char globhelp[] =	"toggle metacharacter expansion of local file names";
const char hashhelp[] =	"toggle printing `#' for each buffer transferred";
const char helphelp[] =	"print local help information";
const char idlehelp[] =	"get (set) idle timer on remote side";
const char lcdhelp[] =	"change local working directory";
const char lshelp[] =	"list contents of remote directory";
const char macdefhelp[] =  "define a macro";
const char mdeletehelp[] = "delete multiple files";
const char mdirhelp[] =    "list contents of multiple remote directories";
const char mgethelp[] =    "get multiple files";
const char mkdirhelp[] =   "make directory on the remote machine";
const char mlshelp[] =     "list contents of multiple remote directories";
const char modtimehelp[] = "show last modification time of remote file";
const char modehelp[] =    "set file transfer mode";
const char mputhelp[] =    "send multiple files";
const char newerhelp[] =   "get file if remote file is newer than local file ";
const char nlisthelp[] =   "nlist contents of remote directory";
const char nmaphelp[] =    "set templates for default file name mapping";
const char ntranshelp[] ="set translation table for default file name mapping";
const char passivehelp[] = "enter passive transfer mode";
const char porthelp[] =	   "toggle use of PORT cmd for each data connection";
const char prompthelp[] =  "force interactive prompting on multiple commands";
const char proxyhelp[] =   "issue command on alternate connection";
const char pwdhelp[] =     "print working directory on remote machine";
const char quithelp[] =    "terminate ftp session and exit";
const char quotehelp[] =   "send arbitrary ftp command";
const char receivehelp[] = "receive file";
const char regethelp[] =   "get file restarting at end of local file";
const char remotehelp[] =  "get help from remote server";
const char renamehelp[] =  "rename file";
const char restarthelp[] = "restart file transfer at bytecount";
const char rmdirhelp[] =   "remove directory on the remote machine";
const char rmtstatushelp[]="show status of remote machine";
const char runiquehelp[] = "toggle store unique for local files";
const char resethelp[] =   "clear queued command replies";
const char sendhelp[] =    "send one file";
const char sitehelp[] =    "send site specific command to remote server\n"
	    "\t\tTry \"rhelp site\" or \"site help\" for more information";
const char shellhelp[] =   "escape to the shell";
const char sizecmdhelp[] = "show size of remote file";
const char statushelp[] =  "show current status";
const char structhelp[] =  "set file transfer structure";
const char suniquehelp[] = "toggle store unique on remote machine";
const char systemhelp[] =  "show remote system type";
const char tenexhelp[] =   "set tenex file transfer type";
const char tickhelp[] =    "toggle printing byte counter during transfers";
const char tracehelp[] =   "toggle packet tracing";
const char typehelp[] =    "set file transfer type";
const char umaskhelp[] =   "get (set) umask on remote side";
const char userhelp[] =    "send new user information";
const char verbosehelp[] = "toggle verbose mode";

struct cmd cmdtab[] = {
	{ "!",		shellhelp,	0, 0, 0, NULL, NULL, shell },
	{ "$",		domachelp,	1, 0, 0, domacro, NULL, NULL },
	{ "account",	accounthelp,	0, 1, 1, account, NULL, NULL },
	{ "append",	appendhelp,	1, 1, 1, put, NULL, NULL },
	{ "ascii",	asciihelp,	0, 1, 1, NULL, setascii, NULL },
	{ "bell",	beephelp,	0, 0, 0, NULL, setbell, NULL },
	{ "binary",	binaryhelp,	0, 1, 1, NULL, setbinary, NULL },
	{ "bye",	quithelp,	0, 0, 0, NULL, quit, NULL },
	{ "case",	casehelp,	0, 0, 1, NULL, setcase, NULL },
	{ "cd",		cdhelp,		0, 1, 1, cd, NULL, NULL },
	{ "cdup",	cduphelp,	0, 1, 1, NULL, cdup, NULL },
	{ "chmod",	chmodhelp,	0, 1, 1, do_chmod, NULL, NULL },
	{ "close",	disconhelp,	0, 1, 1, NULL, disconnect, NULL },
	{ "cr",		crhelp,		0, 0, 0, NULL, setcr, NULL },
	{ "delete",	deletehelp,	0, 1, 1, delete_cmd, NULL, NULL },
	{ "debug",	debughelp,	0, 0, 0, setdebug, NULL, NULL },
	{ "dir",	dirhelp,	1, 1, 1, ls, NULL, NULL },
	{ "disconnect",	disconhelp,	0, 1, 1, NULL, disconnect, NULL },
	{ "exit",	quithelp,	0, 0, 0, NULL, quit, NULL },
	{ "form",	formhelp,	0, 1, 1, NULL, setform, NULL },
	{ "get",	receivehelp,	1, 1, 1, get, NULL, NULL },
	{ "glob",	globhelp,	0, 0, 0, NULL, setglob, NULL },
	{ "hash",	hashhelp,	0, 0, 0, NULL, sethash, NULL },
	{ "help",	helphelp,	0, 0, 1, help, NULL, NULL },
	{ "idle",	idlehelp,	0, 1, 1, idle_cmd, NULL, NULL },
	{ "image",	binaryhelp,	0, 1, 1, NULL, setbinary, NULL },
	{ "lcd",	lcdhelp,	0, 0, 0, lcd, NULL, NULL },
	{ "ls",		lshelp,		1, 1, 1, ls, NULL, NULL },
	{ "macdef",	macdefhelp,	0, 0, 0, macdef, NULL, NULL },
	{ "mdelete",	mdeletehelp,	1, 1, 1, mdelete, NULL, NULL },
	{ "mdir",	mdirhelp,	1, 1, 1, mls, NULL, NULL },
	{ "mget",	mgethelp,	1, 1, 1, mget, NULL, NULL },
	{ "mkdir",	mkdirhelp,	0, 1, 1, makedir, NULL, NULL },
	{ "mls",	mlshelp,	1, 1, 1, mls, NULL, NULL },
	{ "mode",	modehelp,	0, 1, 1, NULL, setmode, NULL },
	{ "modtime",	modtimehelp,	0, 1, 1, modtime, NULL, NULL },
	{ "mput",	mputhelp,	1, 1, 1, mput, NULL, NULL },
	{ "newer",	newerhelp,	1, 1, 1, newer, NULL, NULL },
	{ "nmap",	nmaphelp,	0, 0, 1, setnmap, NULL, NULL },
	{ "nlist",	nlisthelp,	1, 1, 1, ls, NULL, NULL },
	{ "ntrans",	ntranshelp,	0, 0, 1, setntrans, NULL, NULL },
	{ "open",	connecthelp,	0, 0, 1, setpeer, NULL, NULL },
	{ "prompt",	prompthelp,	0, 0, 0, NULL, setprompt, NULL },
        { "passive",    passivehelp,    0, 0, 0, NULL, setpassive, NULL },
	{ "proxy",	proxyhelp,	0, 0, 1, doproxy, NULL, NULL },
	{ "sendport",	porthelp,	0, 0, 0, NULL, setport, NULL },
	{ "put",	sendhelp,	1, 1, 1, put, NULL, NULL },
	{ "pwd",	pwdhelp,	0, 1, 1, NULL, pwd, NULL },
	{ "quit",	quithelp,	0, 0, 0, NULL, quit, NULL },
	{ "quote",	quotehelp,	1, 1, 1, quote, NULL, NULL },
	{ "recv",	receivehelp,	1, 1, 1, get, NULL, NULL },
	{ "reget",	regethelp,	1, 1, 1, reget, NULL, NULL },
	{ "rstatus",	rmtstatushelp,	0, 1, 1, rmtstatus, NULL, NULL },
	{ "rhelp",	remotehelp,	0, 1, 1, rmthelp, NULL, NULL },
	{ "rename",	renamehelp,	0, 1, 1, renamefile, NULL, NULL },
	{ "reset",	resethelp,	0, 1, 1, NULL, reset, NULL },
	{ "restart",	restarthelp,	1, 1, 1, restart, NULL, NULL },
	{ "rmdir",	rmdirhelp,	0, 1, 1, removedir, NULL, NULL },
	{ "runique",	runiquehelp,	0, 0, 1, NULL, setrunique, NULL },
	{ "send",	sendhelp,	1, 1, 1, put, NULL, NULL },
	{ "site",	sitehelp,	0, 1, 1, site, NULL, NULL },
	{ "size",	sizecmdhelp,	1, 1, 1, sizecmd, NULL, NULL },
	{ "status",	statushelp,	0, 0, 1, NULL, status, NULL },
	{ "struct",	structhelp,	0, 1, 1, NULL, setstruct, NULL },
	{ "system",	systemhelp,	0, 1, 1, NULL, syst, NULL },
	{ "sunique",	suniquehelp,	0, 0, 1, NULL, setsunique, NULL },
	{ "tenex",	tenexhelp,	0, 1, 1, NULL, settenex, NULL },
	{ "tick",	tickhelp,	0, 0, 0, NULL, settick, NULL },
	{ "trace",	tracehelp,	0, 0, 0, NULL, settrace, NULL },
	{ "type",	typehelp,	0, 1, 1, settype, NULL, NULL },
	{ "user",	userhelp,	0, 1, 1, user, NULL, NULL },
	{ "umask",	umaskhelp,	0, 1, 1, do_umask, NULL, NULL },
	{ "verbose",	verbosehelp,	0, 0, 0, NULL, setverbose, NULL },
	{ "?",		helphelp,	0, 0, 1, help, NULL, NULL },
	{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

int	NCMDS = (sizeof (cmdtab) / sizeof (cmdtab[0])) - 1;
