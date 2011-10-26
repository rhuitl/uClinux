/* vi: set sw=4 ts=4: */
#include "tinylogin.h"



#if defined TLG_ADDUSER
const char adduser_usage[] = "adduser [OPTIONS] <login name>\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nAdd a user to the system\n\n"
	"Options:\n"
	"\t-h\t\thome directory\n" "\t-s\t\tshell\n" "\t-g\t\tGECOS string\n"
#endif
;
#endif


#if defined TLG_ADDGROUP
const char addgroup_usage[] = "addgroup [OPTIONS] <group name>\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nAdd a group to the system\n\n" "Options:\n" "\t-g\t\tspecify gid\n"
#endif
;
#endif


#if defined TLG_DELUSER
const char deluser_usage[] = "deluser <login name>\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nDelete a user from the system\n"
#endif
;
#endif


#if defined TLG_DELGROUP
const char delgroup_usage[] = "delgroup <group name>\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nDelete a group from the system\n"
#endif
;
#endif


#if defined TLG_LOGIN
const char login_usage[] = "login [OPTION]... [username] [ENV=VAR ...]\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nBegin a new session on the system\n\n"
	"Options:\n"
	"\t-f\t\tDo not authenticate (user already authenticated)\n"
	"\t-h\t\tName of the remote host for this login.\n"
	"\t-p\t\tPreserve environment.\n"
#endif
;
#endif

#if defined TLG_PASSWD
const char passwd_usage[] = 
	"passwd [OPTION] [name]\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nChange a user password. If no name is specified,\n"
	"changes the password for the current user.\n\n"
	"Options:\n"
	"\t-a\t\tDo not authenticate (user already authenticated)\n"

	"\t-a\t\tDefine which algorithm shall be used for the password.\n"
	"\t\t\t(Choices: des"
#ifdef TLG_FEATURE_SHA1_PASSWORDS
	", sha1"
#endif
#ifdef TLG_FEATURE_MD5_PASSWORDS
	", md5"
#endif
	")\n"
	"\t-d\t\tDelete the password for the specified user account.\n"
	"\t-l\t\tLocks (disables) the specified user account.\n"
	"\t-u\t\tUnlocks (re-enables) the specified user account..\n";
#endif
;
#endif


#if defined TLG_SU
const char su_usage[] = "su [OPTION]... [-] [username]\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nChange user id or become root.\n\n"
	"Options:\n" "\t-p\t\tPreserve environment.\n"
#endif
;
#endif


#if defined TLG_SULOGIN
const char sulogin_usage[] = "sulogin [OPTION]... [tty-device]\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nSingle user login\n\n"
	"Options:\n"
	"\t-f\t\tDo not authenticate (user already authenticated)\n"
	"\t-h\t\tName of the remote host for this login.\n"
	"\t-p\t\tPreserve environment.\n"
#endif
;
#endif


#if defined TLG_GETTY
const char getty_usage[] =
	"getty [OPTIONS]... baud_rate,... line [termtype]\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nOpens a tty, prompts for a login name, then invokes /bin/login\n\n"
	"Options:\n"
	"\t-h\t\tEnable hardware (RTS/CTS) flow control.\n"
	"\t-i\t\tDo not display /etc/issue before running login.\n"
	"\t-L\t\tLocal line, so do not do carrier detect.\n"
	"\t-m\t\tGet baud rate from modem's CONNECT status message.\n"
	"\t-w\t\tWait for a CR or LF before sending /etc/issue.\n"
	"\t-l login_app\tInvoke login_app instead of /bin/login.\n"
	"\t-t timeout\tTerminate after timeout if no username is read.\n"

	"\t-I initstring\tSets the init string to send before anything else.\n"
	"\t-H login_host\tLog login_host into the utmp file as the hostname.\n";
#endif
;
#endif


#if defined TLG_VLOCK
const char vlock_usage[] = "vlock [OPTIONS]\n"
#ifndef TLG_FEATURE_TRIVIAL_HELP
	"\nLock a virtual terminal.  A password is required to unlock\n\n"
	"Options:\n" 
	"\t-a\t\tLock all VTs\n"
#endif
;
#endif
