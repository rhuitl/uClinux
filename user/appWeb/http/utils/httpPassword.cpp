///
///	@file 	httpPassword.cpp
/// @brief 	Manage passwords for HTTP authorization.
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
////////////////////////////////// Includes ////////////////////////////////////

#include	"http/shared.h"

////////////////////////////// Forward Declarations ////////////////////////////

static void printUsage(char *programName);
static void	addUser(char *user, char *realm, char *password, bool enabled);
static int	readPassFile(char *passFile);
static int	updatePassFile(char *passFile);
static char	*getPassword(char *passBuf, int passLen);
static char* trimWhiteSpace(char *str);
#if WIN
static char *getpass(char *prompt);
#endif

///////////////////////////////// User Class ///////////////////////////////////

class User : public MprLink {
  private:
	MprStr	name;
	MprStr	realm;
	MprStr	password;
	bool	enabled;
  public:
			User(char *user, char *realm, char *pass, bool enabled) {
				name = mprStrdup(user);
				this->realm = mprStrdup(realm);
				password = mprStrdup(pass);
				this->enabled = enabled;
			};
			~User() {};
	char	*getName() { return name; };
	char	*getRealm() { return realm; };
	char	*getPassword() { return password; };
	bool	getEnabled() { return enabled; };
	void	setPassword(char *pass) { 
				mprFree(password);
				password = mprStrdup(pass); 
			};
};

/////////////////////////////////// Locals /////////////////////////////////////

static MprList 	users;
static char		*programName;

//////////////////////////////////// Code //////////////////////////////////////

int main(int argc, char *argv[])
{
	char	*password, *passFile, *userName;
	char	*encodedPassword, *argp, *realm;
	char	passBuf[MPR_HTTP_MAX_PASS], buf[MPR_HTTP_MAX_PASS * 2];
	int		c, errflg, create, nextArg;
	bool	enable;

	programName = mprGetBaseName(argv[0]);
	userName = 0;
	create = errflg = 0;
	password = 0;
	enable = 1;

#if BLD_FEATURE_LOG
	MprLogService *ls = new MprLogService();
	ls->addListener(new MprLogToFile());
	ls->setLogSpec("stdout:0");
#endif

	MprCmdLine cmdLine(argc, argv, "cdep:");
	while ((c = cmdLine.next(&argp)) != EOF) {
		switch(c) {
		case 'c':
			create++;
			break;

		case 'e':
			enable = 1;
			break;

		case 'd':
			enable = 0;
			break;

		case 'p':
			password = argp;
			break;

		default:
			errflg++;
			break;
		}
	}
	nextArg = cmdLine.firstArg();
	if ((nextArg + 3) > argc) {
		errflg++;
	}

	if (errflg) {
		printUsage(argv[0]);
		exit(2);
	}	

	passFile = argv[nextArg++];
	realm = argv[nextArg++];
	userName = argv[nextArg++];

	if (!create) {
		if (readPassFile(passFile) < 0) {
			exit(2);
		}
		if (access(passFile, R_OK) != 0) {
			mprError(MPR_L, MPR_USER, "Can't find %s\n", passFile);
			exit(3);
		}
		if (access(passFile, W_OK) < 0) {
			mprError(MPR_L, MPR_USER, "Can't write to %s\n", passFile);
			exit(4);
		}
	} else {
		if (access(passFile, R_OK) == 0) {
			mprError(MPR_L, MPR_USER, "Can't create %s, already exists\n", 
				passFile);
			exit(5);
		}
	}

	if (password == 0) {
		password = getPassword(passBuf, sizeof(passBuf));
		if (password == 0) {
			exit(1);
		}
	}

	mprSprintf(buf, sizeof(buf), "%s:%s:%s", userName, realm, password);
	encodedPassword = maMD5(buf);

	addUser(userName, realm, encodedPassword, enable);

	if (updatePassFile(passFile) < 0) {
		exit(6);
	}
	mprFree(encodedPassword);
	
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

static int readPassFile(char *passFile)
{
	FILE	*fp;
	char	buf[MPR_HTTP_MAX_PASS * 2];
	char	*tok, *enabledSpec, *user, *realm, *password;
	bool	enabled;
	int		line;

	fp = fopen(passFile, "r" MPR_TEXT);
	if (fp == 0) {
		mprError(MPR_L, MPR_USER, "Can't open %s\n", passFile);
		return MPR_ERR_CANT_OPEN;
	}
	line = 0;
	while (fgets(buf, sizeof(buf), fp) != 0) {
		line++;
		enabledSpec = mprStrTok(buf, ":", &tok);
		user = mprStrTok(0, ":", &tok);
		realm = mprStrTok(0, ":", &tok);
		password = mprStrTok(0, "\n\r", &tok);
		if (enabledSpec == 0 || user == 0 || realm == 0 || password == 0) {
			mprError(MPR_L, MPR_USER, 
				"Badly formed password on line %d\n", line);
			return MPR_ERR_CANT_OPEN;
		}
		user = trimWhiteSpace(user);
		if (*user == '#' || *user == '\0') {
			continue;
		}
		enabled = (enabledSpec[0] == '1'); 
		
		realm = trimWhiteSpace(realm);
		password = trimWhiteSpace(password);

		users.insert(new User(user, realm, password, enabled));
	}
	fclose(fp);
	return 0;
}
 
////////////////////////////////////////////////////////////////////////////////

static void addUser(char *user, char *realm, char *password, bool enabled)
{
	User	*up;

	up = (User*) users.getFirst();
	while (up) {
		if (strcmp(user, up->getName()) == 0 && 
				strcmp(realm, up->getRealm()) == 0) {
			up->setPassword(password);
			return;
		}
		up = (User*) users.getNext(up);
	}
	users.insert(new User(user, realm, password, enabled));
}

////////////////////////////////////////////////////////////////////////////////

static int updatePassFile(char *passFile)
{
	User	*up;
	char	tempFile[MPR_MAX_FNAME];
	int		fd;

	mprMakeTempFileName(tempFile, sizeof(tempFile), "httpPass", 1);
	fd = open(tempFile, O_CREAT | O_TRUNC | O_WRONLY | O_TEXT, 0664);
	if (fd < 0) {
		mprError(MPR_L, MPR_USER, "Can't open %s\n", tempFile);
		return MPR_ERR_CANT_OPEN;
	}
	up = (User*) users.getFirst();
	while (up) {
		if (mprFprintf(fd, "%d: %s: %s: %s\n", up->getEnabled(), up->getName(), 
				up->getRealm(), up->getPassword()) < 0) {
			mprError(MPR_L, MPR_USER, "Can't write to %s\n", tempFile);
			return MPR_ERR_CANT_WRITE;
		}
		up = (User*) users.getNext(up);
	}
	close(fd);
	unlink(passFile);
	if (rename(tempFile, passFile) < 0) {
		mprError(MPR_L, MPR_USER, "Can't rename %s to %s\n", tempFile, 
			passFile);
		return MPR_ERR_CANT_WRITE;
	}
	return 0;
}
 
////////////////////////////////////////////////////////////////////////////////

static char *getPassword(char *passBuf, int passLen)
{
	char	*password, *confirm;
#if LINUX || WIN || MACOSX || SOLARIS
	password = getpass("New password: ");
	mprStrcpy(passBuf, passLen, password);
	confirm = getpass("Confirm password: ");
	if (strcmp(passBuf, confirm) == 0) {
		return passBuf;
	}
	mprFprintf(MPR_STDERR, "%s: Error: Password not verified\n", programName);
	return 0;
#endif
}

////////////////////////////////////////////////////////////////////////////////
#if WIN

static char *getpass(char *prompt)
{
    static char password[MPR_HTTP_MAX_PASS];
    int		c, i;

    fputs("New password: ", stderr);
	for (i = 0; i < sizeof(password) - 1; i++) {
		c = _getch();
		if (c == '\r' || c == EOF) {
			break;
		}
		if ((c == '\b' || c == 127) && i > 0) {
			password[--i] = '\0';
			fputs("\b \b", stderr);
			i--;
		} else if (c == 26) {			// Control Z
			c = EOF;
			break;
		} else if (c == 3) {			// Control C
			fputs("^C\n", stderr);
			exit(255);
		} else if (!iscntrl(c) && (i < sizeof(password) - 1)) {
			password[i] = c;
			fputc('*', stderr);
		} else {
			fputc('', stderr);
			i--;
		}
    }
	if (c == EOF) {
		return "";
	}
    fputc('\n', stderr);
    password[i] = '\0';
    return password;
}

#endif //WIN
////////////////////////////////////////////////////////////////////////////////
//
//	Display the usage
//

static void printUsage(char *programName)
{
	mprFprintf(MPR_STDERR, 
		"usage: httpPassword [-c] [-p password] passwordFile realm user\n");
	mprFprintf(MPR_STDERR, "Options:\n");
	mprFprintf(MPR_STDERR, "    -c              Create the password file\n");
	mprFprintf(MPR_STDERR, "    -p passWord     Use the specified password\n");
	mprFprintf(MPR_STDERR, "    -e 				Enable (default)\n");
	mprFprintf(MPR_STDERR, "    -d 				Disable\n");
}

////////////////////////////////////////////////////////////////////////////////

static char* trimWhiteSpace(char *str)
{
	int		len;

	if (str == 0) {
		return str;
	}
	while (isspace(*str)) {
		str++;
	}
	len = strlen(str) - 1;
	while (isspace(str[len])) {
		str[len--] = '\0';
	}
	return str;
}

////////////////////////////////////////////////////////////////////////////////

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
