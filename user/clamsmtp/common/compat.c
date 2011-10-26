/*
 * Copyright (c) 2004-2005, Nate Nielsen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 
 *     * Redistributions of source code must retain the above 
 *       copyright notice, this list of conditions and the 
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the 
 *       above copyright notice, this list of conditions and 
 *       the following disclaimer in the documentation and/or 
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be 
 *       used to endorse or promote products derived from this 
 *       software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
 * DAMAGE.
 * 
 *
 * CONTRIBUTORS
 *  Nate Nielsen <nielsen@memberwebs.com>
 *
 * 
 * PORTIONS FROM OPENBSD: -------------------------------------------------
 *
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */ 



#include "usuals.h"
#include "compat.h"

#include <ctype.h>
#include <stdlib.h>

#ifndef HAVE_REALLOCF

void* reallocf(void* ptr, size_t size)
{
	void* ret = realloc(ptr, size);

	if(!ret && size)
		free(ptr);

	return ret;
}

#endif

#ifndef HAVE_STRLWR
char* strlwr(char* s)
{
    char* t = s;
    while(*t)
    {
        *t = tolower(*t);
        t++;
    }
    return s;
}
#endif 

#ifndef HAVE_STRUPR
char* strupr(char* s)
{
    char* t = s;
    while(*t)
    {
        *t = toupper(*t);
        t++;
    }
    return s;
}
#endif 

#ifndef HAVE_STRLCPY

size_t strlcpy(char* dst, const char* src, size_t siz)
{
	char* d = dst;
    const char* s = src;
    size_t n = siz;

    /* Copy as many bytes as will fit */
    if(n != 0 && --n != 0) 
	{
       	do 
		{
           	if((*d++ = *s++) == 0)
               	break;
        } 
		while(--n != 0);
    }
                                                                                
    /* Not enough room in dst, add NUL and traverse rest of src */
    if(n == 0) 
	{
      	if(siz != 0)
           	*d = '\0';              /* NUL-terminate dst */
        while (*s++)
         	;
    }
                                                                                
    return s - src - 1;    /* count does not include NUL */
}

#endif
                                                                                
#ifndef HAVE_STRLCAT
                                                                                
size_t strlcat(char* dst, const char* src, size_t siz)
{
    char* d = dst;
    const char* s = src;
    size_t n = siz;
    size_t dlen;
                                                                                
    /* Find the end of dst and adjust bytes left but don't go past end */
    while(n-- != 0 && *d != '\0')
     	d++;
    dlen = d - dst;
    n = siz - dlen;
                                                                                
    if(n == 0)
        return dlen + strlen(s);
    while(*s != '\0') 
    {
        if(n != 1) 
        {
            *d++ = *s;
            n--; 
        }
        
        s++;
    }

    *d = '\0';
                                                                                
    return dlen + (s - src);       /* count does not include NUL */
}

#endif

#ifndef HAVE_SETENV

#include <stdio.h>

int setenv(const char* name, const char* value, int overwrite)
{
	char* t;
	int r;
	if(getenv(name) && !overwrite)
		return 0;
	t = (char*)malloc((strlen(name) + strlen(value) + 2) * sizeof(char));
	if(!t) return -1;
	sprintf(t, "%s=%s", name, value);
	r = putenv(t);
	free(t);
	return r;
}

#endif

#ifndef HAVE_DAEMON

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>

int daemon(int nochdir, int noclose)
{
	struct sigaction osa, sa;
	int oerrno, fd, osa_ok;
	pid_t newgrp;

	/* A SIGHUP may be thrown when the parent exits below. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	osa_ok = sigaction(SIGHUP, &sa, &osa);
    
	switch(fork()) 
	{
	case -1:
		return -1;
	case 0:
		break;
	default:
		_exit(0);
	}

	newgrp = setsid();
	oerrno = errno;
	if(osa_ok != -1)
		sigaction(SIGHUP, &osa, NULL);
	if(newgrp == -1) 
	{
		errno = oerrno;
		return -1;
	}
	if(!nochdir)
		chdir("/");
        if(!noclose && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) 
	{
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if(fd > 2)
			close(fd);
        }
        return 0;

}

#endif

#ifndef HAVE_ERR_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

extern char** __argv;

static const char* calc_prog_name()
{
	static char prognamebuf[256];
	static int prepared = 0;

	if(!prepared)
	{
		const char* beg = strrchr(__argv[0], '\\');
		const char* temp = strrchr(__argv[0], '/');
		beg = (beg > temp) ? beg : temp;
		beg = (beg) ? beg + 1 : __argv[0];

		temp = strrchr(__argv[0], '.');
		temp = (temp > beg) ? temp : __argv[0] + strlen(__argv[0]);

		if((temp - beg) > 255)
			temp = beg + 255;

		strncpy(prognamebuf, beg, temp - beg);
		prognamebuf[temp - beg] = 0;
		prepared = 1;
	}

	return prognamebuf;
}

static FILE* err_file; /* file to use for error output */

/*
 * This is declared to take a `void *' so that the caller is not required
 * to include <stdio.h> first.  However, it is really a `FILE *', and the
 * manual page documents it as such.
 */
void err_set_file(void *fp)
{
	if (fp)
		err_file = fp;
	else
		err_file = stderr;
}

void err(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrc(eval, errno, fmt, ap);
	va_end(ap);
}

void verr(int eval, const char *fmt, va_list ap)
{
	verrc(eval, errno, fmt, ap);
}

void errc(int eval, int code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrc(eval, code, fmt, ap);
	va_end(ap);
}

void verrc(int eval, int code, const char *fmt, va_list ap)
{
	if (err_file == 0)
		err_set_file((FILE *)0);
	fprintf(err_file, "%s: ", calc_prog_name());
	if (fmt != NULL) {
		vfprintf(err_file, fmt, ap);
		fprintf(err_file, ": ");
	}
	fprintf(err_file, "%s\n", strerror(code));
	exit(eval);
}

void errx(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrx(eval, fmt, ap);
	va_end(ap);
}

void verrx(int eval, const char *fmt, va_list ap)
{
	if (err_file == 0)
		err_set_file((FILE *)0);
	fprintf(err_file, "%s: ", calc_prog_name());
	if (fmt != NULL)
		vfprintf(err_file, fmt, ap);
	fprintf(err_file, "\n");
	exit(eval);
}

void warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnc(errno, fmt, ap);
	va_end(ap);
}

void vwarn(const char *fmt, va_list ap)
{
	vwarnc(errno, fmt, ap);
}

void warnc(int code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnc(code, fmt, ap);
	va_end(ap);
}

void vwarnc(int code, const char *fmt, va_list ap)
{
	if (err_file == 0)
		err_set_file((FILE *)0);
	fprintf(err_file, "%s: ", calc_prog_name());
	if (fmt != NULL) 
	{
		vfprintf(err_file, fmt, ap);
		fprintf(err_file, ": ");
	}
	fprintf(err_file, "%s\n", strerror(code));
}

void warnx(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}

void vwarnx(const char *fmt, va_list ap)
{
	if(err_file == 0)
		err_set_file((FILE*)0);
	fprintf(err_file, "%s: ", calc_prog_name());
	if(fmt != NULL)
		vfprintf(err_file, fmt, ap);
	fprintf(err_file, "\n");
}

#endif

