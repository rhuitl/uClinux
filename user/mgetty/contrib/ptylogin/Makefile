# /* Makefile -- ptylogin makefile
#  * Marc SCHAEFER <schaefer@alphanet.ch>
#  * Creation: 10/01/98
#  * Update:   10/01/98
#  * V1.0 PV001
#  * DESCRIPTION
#  *    This makes ptylogin.
#  * NOTES
#  * BUGS
#  * TODO
#  * COPYING-POLICY
#  *    (C) Marc SCHAEFER, under the GPL
#  * BASED-ON
#  *    Original code.
#  * MODIFICATION-HISTORY
#  *    10/01/99  schaefer  Created this file.
#  * $Id: Makefile,v 1.1 1999/01/16 17:17:05 gert Exp $
#  */

CFLAGS=-Wall
LDFLAGS=
LIBS=-lbsd
CC=gcc

SOURCE=ptylogin.c
EXECUTABLE=ptylogin

all: $(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE)

$(EXECUTABLE): $(SOURCE)
	$(CC) $(SOURCE) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $(EXECUTABLE)