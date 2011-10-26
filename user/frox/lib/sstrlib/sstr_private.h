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

  sstr_private.h -- Header file for secure (?) string library internals.

***************************************/

#ifndef SSTR_PRIVATE_H
#define SSTR_PRIVATE_H

struct _sstr {
	char *buf;
	int len;
	int maxlen;
	int growable;
};

int sstr_alloc_space(sstr * p, int len);
extern void (*on_error) (void);

#endif /*SSTR_PRIVATE_H */
