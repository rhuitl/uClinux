/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */
#ifndef __SP_ICMP_TYPE_CHECK_H__
#define __SP_ICMP_TYPE_CHECK_H__

#define ICMP_TYPE_TEST_EQ 1
#define ICMP_TYPE_TEST_GT 2
#define ICMP_TYPE_TEST_LT 3
#define ICMP_TYPE_TEST_RG 4

typedef struct _IcmpTypeCheckData
{
    /* the icmp type number */
    int icmp_type;
    int icmp_type2;
    u_int8_t operator;
} IcmpTypeCheckData;

void SetupIcmpTypeCheck(void);

#endif  /* __SP_ICMP_TYPE_CHECK_H__ */
