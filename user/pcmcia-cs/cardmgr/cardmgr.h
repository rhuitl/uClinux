/*
 * cardmgr.h 1.36 2001/06/22 04:17:17
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License
 * at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License. 
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU Public License version 2 (the "GPL"), in which
 * case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use
 * your version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the MPL or the GPL.
 */

#define MAX_SOCKS	8
#define MAX_BINDINGS	4
#define MAX_MODULES	4

typedef struct adjust_list_t {
    adjust_t		adj;
    struct adjust_list_t *next;
} adjust_list_t;

typedef struct func_ident_t {
    u_char		funcid;
} func_ident_t;

typedef struct manfid_ident_t {
    u_short		manf;
    u_short		card;
} manfid_ident_t;

typedef struct vers_ident_t {
    int			ns;
    char		*pi[4];
} vers_ident_t;

typedef struct tuple_ident_t {
    cisdata_t		code;
    long		ofs;
    char		*info;
} tuple_ident_t;

typedef struct device_info_t {
    dev_info_t		dev_info;
    int			needs_mtd;
    int			modules;
    char		*module[MAX_MODULES];
    char		*opts[MAX_MODULES];
    char		*class;
    int			refs;
    struct device_info_t *next;
} device_info_t;

#define VERS_1_IDENT	0x0001
#define MANFID_IDENT	0x0002
#define TUPLE_IDENT	0x0010
#define FUNC_IDENT	0x0020
#define BLANK_IDENT	0x0040
#define PCI_IDENT	0x0080
#define EXCL_IDENT	0x00f0

typedef struct card_info_t {
    char		*name;
    int			ident_type;
    union {
	vers_ident_t	vers;
	tuple_ident_t	tuple;
	func_ident_t	func;
    } id;
    manfid_ident_t	manfid;
    int			bindings;
    device_info_t	*device[MAX_BINDINGS];
    int			dev_fn[MAX_BINDINGS];
    char		*cis_file;
    int			refs;
    struct card_info_t	*next;
} card_info_t;

typedef struct mtd_ident_t {
    char		*name;
    enum {
	JEDEC_MTD=1, DTYPE_MTD, DEFAULT_MTD
    } mtd_type;
    int			dtype, jedec_mfr, jedec_info;
    char		*module, *opts;
    int			refs;
    struct mtd_ident_t	*next;
} mtd_ident_t;
    
extern adjust_list_t	*root_adjust;
extern device_info_t	*root_device;
extern card_info_t	*blank_card;
extern card_info_t	*root_card, *root_func;
extern mtd_ident_t	*root_mtd, *default_mtd;

int parse_configfile(char *fn);
