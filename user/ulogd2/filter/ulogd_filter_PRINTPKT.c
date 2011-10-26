/* ulogd_filter_PRINTPKT.c, Version $Revision: 1.1 $
 *
 * This target produces entries identical to the LOG target.
 *
 * (C) 2006 by Philip Craig <philipc@snapgear.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/printpkt.h>

static struct ulogd_key printpkt_outp[] = {
	{ 
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "print", 
	},
};

static int printpkt_interp(struct ulogd_pluginstance *upi)
{
	struct ulogd_key *inp = upi->input.keys;
	struct ulogd_key *ret = upi->output.keys;
	static char buf[4096];
	
	printpkt_print(inp, buf);
	ret[0].u.value.ptr = buf;
	if (!ret[0].u.value.ptr) {
		ulogd_log(ULOGD_ERROR, "OOM (size=%u)\n", strlen(buf)+1);
		return 0;
	}

	ret[0].flags |= ULOGD_RETF_VALID;
	return 0;
}
		
static struct ulogd_plugin printpkt_plugin = {
	.name = "PRINTPKT",
	.input = {
		.keys = printpkt_keys,
		.num_keys = ARRAY_SIZE(printpkt_keys),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.keys = printpkt_outp,
		.num_keys = ARRAY_SIZE(printpkt_outp),
		.type = ULOGD_DTYPE_PACKET,
	},
	.interp = &printpkt_interp,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&printpkt_plugin);
}
