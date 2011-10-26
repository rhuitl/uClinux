# This script was automatically generated from the dsa-548
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered a heap overflow error in imlib, an imaging
library for X and X11, that could be abused by an attacker to execute
arbitrary code on the victim\'s machine.  The updated packages we have
provided in DSA 548-1 did not seem to be sufficient, which should be
fixed by this update.
For the old stable distribution (woody) this problem has been fixed in
version 1.9.14-2woody3.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.14-16.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.9.14-17 of imlib and in version 1.9.14-16.2 of imlib+png2.
We recommend that you upgrade your imlib1 packages.


Solution : http://www.debian.org/security/2004/dsa-548
Risk factor : High';

if (description) {
 script_id(15385);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "548");
 script_cve_id("CVE-2004-0817");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA548] DSA-548-2 imlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-548-2 imlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gdk-imlib-dev', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-imlib-dev is vulnerable in Debian 3.0.\nUpgrade to gdk-imlib-dev_1.9.14-2woody3\n');
}
if (deb_check(prefix: 'gdk-imlib1', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-imlib1 is vulnerable in Debian 3.0.\nUpgrade to gdk-imlib1_1.9.14-2woody3\n');
}
if (deb_check(prefix: 'imlib-base', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib-base is vulnerable in Debian 3.0.\nUpgrade to imlib-base_1.9.14-2woody3\n');
}
if (deb_check(prefix: 'imlib-dev', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib-dev is vulnerable in Debian 3.0.\nUpgrade to imlib-dev_1.9.14-2woody3\n');
}
if (deb_check(prefix: 'imlib-progs', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib-progs is vulnerable in Debian 3.0.\nUpgrade to imlib-progs_1.9.14-2woody3\n');
}
if (deb_check(prefix: 'imlib1', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib1 is vulnerable in Debian 3.0.\nUpgrade to imlib1_1.9.14-2woody3\n');
}
if (deb_check(prefix: 'imlib', release: '3.1', reference: '1.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib is vulnerable in Debian 3.1.\nUpgrade to imlib_1.9\n');
}
if (deb_check(prefix: 'imlib', release: '3.1', reference: '1.9.14-16.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib is vulnerable in Debian sarge.\nUpgrade to imlib_1.9.14-16.2\n');
}
if (deb_check(prefix: 'imlib', release: '3.0', reference: '1.9.14-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib is vulnerable in Debian woody.\nUpgrade to imlib_1.9.14-2woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
