# This script was automatically generated from the dsa-618
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Pavel Kankovsky discovered that several overflows found in the libXpm
library were also present in imlib, an imaging library for X and X11.
An attacker could create a carefully crafted image file in such a way
that it could cause an application linked with imlib to execute
arbitrary code when the file was opened by a victim.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Multiple heap-based buffer overflows.
    Multiple integer overflows.
For the stable distribution (woody) these problems have been fixed in
version 1.9.14-2woody2.
For the unstable distribution (sid) these problems have been fixed in
version 1.9.14-17.1 of imlib and in version 1.9.14-16.1 of imlib+png2
which produces the imlib1 package.
We recommend that you upgrade your imlib packages immediately.


Solution : http://www.debian.org/security/2004/dsa-618
Risk factor : High';

if (description) {
 script_id(16049);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "618");
 script_cve_id("CVE-2004-1025", "CVE-2004-1026");
 script_bugtraq_id(11830);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA618] DSA-618-1 imlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-618-1 imlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gdk-imlib-dev', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-imlib-dev is vulnerable in Debian 3.0.\nUpgrade to gdk-imlib-dev_1.9.14-2woody2\n');
}
if (deb_check(prefix: 'gdk-imlib1', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdk-imlib1 is vulnerable in Debian 3.0.\nUpgrade to gdk-imlib1_1.9.14-2woody2\n');
}
if (deb_check(prefix: 'imlib-base', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib-base is vulnerable in Debian 3.0.\nUpgrade to imlib-base_1.9.14-2woody2\n');
}
if (deb_check(prefix: 'imlib-dev', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib-dev is vulnerable in Debian 3.0.\nUpgrade to imlib-dev_1.9.14-2woody2\n');
}
if (deb_check(prefix: 'imlib-progs', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib-progs is vulnerable in Debian 3.0.\nUpgrade to imlib-progs_1.9.14-2woody2\n');
}
if (deb_check(prefix: 'imlib1', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib1 is vulnerable in Debian 3.0.\nUpgrade to imlib1_1.9.14-2woody2\n');
}
if (deb_check(prefix: 'imlib', release: '3.1', reference: '1.9.14-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib is vulnerable in Debian 3.1.\nUpgrade to imlib_1.9.14-17\n');
}
if (deb_check(prefix: 'imlib', release: '3.0', reference: '1.9.14-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib is vulnerable in Debian woody.\nUpgrade to imlib_1.9.14-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
