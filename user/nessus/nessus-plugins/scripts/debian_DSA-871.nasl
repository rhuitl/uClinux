# This script was automatically generated from the dsa-871
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered two format string vulnerabilities in libgda2,
the GNOME Data Access library for GNOME2, which may lead to the
execution of arbitrary code in programs that use this library.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 1.2.1-2sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your libgda2 packages.


Solution : http://www.debian.org/security/2005/dsa-871
Risk factor : High';

if (description) {
 script_id(22737);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "871");
 script_cve_id("CVE-2005-2958");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA871] DSA-871-2 libgda2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-871-2 libgda2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gda2-freetds', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gda2-freetds is vulnerable in Debian 3.1.\nUpgrade to gda2-freetds_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'gda2-mysql', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gda2-mysql is vulnerable in Debian 3.1.\nUpgrade to gda2-mysql_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'gda2-odbc', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gda2-odbc is vulnerable in Debian 3.1.\nUpgrade to gda2-odbc_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'gda2-postgres', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gda2-postgres is vulnerable in Debian 3.1.\nUpgrade to gda2-postgres_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'gda2-sqlite', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gda2-sqlite is vulnerable in Debian 3.1.\nUpgrade to gda2-sqlite_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'libgda2-3', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgda2-3 is vulnerable in Debian 3.1.\nUpgrade to libgda2-3_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'libgda2-3-dbg', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgda2-3-dbg is vulnerable in Debian 3.1.\nUpgrade to libgda2-3-dbg_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'libgda2-common', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgda2-common is vulnerable in Debian 3.1.\nUpgrade to libgda2-common_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'libgda2-dev', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgda2-dev is vulnerable in Debian 3.1.\nUpgrade to libgda2-dev_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'libgda2-doc', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgda2-doc is vulnerable in Debian 3.1.\nUpgrade to libgda2-doc_1.2.1-2sarge1\n');
}
if (deb_check(prefix: 'libgda2', release: '3.1', reference: '1.2.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgda2 is vulnerable in Debian sarge.\nUpgrade to libgda2_1.2.1-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
