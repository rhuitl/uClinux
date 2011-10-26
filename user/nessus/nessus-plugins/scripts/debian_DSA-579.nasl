# This script was automatically generated from the dsa-579
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow vulnerability has been discovered in the wv library,
used for converting and previewing word documents.  On exploitation an
attacker could execute arbitrary code with the privileges of the user
running the vulnerable application.
For the stable distribution (woody) this problem has been fixed in
version 1.0.2+cvs.2002.06.05-1woody2.
The package in the unstable distribution (sid) is not affected.
We recommend that you upgrade your abiword package.


Solution : http://www.debian.org/security/2004/dsa-579
Risk factor : High';

if (description) {
 script_id(15677);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "579");
 script_cve_id("CVE-2004-0645");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA579] DSA-579-1 abiword");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-579-1 abiword");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'abiword', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian 3.0.\nUpgrade to abiword_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'abiword-common', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-common is vulnerable in Debian 3.0.\nUpgrade to abiword-common_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'abiword-doc', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-doc is vulnerable in Debian 3.0.\nUpgrade to abiword-doc_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'abiword-gnome', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-gnome is vulnerable in Debian 3.0.\nUpgrade to abiword-gnome_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'abiword-gtk', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-gtk is vulnerable in Debian 3.0.\nUpgrade to abiword-gtk_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'abiword-plugins', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-plugins is vulnerable in Debian 3.0.\nUpgrade to abiword-plugins_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'xfonts-abi', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-abi is vulnerable in Debian 3.0.\nUpgrade to xfonts-abi_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (deb_check(prefix: 'abiword', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian woody.\nUpgrade to abiword_1.0.2+cvs.2002.06.05-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
