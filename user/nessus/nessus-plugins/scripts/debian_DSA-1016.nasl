# This script was automatically generated from the dsa-1016
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered several format string vulnerabilities in
Evolution, a free groupware suite, that could lead to crashes of the
application or the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed
in version 1.0.5-1woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.4-2sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.2.3-3.
We recommend that you upgrade your evolution package.


Solution : http://www.debian.org/security/2006/dsa-1016
Risk factor : High';

if (description) {
 script_id(22558);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1016");
 script_cve_id("CVE-2005-2549", "CVE-2005-2550");
 script_bugtraq_id(14532);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1016] DSA-1016-1 evolution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1016-1 evolution");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'evolution', release: '', reference: '2.2.3-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian .\nUpgrade to evolution_2.2.3-3\n');
}
if (deb_check(prefix: 'evolution', release: '3.0', reference: '1.0.5-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian 3.0.\nUpgrade to evolution_1.0.5-1woody3\n');
}
if (deb_check(prefix: 'libcamel-dev', release: '3.0', reference: '1.0.5-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcamel-dev is vulnerable in Debian 3.0.\nUpgrade to libcamel-dev_1.0.5-1woody3\n');
}
if (deb_check(prefix: 'libcamel0', release: '3.0', reference: '1.0.5-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcamel0 is vulnerable in Debian 3.0.\nUpgrade to libcamel0_1.0.5-1woody3\n');
}
if (deb_check(prefix: 'evolution', release: '3.1', reference: '2.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian 3.1.\nUpgrade to evolution_2.0.4-2sarge1\n');
}
if (deb_check(prefix: 'evolution-dev', release: '3.1', reference: '2.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution-dev is vulnerable in Debian 3.1.\nUpgrade to evolution-dev_2.0.4-2sarge1\n');
}
if (deb_check(prefix: 'evolution', release: '3.1', reference: '2.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian sarge.\nUpgrade to evolution_2.0.4-2sarge1\n');
}
if (deb_check(prefix: 'evolution', release: '3.0', reference: '1.0.5-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package evolution is vulnerable in Debian woody.\nUpgrade to evolution_1.0.5-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
