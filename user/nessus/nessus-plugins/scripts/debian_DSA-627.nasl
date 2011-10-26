# This script was automatically generated from the dsa-627
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross-site scripting vulnerability has been discovered in namazu2, a
full text search engine.  An attacker could prepare specially crafted
input that would not be sanitised by namazu2 and hence displayed
verbatim for the victim.
For the stable distribution (woody) this problem has been fixed in
version 2.0.10-1woody3.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.14-1.
We recommend that you upgrade your namazu2 package.


Solution : http://www.debian.org/security/2005/dsa-627
Risk factor : High';

if (description) {
 script_id(16105);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "627");
 script_cve_id("CVE-2004-1318");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA627] DSA-627-1 namazu2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-627-1 namazu2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnmz3', release: '3.0', reference: '2.0.10-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnmz3 is vulnerable in Debian 3.0.\nUpgrade to libnmz3_2.0.10-1woody3\n');
}
if (deb_check(prefix: 'libnmz3-dev', release: '3.0', reference: '2.0.10-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnmz3-dev is vulnerable in Debian 3.0.\nUpgrade to libnmz3-dev_2.0.10-1woody3\n');
}
if (deb_check(prefix: 'namazu2', release: '3.0', reference: '2.0.10-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package namazu2 is vulnerable in Debian 3.0.\nUpgrade to namazu2_2.0.10-1woody3\n');
}
if (deb_check(prefix: 'namazu2-common', release: '3.0', reference: '2.0.10-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package namazu2-common is vulnerable in Debian 3.0.\nUpgrade to namazu2-common_2.0.10-1woody3\n');
}
if (deb_check(prefix: 'namazu2-index-tools', release: '3.0', reference: '2.0.10-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package namazu2-index-tools is vulnerable in Debian 3.0.\nUpgrade to namazu2-index-tools_2.0.10-1woody3\n');
}
if (deb_check(prefix: 'namazu2', release: '3.1', reference: '2.0.14-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package namazu2 is vulnerable in Debian 3.1.\nUpgrade to namazu2_2.0.14-1\n');
}
if (deb_check(prefix: 'namazu2', release: '3.0', reference: '2.0.10-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package namazu2 is vulnerable in Debian woody.\nUpgrade to namazu2_2.0.10-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
