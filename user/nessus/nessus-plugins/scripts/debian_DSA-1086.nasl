# This script was automatically generated from the dsa-1086
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The xmcdconfig creates directories world-writeable allowing local
users to fill the /usr and /var partition and hence cause a denial of
service.  This problem has been half-fixed since version 2.3-1.
For the old stable distribution (woody) this problem has been fixed in
version 2.6-14woody1.
For the stable distribution (sarge) this problem has been fixed in
version 2.6-17sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.6-18.
We recommend that you upgrade your xmcd package.


Solution : http://www.debian.org/security/2006/dsa-1086
Risk factor : High';

if (description) {
 script_id(22628);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1086");
 script_cve_id("CVE-2006-2542");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1086] DSA-1086-1 xmcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1086-1 xmcd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xmcd', release: '', reference: '2.6-18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmcd is vulnerable in Debian .\nUpgrade to xmcd_2.6-18\n');
}
if (deb_check(prefix: 'cddb', release: '3.0', reference: '2.6-14woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cddb is vulnerable in Debian 3.0.\nUpgrade to cddb_2.6-14woody1\n');
}
if (deb_check(prefix: 'xmcd', release: '3.0', reference: '2.6-14woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmcd is vulnerable in Debian 3.0.\nUpgrade to xmcd_2.6-14woody1\n');
}
if (deb_check(prefix: 'cddb', release: '3.1', reference: '2.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cddb is vulnerable in Debian 3.1.\nUpgrade to cddb_2.6-17sarge1\n');
}
if (deb_check(prefix: 'xmcd', release: '3.1', reference: '2.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmcd is vulnerable in Debian 3.1.\nUpgrade to xmcd_2.6-17sarge1\n');
}
if (deb_check(prefix: 'xmcd', release: '3.1', reference: '2.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmcd is vulnerable in Debian sarge.\nUpgrade to xmcd_2.6-17sarge1\n');
}
if (deb_check(prefix: 'xmcd', release: '3.0', reference: '2.6-14woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xmcd is vulnerable in Debian woody.\nUpgrade to xmcd_2.6-14woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
