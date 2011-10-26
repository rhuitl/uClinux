# This script was automatically generated from the dsa-565
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar has reported two vulnerabilities in SoX, a universal
sound sample translator, which may be exploited by malicious people to
compromise a user\'s system with a specially crafted .wav file.
For the stable distribution (woody) these problems have been fixed in
version 12.17.3-4woody2.
For the unstable distribution (sid) these problems have been fixed in
version 12.17.4-9.
We recommend that you upgrade your sox package.


Solution : http://www.debian.org/security/2004/dsa-565
Risk factor : High';

if (description) {
 script_id(15663);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "565");
 script_cve_id("CVE-2004-0557");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA565] DSA-565-1 sox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-565-1 sox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sox', release: '3.0', reference: '12.17.3-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sox is vulnerable in Debian 3.0.\nUpgrade to sox_12.17.3-4woody2\n');
}
if (deb_check(prefix: 'sox-dev', release: '3.0', reference: '12.17.3-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sox-dev is vulnerable in Debian 3.0.\nUpgrade to sox-dev_12.17.3-4woody2\n');
}
if (deb_check(prefix: 'sox', release: '3.1', reference: '12.17.4-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sox is vulnerable in Debian 3.1.\nUpgrade to sox_12.17.4-9\n');
}
if (deb_check(prefix: 'sox', release: '3.0', reference: '12.17.3-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sox is vulnerable in Debian woody.\nUpgrade to sox_12.17.3-4woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
