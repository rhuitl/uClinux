# This script was automatically generated from the dsa-650
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar discovered that due to missing input sanitising in
diatheke, a CGI script for making and browsing a bible website, it is
possible to execute arbitrary commands via a specially crafted URL.
For the stable distribution (woody) this problem has been fixed in
version 1.5.3-3woody2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your diatheke package.


Solution : http://www.debian.org/security/2005/dsa-650
Risk factor : High';

if (description) {
 script_id(16234);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "650");
 script_cve_id("CVE-2005-0015");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA650] DSA-650-1 sword");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-650-1 sword");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'diatheke', release: '3.0', reference: '1.5.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package diatheke is vulnerable in Debian 3.0.\nUpgrade to diatheke_1.5.3-3woody2\n');
}
if (deb_check(prefix: 'libsword-dev', release: '3.0', reference: '1.5.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsword-dev is vulnerable in Debian 3.0.\nUpgrade to libsword-dev_1.5.3-3woody2\n');
}
if (deb_check(prefix: 'libsword-runtime', release: '3.0', reference: '1.5.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsword-runtime is vulnerable in Debian 3.0.\nUpgrade to libsword-runtime_1.5.3-3woody2\n');
}
if (deb_check(prefix: 'libsword1', release: '3.0', reference: '1.5.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsword1 is vulnerable in Debian 3.0.\nUpgrade to libsword1_1.5.3-3woody2\n');
}
if (deb_check(prefix: 'sword', release: '3.0', reference: '1.5.3-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sword is vulnerable in Debian woody.\nUpgrade to sword_1.5.3-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
