# This script was automatically generated from the dsa-1105
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Federico L. Bossi Bonin discovered a buffer overflow in the HTTP
Plugin in xine-lib, the xine video/media player library, that could
allow a remote attacker to cause a denial of service.
For the old stable distribution (woody) this problem has been fixed in
version 0.9.8-2woody5.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.1-1sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.1-2.
We recommend that you upgrade your libxine packages.


Solution : http://www.debian.org/security/2006/dsa-1105
Risk factor : High';

if (description) {
 script_id(22647);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1105");
 script_cve_id("CVE-2006-2802");
 script_bugtraq_id(18187);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1105] DSA-1105-1 xine-lib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1105-1 xine-lib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xine-lib', release: '', reference: '1.1.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian .\nUpgrade to xine-lib_1.1.1-2\n');
}
if (deb_check(prefix: 'libxine-dev', release: '3.0', reference: '0.9.8-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine-dev is vulnerable in Debian 3.0.\nUpgrade to libxine-dev_0.9.8-2woody5\n');
}
if (deb_check(prefix: 'libxine0', release: '3.0', reference: '0.9.8-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine0 is vulnerable in Debian 3.0.\nUpgrade to libxine0_0.9.8-2woody5\n');
}
if (deb_check(prefix: 'libxine-dev', release: '3.1', reference: '1.0.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine-dev is vulnerable in Debian 3.1.\nUpgrade to libxine-dev_1.0.1-1sarge3\n');
}
if (deb_check(prefix: 'libxine1', release: '3.1', reference: '1.0.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine1 is vulnerable in Debian 3.1.\nUpgrade to libxine1_1.0.1-1sarge3\n');
}
if (deb_check(prefix: 'xine-lib', release: '3.1', reference: '1.0.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian sarge.\nUpgrade to xine-lib_1.0.1-1sarge3\n');
}
if (deb_check(prefix: 'xine-lib', release: '3.0', reference: '0.9.8-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian woody.\nUpgrade to xine-lib_0.9.8-2woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
