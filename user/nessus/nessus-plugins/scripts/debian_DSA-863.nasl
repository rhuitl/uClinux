# This script was automatically generated from the dsa-863
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
format string vulnerability in the CDDB processing component of
xine-lib, the xine video/media player library, that could lead to the
execution of arbitrary code caused by a malicious CDDB entry.
For the old stable distribution (woody) this problem has been fixed in
version 0.9.8-2woody4.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.1-1sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your libxine0 and libxine1 packages.


Solution : http://www.debian.org/security/2005/dsa-863
Risk factor : High';

if (description) {
 script_id(20018);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "863");
 script_cve_id("CVE-2005-2967");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA863] DSA-863-1 xine-lib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-863-1 xine-lib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libxine-dev', release: '3.0', reference: '0.9.8-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine-dev is vulnerable in Debian 3.0.\nUpgrade to libxine-dev_0.9.8-2woody4\n');
}
if (deb_check(prefix: 'libxine0', release: '3.0', reference: '0.9.8-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine0 is vulnerable in Debian 3.0.\nUpgrade to libxine0_0.9.8-2woody4\n');
}
if (deb_check(prefix: 'libxine-dev', release: '3.1', reference: '1.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine-dev is vulnerable in Debian 3.1.\nUpgrade to libxine-dev_1.0.1-1sarge1\n');
}
if (deb_check(prefix: 'libxine1', release: '3.1', reference: '1.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine1 is vulnerable in Debian 3.1.\nUpgrade to libxine1_1.0.1-1sarge1\n');
}
if (deb_check(prefix: 'xine-lib', release: '3.1', reference: '1.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian sarge.\nUpgrade to xine-lib_1.0.1-1sarge1\n');
}
if (deb_check(prefix: 'xine-lib', release: '3.0', reference: '0.9.8-2woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian woody.\nUpgrade to xine-lib_0.9.8-2woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
