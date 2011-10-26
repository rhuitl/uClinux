# This script was automatically generated from the dsa-1047
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in resmgr, a resource manager library
daemon and PAM module, that allows local users to bypass access
control rules and open any USB device when access to one device was
granted.
The old stable distribution (woody) does not contain resmgr packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0-2sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 1.0-4.
We recommend that you upgrade your resmgr package.


Solution : http://www.debian.org/security/2006/dsa-1047
Risk factor : High';

if (description) {
 script_id(22589);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1047");
 script_cve_id("CVE-2006-2147");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1047] DSA-1047-1 resmgr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1047-1 resmgr");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'resmgr', release: '', reference: '1.0-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package resmgr is vulnerable in Debian .\nUpgrade to resmgr_1.0-4\n');
}
if (deb_check(prefix: 'libresmgr-dev', release: '3.1', reference: '1.0-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libresmgr-dev is vulnerable in Debian 3.1.\nUpgrade to libresmgr-dev_1.0-2sarge2\n');
}
if (deb_check(prefix: 'libresmgr1', release: '3.1', reference: '1.0-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libresmgr1 is vulnerable in Debian 3.1.\nUpgrade to libresmgr1_1.0-2sarge2\n');
}
if (deb_check(prefix: 'resmgr', release: '3.1', reference: '1.0-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package resmgr is vulnerable in Debian 3.1.\nUpgrade to resmgr_1.0-2sarge2\n');
}
if (deb_check(prefix: 'resmgr', release: '3.1', reference: '1.0-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package resmgr is vulnerable in Debian sarge.\nUpgrade to resmgr_1.0-2sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
