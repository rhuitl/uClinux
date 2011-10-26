# This script was automatically generated from the dsa-1151
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Yan Rong Ge discovered out-of-boundary memory access in heartbeat, the
subsystem for High-Availability Linux.  This could be used by a remote
attacker to cause a denial of service.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.3-9sarge6.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.4-14 and heartbeat-2 2.0.6-2.
We recommend that you upgrade your heartbeat packages.


Solution : http://www.debian.org/security/2006/dsa-1151
Risk factor : High';

if (description) {
 script_id(22693);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1151");
 script_cve_id("CVE-2006-3121");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1151] DSA-1151-1 heartbeat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1151-1 heartbeat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heartbeat', release: '', reference: '1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian .\nUpgrade to heartbeat_1.2\n');
}
if (deb_check(prefix: 'heartbeat', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian 3.1.\nUpgrade to heartbeat_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'heartbeat-dev', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat-dev is vulnerable in Debian 3.1.\nUpgrade to heartbeat-dev_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'ldirectord', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldirectord is vulnerable in Debian 3.1.\nUpgrade to ldirectord_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'libpils-dev', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpils-dev is vulnerable in Debian 3.1.\nUpgrade to libpils-dev_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'libpils0', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpils0 is vulnerable in Debian 3.1.\nUpgrade to libpils0_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'libstonith-dev', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith-dev is vulnerable in Debian 3.1.\nUpgrade to libstonith-dev_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'libstonith0', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith0 is vulnerable in Debian 3.1.\nUpgrade to libstonith0_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'stonith', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package stonith is vulnerable in Debian 3.1.\nUpgrade to stonith_1.2.3-9sarge6\n');
}
if (deb_check(prefix: 'heartbeat', release: '3.1', reference: '1.2.3-9sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian sarge.\nUpgrade to heartbeat_1.2.3-9sarge6\n');
}
if (w) { security_hole(port: 0, data: desc); }
