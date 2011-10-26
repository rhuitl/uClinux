# This script was automatically generated from the dsa-761
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The security update DSA 761-1 for pdns contained a bug which caused a
regression.  This problem is corrected with this advisory.  For
completeness below please find the original advisory text:
Eric Romang discovered several insecure temporary file creations in
heartbeat, the subsystem for High-Availability Linux.
For the old stable distribution (woody) these problems have been fixed in
version 0.4.9.0l-7.3.
For the stable distribution (sarge) these problems have been fixed in
version 1.2.3-9sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 1.2.3-12.
We recommend that you upgrade your heartbeat package.


Solution : http://www.debian.org/security/2005/dsa-761
Risk factor : High';

if (description) {
 script_id(19224);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "761");
 script_cve_id("CVE-2005-2231");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA761] DSA-761-2 heartbeat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-761-2 heartbeat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'heartbeat', release: '', reference: '1.2.3-12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian .\nUpgrade to heartbeat_1.2.3-12\n');
}
if (deb_check(prefix: 'heartbeat', release: '3.0', reference: '0.4.9.0l-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian 3.0.\nUpgrade to heartbeat_0.4.9.0l-7.3\n');
}
if (deb_check(prefix: 'ldirectord', release: '3.0', reference: '0.4.9.0l-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldirectord is vulnerable in Debian 3.0.\nUpgrade to ldirectord_0.4.9.0l-7.3\n');
}
if (deb_check(prefix: 'libstonith-dev', release: '3.0', reference: '0.4.9.0l-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith-dev is vulnerable in Debian 3.0.\nUpgrade to libstonith-dev_0.4.9.0l-7.3\n');
}
if (deb_check(prefix: 'libstonith0', release: '3.0', reference: '0.4.9.0l-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith0 is vulnerable in Debian 3.0.\nUpgrade to libstonith0_0.4.9.0l-7.3\n');
}
if (deb_check(prefix: 'stonith', release: '3.0', reference: '0.4.9.0l-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package stonith is vulnerable in Debian 3.0.\nUpgrade to stonith_0.4.9.0l-7.3\n');
}
if (deb_check(prefix: 'heartbeat', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian 3.1.\nUpgrade to heartbeat_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'heartbeat-dev', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat-dev is vulnerable in Debian 3.1.\nUpgrade to heartbeat-dev_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'ldirectord', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldirectord is vulnerable in Debian 3.1.\nUpgrade to ldirectord_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'libpils-dev', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpils-dev is vulnerable in Debian 3.1.\nUpgrade to libpils-dev_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'libpils0', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpils0 is vulnerable in Debian 3.1.\nUpgrade to libpils0_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'libstonith-dev', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith-dev is vulnerable in Debian 3.1.\nUpgrade to libstonith-dev_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'libstonith0', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libstonith0 is vulnerable in Debian 3.1.\nUpgrade to libstonith0_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'stonith', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package stonith is vulnerable in Debian 3.1.\nUpgrade to stonith_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'heartbeat', release: '3.1', reference: '1.2.3-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian sarge.\nUpgrade to heartbeat_1.2.3-9sarge3\n');
}
if (deb_check(prefix: 'heartbeat', release: '3.0', reference: '0.4.9.0l-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package heartbeat is vulnerable in Debian woody.\nUpgrade to heartbeat_0.4.9.0l-7.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
