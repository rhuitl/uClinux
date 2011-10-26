# This script was automatically generated from the dsa-507
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser discovered a problem in neon, an HTTP and WebDAV client
library, which is also present in cadaver, a command-line client for
WebDAV server.  User input is copied into variables not large enough
for all cases.  This can lead to an overflow of a static heap
variable.
For the stable distribution (woody) this problem has been fixed in
version 0.18.0-1woody3.
For the unstable distribution (sid) this problem has been fixed in
version 0.22.1-3.
We recommend that you upgrade your cadaver package.


Solution : http://www.debian.org/security/2004/dsa-507
Risk factor : High';

if (description) {
 script_id(15344);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "507");
 script_cve_id("CVE-2004-0398");
 script_bugtraq_id(10385);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA507] DSA-507-1 cadaver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-507-1 cadaver");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cadaver', release: '3.0', reference: '0.18.0-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cadaver is vulnerable in Debian 3.0.\nUpgrade to cadaver_0.18.0-1woody3\n');
}
if (deb_check(prefix: 'cadaver', release: '3.1', reference: '0.22.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cadaver is vulnerable in Debian 3.1.\nUpgrade to cadaver_0.22.1-3\n');
}
if (deb_check(prefix: 'cadaver', release: '3.0', reference: '0.18.0-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cadaver is vulnerable in Debian woody.\nUpgrade to cadaver_0.18.0-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
