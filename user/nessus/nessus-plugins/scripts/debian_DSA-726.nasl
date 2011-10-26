# This script was automatically generated from the dsa-726
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A format string vulnerability has been discovered in the MySQL/PgSQL
authentication module of Oops, a caching HTTP proxy server written
for performance.
For the stable distribution (woody) this problem has been fixed in
version 1.5.19.cvs.20010818-0.1woody1
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your oops package.


Solution : http://www.debian.org/security/2005/dsa-726
Risk factor : High';

if (description) {
 script_id(18513);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "726");
 script_cve_id("CVE-2005-1121");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA726] DSA-726-1 oops");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-726-1 oops");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'oops', release: '3.0', reference: '1.5.19.cvs.20010818-0.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package oops is vulnerable in Debian 3.0.\nUpgrade to oops_1.5.19.cvs.20010818-0.1woody1\n');
}
if (deb_check(prefix: 'oops', release: '3.0', reference: '1.5.19.cvs.20010818-0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package oops is vulnerable in Debian woody.\nUpgrade to oops_1.5.19.cvs.20010818-0\n');
}
if (w) { security_hole(port: 0, data: desc); }
