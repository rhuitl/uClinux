# This script was automatically generated from the dsa-307
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
gPS is a graphical application to watch system processes.  In release
1.1.0 of the gps package, several security vulnerabilities were fixed,
as detailed in the changelog:
All of these problems affect Debian\'s gps package version 0.9.4-1 in
Debian woody.  Debian potato also contains a gps package (version
0.4.1-2), but it is not affected by these problems, as the relevant
functionality is not implemented in that version.
For the stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody1.
The old stable distribution (potato) is not affected by these problems.
For the unstable distribution (sid) these problems are fixed in
version 1.1.0-1.
We recommend that you update your gps package.


Solution : http://www.debian.org/security/2003/dsa-307
Risk factor : High';

if (description) {
 script_id(15144);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "307");
 script_cve_id("CVE-2003-0360", "CVE-2003-0361", "CVE-2003-0362");
 script_bugtraq_id(7736);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA307] DSA-307-1 gps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-307-1 gps");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gps', release: '3.0', reference: '0.9.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gps is vulnerable in Debian 3.0.\nUpgrade to gps_0.9.4-1woody1\n');
}
if (deb_check(prefix: 'rgpsp', release: '3.0', reference: '0.9.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rgpsp is vulnerable in Debian 3.0.\nUpgrade to rgpsp_0.9.4-1woody1\n');
}
if (deb_check(prefix: 'gps', release: '3.1', reference: '1.1.0-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gps is vulnerable in Debian 3.1.\nUpgrade to gps_1.1.0-1\n');
}
if (deb_check(prefix: 'gps', release: '3.0', reference: '0.9.4-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gps is vulnerable in Debian woody.\nUpgrade to gps_0.9.4-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
