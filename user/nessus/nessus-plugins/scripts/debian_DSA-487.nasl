# This script was automatically generated from the dsa-487
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple format string vulnerabilities were discovered in neon, an
HTTP and WebDAV client library.  These vulnerabilities could
potentially be exploited by a malicious WebDAV server to execute
arbitrary code with the privileges of the process using libneon.
For the current stable distribution (woody) these problems have been
fixed in version 0.19.3-2woody3.
For the unstable distribution (sid), these problems have been fixed in
version 0.24.5-1.
We recommend that you update your neon package.


Solution : http://www.debian.org/security/2004/dsa-487
Risk factor : High';

if (description) {
 script_id(15324);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "487");
 script_cve_id("CVE-2004-0179");
 script_bugtraq_id(10136);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA487] DSA-487-1 neon");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-487-1 neon");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libneon-dev', release: '3.0', reference: '0.19.3-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libneon-dev is vulnerable in Debian 3.0.\nUpgrade to libneon-dev_0.19.3-2woody3\n');
}
if (deb_check(prefix: 'libneon19', release: '3.0', reference: '0.19.3-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libneon19 is vulnerable in Debian 3.0.\nUpgrade to libneon19_0.19.3-2woody3\n');
}
if (deb_check(prefix: 'neon', release: '3.1', reference: '0.24.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package neon is vulnerable in Debian 3.1.\nUpgrade to neon_0.24.5-1\n');
}
if (deb_check(prefix: 'neon', release: '3.0', reference: '0.19.3-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package neon is vulnerable in Debian woody.\nUpgrade to neon_0.19.3-2woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
