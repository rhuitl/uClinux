# This script was automatically generated from the dsa-614
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luke "infamous41md" discovered multiple vulnerabilities in xzgv, a
picture viewer for X11 with a thumbnail-based selector.  Remote
exploitation of an integer overflow vulnerability could allow the
execution of arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 0.7-6woody2.
For the unstable distribution (sid) these problems have been fixed in
version 0.8-3.
We recommend that you upgrade your xzgv package immediately.


Solution : http://www.debian.org/security/2004/dsa-614
Risk factor : High';

if (description) {
 script_id(16020);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "614");
 script_cve_id("CVE-2004-0994");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA614] DSA-614-1 xzgv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-614-1 xzgv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xzgv', release: '3.0', reference: '0.7-6woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian 3.0.\nUpgrade to xzgv_0.7-6woody2\n');
}
if (deb_check(prefix: 'xzgv', release: '3.1', reference: '0.8-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian 3.1.\nUpgrade to xzgv_0.8-3\n');
}
if (deb_check(prefix: 'xzgv', release: '3.0', reference: '0.7-6woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian woody.\nUpgrade to xzgv_0.7-6woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
