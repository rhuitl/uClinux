# This script was automatically generated from the dsa-655
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered that zhcon, a fast console CJK system using
the Linux framebuffer, accesses a user-controlled configuration file
with elevated privileges.  Thus, it is possible to read arbitrary
files.
For the stable distribution (woody) this problem has been fixed in
version 0.2-4woody3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your zhcon package.


Solution : http://www.debian.org/security/2005/dsa-655
Risk factor : High';

if (description) {
 script_id(16239);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "655");
 script_cve_id("CVE-2005-0072");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA655] DSA-655-1 zhcon");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-655-1 zhcon");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zhcon', release: '3.0', reference: '0.2-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zhcon is vulnerable in Debian 3.0.\nUpgrade to zhcon_0.2-4woody3\n');
}
if (deb_check(prefix: 'zhcon', release: '3.0', reference: '0.2-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zhcon is vulnerable in Debian woody.\nUpgrade to zhcon_0.2-4woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
