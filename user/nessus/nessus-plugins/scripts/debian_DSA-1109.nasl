# This script was automatically generated from the dsa-1109
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Russ Allbery discovered that rssh, a restricted shell, performs
insufficient checking of incoming commands, which might lead to a bypass
of access restrictions.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.3-1.sarge.2.
For the unstable distribution (sid) this problem has been fixed in
version 2.3.0-1.1.
We recommend that you upgrade your rssh package.


Solution : http://www.debian.org/security/2006/dsa-1109
Risk factor : High';

if (description) {
 script_id(22651);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1109");
 script_cve_id("CVE-2006-1320");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1109] DSA-1109-1 rssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1109-1 rssh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rssh', release: '', reference: '2.3.0-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rssh is vulnerable in Debian .\nUpgrade to rssh_2.3.0-1.1\n');
}
if (deb_check(prefix: 'rssh', release: '3.1', reference: '2.2.3-1.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rssh is vulnerable in Debian 3.1.\nUpgrade to rssh_2.2.3-1.sarge.2\n');
}
if (deb_check(prefix: 'rssh', release: '3.1', reference: '2.2.3-1.sarge.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rssh is vulnerable in Debian sarge.\nUpgrade to rssh_2.2.3-1.sarge.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
