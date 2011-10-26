# This script was automatically generated from the dsa-1149
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tavis Ormandy from the Google Security Team discovered a missing
boundary check in ncompress, the original Lempel-Ziv compress and
uncompress programs, which allows a specially crafted datastream to
underflow a buffer with attacker controlled data.
For the stable distribution (sarge) this problem has been fixed in
version 4.2.4-15sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 4.2.4-15sarge2.
We recommend that you upgrade your ncompress package.


Solution : http://www.debian.org/security/2006/dsa-1149
Risk factor : High';

if (description) {
 script_id(22691);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1149");
 script_cve_id("CVE-2006-1168");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1149] DSA-1149-1 ncompress");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1149-1 ncompress");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ncompress', release: '', reference: '4.2.4-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncompress is vulnerable in Debian .\nUpgrade to ncompress_4.2.4-15sarge2\n');
}
if (deb_check(prefix: 'ncompress', release: '3.1', reference: '4.2.4-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncompress is vulnerable in Debian 3.1.\nUpgrade to ncompress_4.2.4-15sarge2\n');
}
if (deb_check(prefix: 'ncompress', release: '3.1', reference: '4.2.4-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ncompress is vulnerable in Debian sarge.\nUpgrade to ncompress_4.2.4-15sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
