# This script was automatically generated from the dsa-1119
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Akira Tanaka discovered a vulnerability in Hiki Wiki, a Wiki engine
written in Ruby that allows remote attackers to cause a denial of
service via high CPU consumption using by performing a diff between
large and specially crafted Wiki pages.
For the stable distribution (sarge) this problem has been fixed in
version 0.6.5-2.
For the unstable distribution (sid) this problem has been fixed in
version 0.8.6-1.
We recommend that you upgrade your hiki package.


Solution : http://www.debian.org/security/2006/dsa-1119
Risk factor : High';

if (description) {
 script_id(22661);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1119");
 script_cve_id("CVE-2006-3379");
 script_bugtraq_id(18785);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1119] DSA-1119-1 hiki");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1119-1 hiki");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hiki', release: '', reference: '0.8.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hiki is vulnerable in Debian .\nUpgrade to hiki_0.8.6-1\n');
}
if (deb_check(prefix: 'hiki', release: '3.1', reference: '0.6.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hiki is vulnerable in Debian 3.1.\nUpgrade to hiki_0.6.5-2\n');
}
if (deb_check(prefix: 'hiki', release: '3.1', reference: '0.6.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hiki is vulnerable in Debian sarge.\nUpgrade to hiki_0.6.5-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
