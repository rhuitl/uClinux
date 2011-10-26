# This script was automatically generated from the dsa-1100
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A boundary checking error has been discovered in wv2, a library for
accessing Microsoft Word documents, which can lead to an integer
overflow induced by processing word files.
The old stable distribution (woody) does not contain wv2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.2.2-1sarge1
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your libwv packages.


Solution : http://www.debian.org/security/2006/dsa-1100
Risk factor : High';

if (description) {
 script_id(22642);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1100");
 script_cve_id("CVE-2006-2197");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1100] DSA-1100-1 wv2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1100-1 wv2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libwv2-1', release: '3.1', reference: '0.2.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwv2-1 is vulnerable in Debian 3.1.\nUpgrade to libwv2-1_0.2.2-1sarge1\n');
}
if (deb_check(prefix: 'libwv2-dev', release: '3.1', reference: '0.2.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwv2-dev is vulnerable in Debian 3.1.\nUpgrade to libwv2-dev_0.2.2-1sarge1\n');
}
if (deb_check(prefix: 'wv2', release: '3.1', reference: '0.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wv2 is vulnerable in Debian sarge.\nUpgrade to wv2_0.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
