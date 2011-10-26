# This script was automatically generated from the dsa-1068
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jan Braun discovered that the fbgs script of fbi, an image viewer for
the framebuffer environment, creates an directory in a predictable manner,
which allows denial of service through symlink attacks.
For the old stable distribution (woody) this problem has been fixed in
version 1.23woody1.
For the stable distribution (sarge) this problem has been fixed in
version 2.01-1.2sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your fbi package.


Solution : http://www.debian.org/security/2006/dsa-1068
Risk factor : High';

if (description) {
 script_id(22610);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1068");
 script_cve_id("CVE-2006-1695");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1068] DSA-1068-1 fbi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1068-1 fbi");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fbi', release: '3.0', reference: '1.23woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fbi is vulnerable in Debian 3.0.\nUpgrade to fbi_1.23woody1\n');
}
if (deb_check(prefix: 'exiftran', release: '3.1', reference: '2.01-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package exiftran is vulnerable in Debian 3.1.\nUpgrade to exiftran_2.01-1.2sarge1\n');
}
if (deb_check(prefix: 'fbi', release: '3.1', reference: '2.01-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fbi is vulnerable in Debian 3.1.\nUpgrade to fbi_2.01-1.2sarge1\n');
}
if (deb_check(prefix: 'fbi', release: '3.1', reference: '2.01-1.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fbi is vulnerable in Debian sarge.\nUpgrade to fbi_2.01-1.2sarge1\n');
}
if (deb_check(prefix: 'fbi', release: '3.0', reference: '1.23woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fbi is vulnerable in Debian woody.\nUpgrade to fbi_1.23woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
