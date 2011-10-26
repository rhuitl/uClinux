# This script was automatically generated from the dsa-1144
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that one of the utilities shipped with chmlib, a
library for dealing with Microsoft CHM files, performs insufficient
sanitising of filenames, which might lead to directory traversal.
For the stable distribution (sarge) this problem has been fixed in
version 0.35-6sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 0.38-1.
We recommend that you upgrade your chmlib-bin package.


Solution : http://www.debian.org/security/2006/dsa-1144
Risk factor : High';

if (description) {
 script_id(22686);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1144");
 script_cve_id("CVE-2006-3178");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1144] DSA-1144-1 chmlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1144-1 chmlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'chmlib', release: '', reference: '0.38-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib is vulnerable in Debian .\nUpgrade to chmlib_0.38-1\n');
}
if (deb_check(prefix: 'chmlib', release: '3.1', reference: '0.35-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib is vulnerable in Debian 3.1.\nUpgrade to chmlib_0.35-6sarge3\n');
}
if (deb_check(prefix: 'chmlib-bin', release: '3.1', reference: '0.35-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib-bin is vulnerable in Debian 3.1.\nUpgrade to chmlib-bin_0.35-6sarge3\n');
}
if (deb_check(prefix: 'chmlib-dev', release: '3.1', reference: '0.35-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib-dev is vulnerable in Debian 3.1.\nUpgrade to chmlib-dev_0.35-6sarge3\n');
}
if (deb_check(prefix: 'chmlib', release: '3.1', reference: '0.35-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib is vulnerable in Debian sarge.\nUpgrade to chmlib_0.35-6sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
