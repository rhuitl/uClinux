# This script was automatically generated from the dsa-886
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in chmlib, a library for
dealing with CHM format files.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Palasik Sandor discovered a buffer overflow in the LZX
    decompression method.
    A buffer overflow has been discovered that could lead to the
    execution of arbitrary code.
    Sven Tantau discovered a buffer overflow that could lead to the
    execution of arbitrary code.
The old stable distribution (woody) does not contain chmlib packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.35-6sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.37-2.
We recommend that you upgrade your chmlib packages.


Solution : http://www.debian.org/security/2005/dsa-886
Risk factor : High';

if (description) {
 script_id(22752);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "886");
 script_cve_id("CVE-2005-2659", "CVE-2005-2930", "CVE-2005-3318");
 script_bugtraq_id(15211);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA886] DSA-886-1 chmlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-886-1 chmlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'chmlib', release: '', reference: '0.37-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib is vulnerable in Debian .\nUpgrade to chmlib_0.37-2\n');
}
if (deb_check(prefix: 'chmlib', release: '3.1', reference: '0.35-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib is vulnerable in Debian 3.1.\nUpgrade to chmlib_0.35-6sarge1\n');
}
if (deb_check(prefix: 'chmlib-bin', release: '3.1', reference: '0.35-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib-bin is vulnerable in Debian 3.1.\nUpgrade to chmlib-bin_0.35-6sarge1\n');
}
if (deb_check(prefix: 'chmlib-dev', release: '3.1', reference: '0.35-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib-dev is vulnerable in Debian 3.1.\nUpgrade to chmlib-dev_0.35-6sarge1\n');
}
if (deb_check(prefix: 'chmlib', release: '3.1', reference: '0.35-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chmlib is vulnerable in Debian sarge.\nUpgrade to chmlib_0.35-6sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
