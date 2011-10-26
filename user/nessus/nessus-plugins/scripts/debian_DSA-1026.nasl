# This script was automatically generated from the dsa-1026
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Markus Oberhumer discovered a flaw in the way zlib, a library used for
file compression and decompression, handles invalid input. This flaw can
cause programs which use zlib to crash when opening an invalid file.
A further error in the way zlib handles the inflation of certain
compressed files can cause a program which uses zlib to crash when opening
an invalid file.
sash, the stand-alone shell, links statically against zlib, and was
thus affected by these problems.
The old stable distribution (woody) isn\'t affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 3.7-5sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 3.7-6.
We recommend that you upgrade your sash package.


Solution : http://www.debian.org/security/2006/dsa-1026
Risk factor : High';

if (description) {
 script_id(22568);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1026");
 script_cve_id("CVE-2005-1849", "CVE-2005-2096");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1026] DSA-1026-1 sash");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1026-1 sash");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sash', release: '', reference: '3.7-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sash is vulnerable in Debian .\nUpgrade to sash_3.7-6\n');
}
if (deb_check(prefix: 'sash', release: '3.1', reference: '3.7-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sash is vulnerable in Debian 3.1.\nUpgrade to sash_3.7-5sarge1\n');
}
if (deb_check(prefix: 'sash', release: '3.1', reference: '3.7-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sash is vulnerable in Debian sarge.\nUpgrade to sash_3.7-5sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
