# This script was automatically generated from the dsa-998
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Derek Noonburg has fixed several potential vulnerabilities in xpdf,
which are also present in libextractor, a library to extract arbitrary
meta-data from files.
The old stable distribution (woody) does not contain libextractor packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.4.2-2sarge3.
For the unstable distribution (sarge) these problems have been fixed in
version 0.5.10-1.
We recommend that you upgrade your libextractor package.


Solution : http://www.debian.org/security/2006/dsa-998
Risk factor : High';

if (description) {
 script_id(22864);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "998");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA998] DSA-998-1 libextractor");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-998-1 libextractor");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'extract', release: '3.1', reference: '0.4.2-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package extract is vulnerable in Debian 3.1.\nUpgrade to extract_0.4.2-2sarge3\n');
}
if (deb_check(prefix: 'libextractor1', release: '3.1', reference: '0.4.2-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor1 is vulnerable in Debian 3.1.\nUpgrade to libextractor1_0.4.2-2sarge3\n');
}
if (deb_check(prefix: 'libextractor1-dev', release: '3.1', reference: '0.4.2-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor1-dev is vulnerable in Debian 3.1.\nUpgrade to libextractor1-dev_0.4.2-2sarge3\n');
}
if (deb_check(prefix: 'libextractor', release: '3.1', reference: '0.5.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor is vulnerable in Debian sarge.\nUpgrade to libextractor_0.5.10-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
