# This script was automatically generated from the dsa-1148
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in gallery, a web-based
photo album. The Common Vulnerabilities and Exposures project identifies
the following problems:
    A cross-site scripting vulnerability allows injection of web script
    code through HTML or EXIF information.
    A cross-site scripting vulnerability in the user registration allows
    injection of web script code.
    Missing input sanitising in the stats modules allows information
    disclosure.
For the stable distribution (sarge) these problems have been fixed in
version 1.5-1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 1.5-2.
We recommend that you upgrade your gallery package.


Solution : http://www.debian.org/security/2006/dsa-1148
Risk factor : High';

if (description) {
 script_id(22690);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1148");
 script_cve_id("CVE-2005-2734", "CVE-2006-0330", "CVE-2006-4030");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1148] DSA-1148-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1148-1 gallery");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gallery', release: '', reference: '1.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian .\nUpgrade to gallery_1.5-2\n');
}
if (deb_check(prefix: 'gallery', release: '3.1', reference: '1.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.1.\nUpgrade to gallery_1.5-1sarge2\n');
}
if (deb_check(prefix: 'gallery', release: '3.1', reference: '1.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian sarge.\nUpgrade to gallery_1.5-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
