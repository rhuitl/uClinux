# This script was automatically generated from the dsa-626
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Dmitry V. Levin discovered a buffer overflow in libtiff, the Tag Image
File Format library for processing TIFF graphics files.  Upon reading
a TIFF file it is possible to crash the application, and maybe also to
execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 3.5.5-6.woody5.
For the unstable distribution (sid) this problem has been fixed in
version 3.6.1-5.
We recommend that you upgrade your libtiff package.


Solution : http://www.debian.org/security/2005/dsa-626
Risk factor : High';

if (description) {
 script_id(16104);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "626");
 script_cve_id("CVE-2004-1183");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA626] DSA-626-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-626-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-6.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.0.\nUpgrade to libtiff-tools_3.5.5-6.woody5\n');
}
if (deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-6.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g is vulnerable in Debian 3.0.\nUpgrade to libtiff3g_3.5.5-6.woody5\n');
}
if (deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-6.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g-dev is vulnerable in Debian 3.0.\nUpgrade to libtiff3g-dev_3.5.5-6.woody5\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.6.1-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian 3.1.\nUpgrade to tiff_3.6.1-5\n');
}
if (deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-6.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian woody.\nUpgrade to tiff_3.5.5-6.woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
