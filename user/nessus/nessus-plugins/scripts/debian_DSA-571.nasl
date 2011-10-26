# This script was automatically generated from the dsa-571
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several integer overflows have been discovered by its upstream
developers in libpng, a commonly used library to display PNG graphics.
They could be exploited to cause arbitrary code to be executed when a
specially crafted PNG image is processed.
For the stable distribution (woody) these problems have been fixed in
version 1.2.1-1.1.woody.9.
For the unstable distribution (sid) these problems have been fixed in
version 1.2.5.0-9.
We recommend that you upgrade your libpng3 packages.


Solution : http://www.debian.org/security/2004/dsa-571
Risk factor : High';

if (description) {
 script_id(15669);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "571");
 script_cve_id("CVE-2004-0599");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA571] DSA-571-1 libpng3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-571-1 libpng3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng-dev is vulnerable in Debian 3.0.\nUpgrade to libpng-dev_1.2.1-1.1.woody.9\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian 3.0.\nUpgrade to libpng3_1.2.1-1.1.woody.9\n');
}
if (deb_check(prefix: 'libpng3', release: '3.1', reference: '1.2.5.0-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian 3.1.\nUpgrade to libpng3_1.2.5.0-9\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian woody.\nUpgrade to libpng3_1.2.1-1.1.woody.9\n');
}
if (w) { security_hole(port: 0, data: desc); }
