# This script was automatically generated from the dsa-570
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
For the stable distribution (woody) this problem has been fixed in
version 1.0.12-3.woody.9.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.15-8.
We recommend that you upgrade your libpng packages.


Solution : http://www.debian.org/security/2004/dsa-570
Risk factor : High';

if (description) {
 script_id(15668);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "570");
 script_cve_id("CVE-2004-0599");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA570] DSA-570-1 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-570-1 libpng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2 is vulnerable in Debian 3.0.\nUpgrade to libpng2_1.0.12-3.woody.9\n');
}
if (deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2-dev is vulnerable in Debian 3.0.\nUpgrade to libpng2-dev_1.0.12-3.woody.9\n');
}
if (deb_check(prefix: 'libpng', release: '3.1', reference: '1.0.15-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng is vulnerable in Debian 3.1.\nUpgrade to libpng_1.0.15-8\n');
}
if (deb_check(prefix: 'libpng', release: '3.0', reference: '1.0.12-3.woody.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng is vulnerable in Debian woody.\nUpgrade to libpng_1.0.12-3.woody.9\n');
}
if (w) { security_hole(port: 0, data: desc); }
