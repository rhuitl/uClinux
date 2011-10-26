# This script was automatically generated from the dsa-948
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Maksim Orlovich discovered that the kjs Javascript interpreter, used
in the Konqueror web browser and in other parts of KDE, performs
insufficient bounds checking when parsing UTF-8 encoded Uniform Resource
Identifiers, which may lead to a heap based buffer overflow and the
execution of arbitrary code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-6.4
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your kdelibs package.


Solution : http://www.debian.org/security/2006/dsa-948
Risk factor : High';

if (description) {
 script_id(22814);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "948");
 script_cve_id("CVE-2006-0019");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA948] DSA-948-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-948-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdelibs', release: '3.1', reference: '3.3.2-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian 3.1.\nUpgrade to kdelibs_3.3.2-6.4\n');
}
if (deb_check(prefix: 'kdelibs-bin', release: '3.1', reference: '3.3.2-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs-bin is vulnerable in Debian 3.1.\nUpgrade to kdelibs-bin_3.3.2-6.4\n');
}
if (deb_check(prefix: 'kdelibs-data', release: '3.1', reference: '3.3.2-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs-data is vulnerable in Debian 3.1.\nUpgrade to kdelibs-data_3.3.2-6.4\n');
}
if (deb_check(prefix: 'kdelibs4', release: '3.1', reference: '3.3.2-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs4 is vulnerable in Debian 3.1.\nUpgrade to kdelibs4_3.3.2-6.4\n');
}
if (deb_check(prefix: 'kdelibs4-dev', release: '3.1', reference: '3.3.2-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs4-dev is vulnerable in Debian 3.1.\nUpgrade to kdelibs4-dev_3.3.2-6.4\n');
}
if (deb_check(prefix: 'kdelibs4-doc', release: '3.1', reference: '3.3.2-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs4-doc is vulnerable in Debian 3.1.\nUpgrade to kdelibs4-doc_3.3.2-6.4\n');
}
if (deb_check(prefix: 'kdelibs', release: '3.1', reference: '3.3.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian sarge.\nUpgrade to kdelibs_3.3.2-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
