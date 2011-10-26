# This script was automatically generated from the dsa-804
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
KDE developers have reported a vulnerability in the backup file
handling of Kate and Kwrite.  The backup files are created with
default permissions, even if the original file had more strict
permissions set.  This could disclose information unintendedly.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-6.2.
For the unstable distribution (sid) these problems have been fixed in
version 3.4.1-1.
We recommend that you upgrade your kdelibs packages.


Solution : http://www.debian.org/security/2005/dsa-804
Risk factor : High';

if (description) {
 script_id(19611);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "804");
 script_cve_id("CVE-2005-1920");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA804] DSA-804-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-804-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdelibs', release: '', reference: '3.4.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian .\nUpgrade to kdelibs_3.4.1-1\n');
}
if (deb_check(prefix: 'kdelibs', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian 3.1.\nUpgrade to kdelibs_3.3.2-6.2\n');
}
if (deb_check(prefix: 'kdelibs-bin', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs-bin is vulnerable in Debian 3.1.\nUpgrade to kdelibs-bin_3.3.2-6.2\n');
}
if (deb_check(prefix: 'kdelibs-data', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs-data is vulnerable in Debian 3.1.\nUpgrade to kdelibs-data_3.3.2-6.2\n');
}
if (deb_check(prefix: 'kdelibs4', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs4 is vulnerable in Debian 3.1.\nUpgrade to kdelibs4_3.3.2-6.2\n');
}
if (deb_check(prefix: 'kdelibs4-dev', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs4-dev is vulnerable in Debian 3.1.\nUpgrade to kdelibs4-dev_3.3.2-6.2\n');
}
if (deb_check(prefix: 'kdelibs4-doc', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs4-doc is vulnerable in Debian 3.1.\nUpgrade to kdelibs4-doc_3.3.2-6.2\n');
}
if (deb_check(prefix: 'kdelibs', release: '3.1', reference: '3.3.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian sarge.\nUpgrade to kdelibs_3.3.2-6.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
