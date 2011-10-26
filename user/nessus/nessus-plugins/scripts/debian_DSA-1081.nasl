# This script was automatically generated from the dsa-1081
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered a buffer overflow in the processing of ASF
files in libextractor, a library to extract arbitrary meta-data from
files, which can lead to the execution of arbitrary code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.4.2-2sarge5.
For the unstable distribution (sid) this problem has been fixed in
version 0.5.14-1.
We recommend that you upgrade your libextractor packages.


Solution : http://www.debian.org/security/2006/dsa-1081
Risk factor : High';

if (description) {
 script_id(22623);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1081");
 script_cve_id("CVE-2006-2458");
 script_bugtraq_id(18021);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1081] DSA-1081-1 libextractor");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1081-1 libextractor");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libextractor', release: '', reference: '0.5.14-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor is vulnerable in Debian .\nUpgrade to libextractor_0.5.14-1\n');
}
if (deb_check(prefix: 'extract', release: '3.1', reference: '0.4.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package extract is vulnerable in Debian 3.1.\nUpgrade to extract_0.4.2-2sarge5\n');
}
if (deb_check(prefix: 'libextractor1', release: '3.1', reference: '0.4.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor1 is vulnerable in Debian 3.1.\nUpgrade to libextractor1_0.4.2-2sarge5\n');
}
if (deb_check(prefix: 'libextractor1-dev', release: '3.1', reference: '0.4.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor1-dev is vulnerable in Debian 3.1.\nUpgrade to libextractor1-dev_0.4.2-2sarge5\n');
}
if (deb_check(prefix: 'libextractor', release: '3.1', reference: '0.4.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libextractor is vulnerable in Debian sarge.\nUpgrade to libextractor_0.4.2-2sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
