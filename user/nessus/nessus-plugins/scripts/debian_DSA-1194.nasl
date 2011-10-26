# This script was automatically generated from the dsa-1194
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that an integer overflow in libwmf, the library to read
Windows Metafile Format files, can be exploited to execute arbitrary code
if a crafted WMF file is parsed.
For the stable distribution (sarge) this problem has been fixed in
version 0.2.8.3-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.2.8.4-2.
We recommend that you upgrade your libwmf package.


Solution : http://www.debian.org/security/2006/dsa-1194
Risk factor : High';

if (description) {
 script_id(22735);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1194");
 script_cve_id("CVE-2006-3376");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1194] DSA-1194-1 libwmf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1194-1 libwmf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libwmf', release: '', reference: '0.2.8.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmf is vulnerable in Debian .\nUpgrade to libwmf_0.2.8.4-2\n');
}
if (deb_check(prefix: 'libwmf-bin', release: '3.1', reference: '0.2.8.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmf-bin is vulnerable in Debian 3.1.\nUpgrade to libwmf-bin_0.2.8.3-2sarge1\n');
}
if (deb_check(prefix: 'libwmf-dev', release: '3.1', reference: '0.2.8.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmf-dev is vulnerable in Debian 3.1.\nUpgrade to libwmf-dev_0.2.8.3-2sarge1\n');
}
if (deb_check(prefix: 'libwmf-doc', release: '3.1', reference: '0.2.8.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmf-doc is vulnerable in Debian 3.1.\nUpgrade to libwmf-doc_0.2.8.3-2sarge1\n');
}
if (deb_check(prefix: 'libwmf0.2-7', release: '3.1', reference: '0.2.8.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmf0.2-7 is vulnerable in Debian 3.1.\nUpgrade to libwmf0.2-7_0.2.8.3-2sarge1\n');
}
if (deb_check(prefix: 'libwmf', release: '3.1', reference: '0.2.8.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmf is vulnerable in Debian sarge.\nUpgrade to libwmf_0.2.8.3-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
